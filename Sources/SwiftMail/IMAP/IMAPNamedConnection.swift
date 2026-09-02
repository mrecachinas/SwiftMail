import Foundation
@preconcurrency import NIOIMAPCore

/// A user-controlled, reusable IMAP connection managed by ``IMAPServer``.
///
/// Instances are obtained via ``IMAPServer/connection(named:)``.
/// The server handles lifecycle bootstrap/authentication and teardown; callers decide
/// which mailbox and commands run on each named connection.
public actor IMAPNamedConnection {
    public let name: String
    public nonisolated let token: IMAPNamedConnectionToken

    // Widened from `private` to internal so the extensions split across files
    // (Mailbox/Idle/Fetch/Search/Manipulation) can reach them; not part of the
    // public API.
    let connection: IMAPConnection
    let authenticateOnConnection: @Sendable (IMAPConnection) async throws -> Void
    let authenticateOnConnectionWithGeneration: (@Sendable (IMAPConnection, Int) async throws -> Void)?
    let validity: IMAPNamedConnectionValidity
    let lifecycleState: IMAPServerLifecycleState?

    /// The timestamp of the last successfully completed command on this connection.
    /// Useful for implementing staleness checks in ephemeral connection patterns.
    public private(set) var lastActivity: Date?
    private var authenticationWaiters: [CheckedContinuation<Void, any Error>] = []
    private var isAuthenticationInFlight = false

    var authenticationWaiterCountForTesting: Int {
        authenticationWaiters.count
    }

    init(
        name: String,
        connection: IMAPConnection,
        token: IMAPNamedConnectionToken,
        validity: IMAPNamedConnectionValidity,
        authenticateOnConnection: @escaping @Sendable (IMAPConnection) async throws -> Void,
        authenticateOnConnectionWithGeneration: (@Sendable (IMAPConnection, Int) async throws -> Void)? = nil,
        lifecycleState: IMAPServerLifecycleState? = nil
    ) {
        self.name = name
        self.connection = connection
        self.token = token
        self.validity = validity
        self.authenticateOnConnection = authenticateOnConnection
        self.authenticateOnConnectionWithGeneration = authenticateOnConnectionWithGeneration
        self.lifecycleState = lifecycleState
    }

    init(
        name: String,
        connection: IMAPConnection,
        authenticateOnConnection: @escaping @Sendable (IMAPConnection) async throws -> Void
    ) {
        self.init(
            name: name,
            connection: connection,
            token: IMAPNamedConnectionToken(name: name, generation: 0),
            validity: IMAPNamedConnectionValidity(),
            authenticateOnConnection: authenticateOnConnection
        )
    }

    /// Whether the underlying transport channel is currently active.
    public var isConnected: Bool {
        connection.isConnected
    }

    /// Whether this connection currently has an authenticated IMAP session.
    public var isAuthenticated: Bool {
        connection.isAuthenticated
    }

    /// Connect (or reconnect) the underlying transport and ensure authentication.
    public func connect() async throws {
        let startup = try prepareLifecycleRegistration()
        do {
            try await connection.connect(
                expectedGeneration: startup.transportGeneration,
                authenticationGeneration: startup.authenticationGeneration
            )
            try validity.check(token)
            try await ensureAuthenticated(authenticationGeneration: startup.authenticationGeneration)
            try validity.check(token)
        } catch {
            // Close only the transport generation this startup was bound to.
            connection.forceCloseTransport(ifCurrentGeneration: startup.transportGeneration)
            throw error
        }
    }

    /// Disconnect this named connection.
    public func disconnect() async throws {
        try await connection.disconnect()
    }

    /// Whether the server advertised UIDPLUS for this connection.
    public var supportsUIDPlus: Bool {
        capabilities.containsUIDPlusCapability
    }

    /// Whether the server advertised MOVE (RFC 6851) for this connection.
    ///
    /// This reports the advertised capability only. The default
    /// ``move(messages:to:fallback:)`` policy retains the existing UIDPLUS-dependent fallback,
    /// while ``MoveFallbackPolicy/disabled`` requires MOVE directly.
    public var supportsMove: Bool {
        capabilities.containsMoveCapability
    }

    // MARK: - Internal Helpers

    /// Capabilities snapshot reused by the split extensions when deciding
    /// whether optional commands are supported.
    var capabilities: Set<NIOIMAPCore.Capability> {
        connection.capabilitiesSnapshot
    }

    /// Mark a successful command — invoked by helpers that talk directly to
    /// `connection` (idle, noop, fetchCapabilities, …).
    func recordActivity() {
        lastActivity = Date()
    }

    func ensureAuthenticated(authenticationGeneration: Int? = nil) async throws {
        try prepareLifecycleRegistration()
        guard !connection.isAuthenticated else { return }
        let startup = try validity.bind(to: connection, token: token)

        if isAuthenticationInFlight {
            do {
                try await withCheckedThrowingContinuation { continuation in
                    authenticationWaiters.append(continuation)
                }
                try validity.check(token)
            } catch {
                connection.forceCloseTransport(ifCurrentGeneration: startup.transportGeneration)
                throw error
            }
            return
        }

        // Concurrent callers share this leader's result. Failure clears the
        // in-flight state so a later call can retry normally.
        isAuthenticationInFlight = true
        do {
            if let authenticateOnConnectionWithGeneration {
                try await authenticateOnConnectionWithGeneration(
                    connection, authenticationGeneration ?? startup.authenticationGeneration
                )
            } else {
                try await authenticateOnConnection(connection)
            }
            try validity.check(token)
            completeAuthenticationWaiters(with: .success(()))
        } catch {
            connection.forceCloseTransport(ifCurrentGeneration: startup.transportGeneration)
            completeAuthenticationWaiters(with: .failure(error))
            throw error
        }
    }

    private func completeAuthenticationWaiters(with result: Result<Void, any Error>) {
        isAuthenticationInFlight = false
        let waiters = authenticationWaiters
        authenticationWaiters.removeAll()

        for waiter in waiters {
            switch result {
                case .success:
                    waiter.resume()
                case .failure(let error):
                    waiter.resume(throwing: error)
            }
        }
    }

    /// Bind the lease before publishing its transport in the server registry,
    /// then install invalidation before any connect/auth await. A failed epoch
    /// or handler installation rolls back the registration so stale handles
    /// cannot repopulate the registry.
    @discardableResult
    private func prepareLifecycleRegistration() throws -> IMAPNamedConnectionStartup {
        let startup = try validity.bind(to: connection, token: token)
        guard let lifecycleState else { return startup }

        let registrationEpoch = lifecycleState.captureRegistrationEpoch()
        guard lifecycleState.register(connection, registrationEpoch: registrationEpoch),
              lifecycleState.isCurrentRegistration(connection, epoch: registrationEpoch) else {
            lifecycleState.unregister(connection)
            validity.invalidate()
            throw CancellationError()
        }
        let leaseValidity = validity
        let handlerInstalled = lifecycleState.registerInvalidationHandler(for: connection) {
            leaseValidity.invalidate()
        }
        guard handlerInstalled else {
            lifecycleState.unregister(connection)
            validity.invalidate()
            throw CancellationError()
        }

        let leaseConnection = connection
        let leaseToken = token
        connection.setLifecyclePreparation { [weak lifecycleState, weak leaseValidity, leaseConnection, leaseToken] in
            guard let lifecycleState, let leaseValidity else {
                throw CancellationError()
            }
            _ = try leaseValidity.bind(to: leaseConnection, token: leaseToken)
            let epoch = lifecycleState.captureRegistrationEpoch()
            guard lifecycleState.register(leaseConnection, registrationEpoch: epoch),
                  lifecycleState.isCurrentRegistration(leaseConnection, epoch: epoch) else {
                lifecycleState.unregister(leaseConnection)
                leaseValidity.invalidate()
                throw CancellationError()
            }
            guard lifecycleState.registerInvalidationHandler(for: leaseConnection, {
                leaseValidity.invalidate()
            }) else {
                lifecycleState.unregister(leaseConnection)
                leaseValidity.invalidate()
                throw CancellationError()
            }
        }
        return startup
    }

    @discardableResult
    func executeCommand<CommandType: IMAPCommand>(
        _ command: CommandType
    ) async throws -> CommandType.ResultType {
        try validity.check(token)
        let transportGeneration = connection.captureTransportGeneration()
        do {
            try await ensureAuthenticated()
            try validity.check(token)
            let result = try await connection.executeCommand(command)
            try validity.check(token)
            lastActivity = Date()
            return result
        } catch {
            if !validity.isValid {
                connection.forceCloseTransport(ifCurrentGeneration: transportGeneration)
            }
            throw error
        }
    }

    func resolveMailboxPath(_ mailboxName: String) -> String {
        guard let namespaces = connection.namespacesSnapshot else {
            return mailboxName
        }
        return namespaces.resolveMailboxPath(mailboxName)
    }
}

public struct IMAPNamedConnectionToken: Hashable, Sendable {
    public let name: String
    public let generation: UInt64

    public init(name: String, generation: UInt64) {
        self.name = name
        self.generation = generation
    }
}

final class IMAPNamedConnectionValidity: @unchecked Sendable {
    private let lock = NSLock()
    private var valid = true
    private var boundConnection: IMAPConnection?
    private var boundTransportGeneration: Int?

    func invalidate() {
        let binding = lock.withLock { () -> (IMAPConnection, Int)? in
            valid = false
            guard let boundConnection, let boundTransportGeneration else { return nil }
            return (boundConnection, boundTransportGeneration)
        }
        binding?.0.forceCloseTransport(ifCurrentGeneration: binding?.1)
    }

    var isValid: Bool {
        lock.withLock { valid }
    }

    /// Atomically binds lease validity to the transport generations used by
    /// connect/auth startup.
    func bind(to connection: IMAPConnection, token: IMAPNamedConnectionToken) throws -> IMAPNamedConnectionStartup {
        lock.lock()
        defer { lock.unlock() }
        guard valid else {
            throw IMAPError.connectionFailed(
                "Named connection \(token.name) generation \(token.generation) is invalid"
            )
        }
        boundConnection = connection
        boundTransportGeneration = connection.captureTransportGeneration()
        return IMAPNamedConnectionStartup(
            transportGeneration: boundTransportGeneration!,
            authenticationGeneration: connection.captureAuthenticationGeneration()
        )
    }

    func check(_ token: IMAPNamedConnectionToken) throws {
        let binding = lock.withLock { () -> (IMAPConnection, Int)? in
            guard !valid, let boundConnection, let boundTransportGeneration else { return nil }
            return (boundConnection, boundTransportGeneration)
        }
        if let binding {
            binding.0.forceCloseTransport(ifCurrentGeneration: binding.1)
            throw IMAPError.connectionFailed(
                "Named connection \(token.name) generation \(token.generation) is invalid"
            )
        }
        guard isValid else {
            throw IMAPError.connectionFailed(
                "Named connection \(token.name) generation \(token.generation) is invalid"
            )
        }
    }
}

struct IMAPNamedConnectionStartup: Sendable {
    let transportGeneration: Int
    let authenticationGeneration: Int
}
