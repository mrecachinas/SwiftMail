import Foundation
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import OrderedCollections

/**
 An actor that represents a connection to an IMAP server.

 Use this class to establish and manage connections to IMAP servers, perform authentication,
 and execute IMAP commands. The class handles connection lifecycle, command execution,
 and maintains server state.

 Example:
 ```swift
 let server = IMAPServer(host: "imap.example.com", port: 993)
 try await server.connect()
 try await server.login(username: "user@example.com", password: "password")
 ```

 - Note: All operations are logged using the Swift Logging package. To view logs in Console.app:
 1. Open Console.app
 2. Search for "process:com.cocoanetics.SwiftMail"
 3. Adjust the "Action" menu to show Debug and Info messages
 */
/// Maximum number of identifiers per IMAP FETCH command when chunking large sets.
let defaultFetchChunkSize = 50

/// Thread-safe lifecycle state shared by the server actor and synchronous
/// cancellation entry points. The latter must fence replay and close every
/// transport before an actor hop or an await.
final class IMAPServerLifecycleState: @unchecked Sendable {
    let replayEpoch = IMAPReplayEpoch()
    private let lock = NSLock()
    private var connections: [ObjectIdentifier: IMAPConnection] = [:]
    private var cancellationHandlers: [ObjectIdentifier: @Sendable () -> Void] = [:]
    private var invalidationHandlers: [ObjectIdentifier: @Sendable () -> Void] = [:]
    private var registrationEpoch: UInt64 = 0
    private var signingOut = false
    private var closingGenerations: Set<UInt64> = []
    private var signOutGeneration: UInt64?

    func captureRegistrationEpoch() -> UInt64 {
        lock.withLock { registrationEpoch }
    }

    @discardableResult
    func register(_ connection: IMAPConnection, registrationEpoch expectedEpoch: UInt64? = nil) -> Bool {
        let accepted = lock.withLock {
            guard !signingOut, closingGenerations.isEmpty,
                  expectedEpoch.map({ $0 == registrationEpoch }) ?? true else {
                return false
            }
            connections[ObjectIdentifier(connection)] = connection
            return true
        }
        if !accepted {
            connection.forceCloseTransport()
        }
        return accepted
    }

    @discardableResult
    func registerCancellationHandler(
        for connection: IMAPConnection,
        registrationEpoch expectedEpoch: UInt64? = nil,
        _ handler: @escaping @Sendable () -> Void
    ) -> Bool {
        let accepted = lock.withLock {
            let id = ObjectIdentifier(connection)
            guard connections[id] != nil, !signingOut, closingGenerations.isEmpty,
                  expectedEpoch.map({ $0 == registrationEpoch }) ?? true else {
                return false
            }
            cancellationHandlers[id] = handler
            return true
        }
        if !accepted {
            handler()
        }
        return accepted
    }

    func unregister(_ connection: IMAPConnection) {
        lock.withLock {
            let id = ObjectIdentifier(connection)
            connections.removeValue(forKey: id)
            cancellationHandlers.removeValue(forKey: id)
            invalidationHandlers.removeValue(forKey: id)
        }
    }

    func discardInvalidationHandler(for connection: IMAPConnection) {
        _ = lock.withLock {
            invalidationHandlers.removeValue(forKey: ObjectIdentifier(connection))
        }
    }

    @discardableResult
    func registerInvalidationHandler(
        for connection: IMAPConnection,
        _ handler: @escaping @Sendable () -> Void
    ) -> Bool {
        let accepted = lock.withLock {
            let id = ObjectIdentifier(connection)
            guard connections[id] != nil, !signingOut, closingGenerations.isEmpty else {
                return false
            }
            invalidationHandlers[id] = handler
            return true
        }
        if !accepted {
            handler()
        }
        return accepted
    }

    func isCurrentRegistration(_ connection: IMAPConnection, epoch: UInt64) -> Bool {
        lock.withLock {
            !signingOut && closingGenerations.isEmpty && registrationEpoch == epoch
                && connections[ObjectIdentifier(connection)] != nil
        }
    }

    func prepareRegistration(
        for connection: IMAPConnection,
        _ invalidationHandler: @escaping @Sendable () -> Void
    ) throws {
        let epoch = captureRegistrationEpoch()
        guard register(connection, registrationEpoch: epoch),
              isCurrentRegistration(connection, epoch: epoch),
              registerInvalidationHandler(for: connection, invalidationHandler) else {
            unregister(connection)
            throw CancellationError()
        }
    }

    func beginClosing() -> UInt64 {
        lock.withLock {
            registrationEpoch &+= 1
            closingGenerations.insert(registrationEpoch)
            return registrationEpoch
        }
    }

    func finishClosing(_ generation: UInt64) {
        _ = lock.withLock {
            closingGenerations.remove(generation)
        }
    }

    func forceCloseAll() {
        let generation = beginClosing()
        forceCloseRegistered()
        finishClosing(generation)
    }

    @discardableResult
    func beginSignOut() -> UInt64 {
        replayEpoch.invalidate()
        let snapshot = lock.withLock { () -> (
            UInt64, [IMAPConnection], [@Sendable () -> Void], [@Sendable () -> Void]
        ) in
            if let signOutGeneration {
                closingGenerations.remove(signOutGeneration)
            }
            signingOut = true
            registrationEpoch &+= 1
            signOutGeneration = registrationEpoch
            closingGenerations.insert(registrationEpoch)
            let snapshot = (
                registrationEpoch,
                Array(connections.values),
                Array(cancellationHandlers.values),
                Array(invalidationHandlers.values)
            )
            connections.removeAll()
            cancellationHandlers.removeAll()
            invalidationHandlers.removeAll()
            return snapshot
        }
        snapshot.3.forEach { $0() }
        snapshot.2.forEach { $0() }
        snapshot.1.forEach { $0.forceCloseTransport() }
        return snapshot.0
    }

    func currentSignOutGeneration() -> UInt64? {
        lock.withLock { signOutGeneration }
    }

    func finishSignOut(_ generation: UInt64) {
        lock.withLock {
            guard signOutGeneration == generation else { return }
            signOutGeneration = nil
            signingOut = false
            closingGenerations.remove(generation)
        }
    }

    func invalidateAuthenticationGenerations() {
        let snapshot = lock.withLock { Array(connections.values) }
        snapshot.forEach { $0.invalidateAuthenticationGeneration() }
    }

    private func forceCloseRegistered() {
        let snapshot = lock.withLock {
            let snapshot = (
                Array(connections.values),
                Array(cancellationHandlers.values),
                Array(invalidationHandlers.values)
            )
            connections.removeAll()
            cancellationHandlers.removeAll()
            invalidationHandlers.removeAll()
            return snapshot
        }
        snapshot.2.forEach { $0() }
        snapshot.1.forEach { $0() }
        snapshot.0.forEach { $0.forceCloseTransport() }
    }

    var registeredConnectionCountForTesting: Int {
        lock.withLock { connections.count }
    }

    var cancellationHandlerCountForTesting: Int {
        lock.withLock { cancellationHandlers.count }
    }

    var invalidationHandlerCountForTesting: Int {
        lock.withLock { invalidationHandlers.count }
    }
}

final class IMAPReplayEpoch: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 0

    func capture() -> UInt64 {
        lock.withLock { value }
    }

    func invalidate() {
        lock.withLock { value &+= 1 }
    }

    func check(_ expected: UInt64) throws {
        guard lock.withLock({ value == expected }) else {
            throw CancellationError()
        }
    }
}

public actor IMAPServer {
    // MARK: - Properties

    /** The hostname of the IMAP server */
    let host: String

    /** The port number of the IMAP server */
    let port: Int

    /// Explicit TLS preference. `.automatic` infers from the standard IMAP ports.
    let transportSecurity: MailTransportSecurity

    /// Certificate verification preference used by all TLS transports for this server.
    let certificateVerificationPolicy: MailCertificateVerificationPolicy

    /// Lowest TLS version any transport for this server may negotiate.
    let minimumTLSVersion: MailTLSMinimumVersion

    /// Maximum number of bytes the IMAP response parser may buffer before failing.
    /// Large SEARCH/FETCH responses from dense mailboxes can exceed a small buffer
    /// and surface as `PayloadTooLargeError`; raise this for very large mailboxes.
    let responseBufferLimit: Int

    /// Bounds the response parser enforces against a hostile or malfunctioning server.
    let parserLimits: IMAPParserLimits

    /** The event loop group for handling asynchronous operations */
    let group: EventLoopGroup
    let lifecycleState: IMAPServerLifecycleState

    /// Primary connection used for non-IDLE commands.
    let primaryConnection: IMAPConnection

    /// Spawned IDLE connections keyed by session ID.
    var idleConnections: [UUID: IdleConnection] = [:]

    /// User-managed named connections keyed by requested name.
    var namedConnections: [String: NamedConnection] = [:]

    /// Named connections currently being created, including their transports.
    var pendingNamedConnections: [String: PendingNamedConnection] = [:]
    var nextNamedConnectionGeneration: UInt64 = 0

    /// Authentication configuration for spawning new connections.
    var authentication: Authentication?

    /// RFC 2971 client identity replayed after every successful
    /// authentication on every connection this server opens (primary,
    /// dedicated IDLE connections, and transparent re-authentication).
    /// Set it before calling `login`/`authenticatePlain`/`authenticateXOAUTH2`.
    var clientIdentification: Identification?

    /** The list of all mailboxes with their attributes */
    public private(set) var mailboxes: [Mailbox.Info] = []

    /** Special folders - mailboxes with SPECIAL-USE attributes */
    public private(set) var specialMailboxes: [Mailbox.Info] = []

    /// Namespaces discovered from the server
    public internal(set) var namespaces: NamespaceResponse?

    /// Capabilities reported by the primary connection.
    var capabilities: Set<NIOIMAPCore.Capability> {
        primaryConnection.capabilitiesSnapshot
    }

    /// Whether the primary connection advertised UIDPLUS.
    public var supportsUIDPlus: Bool {
        capabilities.containsUIDPlusCapability
    }

    /// Whether the primary connection advertised MOVE (RFC 6851).
    ///
    /// This reports the advertised capability only. The default
    /// ``move(messages:to:fallback:)`` policy retains the existing UIDPLUS-dependent fallback,
    /// while ``MoveFallbackPolicy/disabled`` requires MOVE directly.
    public var supportsMove: Bool {
        capabilities.containsMoveCapability
    }

    var certificatePolicyForTesting: MailCertificateVerificationPolicy {
        primaryConnection.certificateVerificationPolicyForTesting
    }

    /**
     Logger for IMAP operations
     To view these logs in Console.app:
     1. Open Console.app
     2. In the search field, type "process:com.cocoanetics.SwiftIMAP"
     3. You may need to adjust the "Action" menu to show "Include Debug Messages" and "Include Info Messages"
     */
    let logger: Logging.Logger

    struct IdleConnection {
        let mailbox: String
        let connection: IMAPConnection
        /// The session's private EventLoopGroup; shut down as the final step of teardown.
        let idleGroup: EventLoopGroup
        /// Set once the resilient cycle starts. Server-side teardown must cancel the
        /// cycle task before touching the connection — the runner is self-healing, so
        /// a socket that merely closes underneath it is treated as a dropped
        /// connection and re-dialed.
        var lifecycle: IMAPIdleSessionLifecycle?
        var cycleTask: Task<Void, Never>?
    }

    struct NamedConnection {
        let connection: IMAPConnection
        let handle: IMAPNamedConnection
        let token: IMAPNamedConnectionToken
    }

    struct PendingNamedConnection {
        struct Waiter {
            let id: UUID
            let continuation: CheckedContinuation<IMAPNamedConnection, any Error>
        }

        let connection: IMAPConnection
        let token: IMAPNamedConnectionToken
        let validity: IMAPNamedConnectionValidity
        var waiters: [Waiter]
    }

    enum AuthenticationMethod {
        case login(username: String, password: String)
        case plain(username: String, password: String)
        case xoauth2(email: String, accessTokenProvider: @Sendable () async throws -> String)
    }

    struct Authentication {
        let method: AuthenticationMethod
        var identification: Identification?
        let replayEpoch: UInt64
        let replayFence: IMAPReplayEpoch

        init(
            method: AuthenticationMethod,
            identification: Identification?,
            replayEpoch: UInt64? = nil,
            replayFence: IMAPReplayEpoch? = nil
        ) {
            self.method = method
            self.identification = identification
            self.replayFence = replayFence ?? IMAPReplayEpoch()
            self.replayEpoch = replayEpoch ?? self.replayFence.capture()
        }

        func authenticate(
            on connection: IMAPConnection,
            authenticationGeneration: Int? = nil
        ) async throws {
            try replayFence.check(replayEpoch)
            switch method {
                case .login(let username, let password):
                    try await connection.login(
                        username: username, password: password,
                        authenticationGeneration: authenticationGeneration
                    )
                case .plain(let username, let password):
                    try await connection.authenticatePlain(
                        username: username, password: password,
                        authenticationGeneration: authenticationGeneration
                    )
                case .xoauth2(let email, let accessTokenProvider):
                    try replayFence.check(replayEpoch)
                    let accessToken = try await accessTokenProvider()
                    try replayFence.check(replayEpoch)
                    try await connection.authenticateXOAUTH2(
                        email: email, accessToken: accessToken,
                        authenticationGeneration: authenticationGeneration
                    )
            }
            try replayFence.check(replayEpoch)
            // RFC 2971: some servers (e.g. NetEase 163/126) reject SELECT on any
            // authenticated connection that has not identified itself, so the
            // stored identity is replayed after every authentication.
            guard let identification else { return }
            try await Self.identify(
                connection, with: identification,
                authenticationGeneration: authenticationGeneration
            )
        }

        /// Replays the stored RFC 2971 identity on a freshly authenticated
        /// connection. Servers that do not advertise the ID capability are
        /// never sent the command — the snapshot is authoritative here because
        /// every authentication path refreshes it before returning. A server
        /// refusing ID (NO/BAD) is tolerated: the session stays authenticated
        /// and usable. But an ID failure that recycles the connection (socket
        /// closed, timeout) must propagate — swallowing it would report
        /// authentication success for a connection that is no longer
        /// connected or authenticated.
        static func identify(
            _ connection: IMAPConnection,
            with identification: Identification,
            authenticationGeneration: Int? = nil
        ) async throws {
            guard connection.capabilitiesSnapshot.contains(.id) else { return }

            do {
                _ = try await connection.id(
                    identification, authenticationGeneration: authenticationGeneration
                )
            } catch let error as CancellationError {
                throw error
            } catch {
                guard connection.isConnected, connection.isAuthenticated else {
                    throw error
                }
            }
        }
    }

    // MARK: - Initialization

    /// The default IMAP response parser buffer limit (1 MB).
    ///
    /// Large SEARCH responses can contain thousands of message IDs; 1 MB keeps
    /// typical mailboxes working without an unbounded buffer. Callers indexing
    /// very large or dense mailboxes can pass a larger value to the initializer.
    public static let defaultResponseBufferLimit = 1024 * 1024

    /**
     Initialize a new IMAP server connection

     - Parameters:
     - host: The hostname of the IMAP server
     - port: The port number of the IMAP server (typically 993 for SSL)
     - transportSecurity: The transport security policy to use. `.automatic` infers from standard IMAP
     ports; explicit values override that inference.
     - certificateVerificationPolicy: The certificate verification policy to use for TLS connections.
     - minimumTLSVersion: The lowest TLS version any transport may negotiate. Defaults to
     ``MailTLSMinimumVersion/tlsv12``, the lowest version RFC 8996 still permits. Pass
     ``MailTLSMinimumVersion/tlsv13`` when every server you talk to supports it, which makes
     a downgrade impossible regardless of what the server offers.
     - numberOfThreads: The number of threads to use for the event loop group
     - parserLimits: Bounds the response parser enforces against a hostile or malfunctioning
     server. Defaults to ``IMAPParserLimits/default``, which leaves body size and attribute
     count unbounded — the behaviour before this parameter existed.
     - responseBufferLimit: Maximum bytes the IMAP response parser may buffer
     before failing with `PayloadTooLargeError`. Defaults to
     ``IMAPServer/defaultResponseBufferLimit`` (1 MB), which handles large SEARCH
     responses containing thousands of message IDs. Raise it for very dense
     mailboxes whose SEARCH/FETCH responses exceed 1 MB. Must be greater than 0.

     - Precondition: `responseBufferLimit > 0` — a non-positive limit would make
     every response exceed the buffer and fail with `PayloadTooLargeError`.
     */
    public init(
        host: String,
        port: Int,
        transportSecurity: MailTransportSecurity = .automatic,
        certificateVerificationPolicy: MailCertificateVerificationPolicy = .fullVerification,
        minimumTLSVersion: MailTLSMinimumVersion = .tlsv12,
        numberOfThreads: Int = 1,
        responseBufferLimit: Int = IMAPServer.defaultResponseBufferLimit,
        parserLimits: IMAPParserLimits = .default
    ) {
        precondition(responseBufferLimit > 0, "responseBufferLimit must be greater than 0 bytes")
        self.host = host
        self.port = port
        self.transportSecurity = transportSecurity
        self.certificateVerificationPolicy = certificateVerificationPolicy
        self.minimumTLSVersion = minimumTLSVersion
        self.responseBufferLimit = responseBufferLimit
        self.parserLimits = parserLimits
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: numberOfThreads)
        let lifecycleState = IMAPServerLifecycleState()
        self.lifecycleState = lifecycleState

        // Initialize loggers
        self.logger = Logging.Logger(label: "com.cocoanetics.SwiftMail.IMAPServer")

        let primaryLoggerLabel = "com.cocoanetics.SwiftMail.IMAPServer"
        let outboundLabel = "com.cocoanetics.SwiftMail.IMAP_OUT"
        let inboundLabel = "com.cocoanetics.SwiftMail.IMAP_IN"
        let primaryConnection = IMAPConnection(
            host: host,
            port: port,
            transportSecurity: transportSecurity,
            certificateVerificationPolicy: certificateVerificationPolicy,
            minimumTLSVersion: minimumTLSVersion,
            group: group,
            loggerLabel: primaryLoggerLabel,
            outboundLabel: outboundLabel,
            inboundLabel: inboundLabel,
            connectionID: "primary",
            connectionRole: "primary",
            responseBufferLimit: responseBufferLimit,
            parserLimits: parserLimits
        )
        self.primaryConnection = primaryConnection
        primaryConnection.setLifecyclePreparation { [lifecycleState, primaryConnection] in
            try lifecycleState.prepareRegistration(for: primaryConnection) {
                primaryConnection.forceCloseTransport()
            }
        }
        lifecycleState.register(primaryConnection)
    }

    public init(
        host: String,
        port: Int,
        useTLS: Bool?,
        numberOfThreads: Int = 1,
        responseBufferLimit: Int = IMAPServer.defaultResponseBufferLimit
    ) {
        self.init(
            host: host,
            port: port,
            transportSecurity: Self.resolveLegacyTransportSecurity(port: port, useTLS: useTLS),
            certificateVerificationPolicy: .fullVerification,
            numberOfThreads: numberOfThreads,
            responseBufferLimit: responseBufferLimit
        )
    }

    private static func resolveLegacyTransportSecurity(port: Int, useTLS: Bool?) -> MailTransportSecurity {
        guard let useTLS else {
            return .automatic
        }

        if useTLS {
            return port == 143 ? .startTLS : .implicitTLS
        }

        return .plainText
    }

    /// Test-only access to the response buffer limit configured on the primary connection.
    var primaryResponseBufferLimitForTesting: Int {
        primaryConnection.responseBufferLimit
    }

    deinit {
        // Same non-blocking pattern as SMTPServer.deinit. The callback form needs
        // neither a Task nor an actor hop: the previous @MainActor task variant
        // quietly serialized every shutdown through the main actor and never ran at
        // all in processes that do not drain the main queue.
        group.shutdownGracefully { _ in }
    }

    // MARK: - Mailbox State (used by helpers in extensions)

    /// Replace the cached mailbox listing. Used by mailbox-listing extensions.
    func updateMailboxes(_ value: [Mailbox.Info]) {
        self.mailboxes = value
    }

    /// Replace the cached special-use mailbox listing. Used by special-use extensions.
    func updateSpecialMailboxes(_ value: [Mailbox.Info]) {
        self.specialMailboxes = value
    }

    /// Reset cached mailbox state when closing all connections.
    func clearMailboxState() {
        self.namespaces = nil
        self.mailboxes = []
        self.specialMailboxes = []
    }
}
