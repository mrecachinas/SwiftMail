import Foundation
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import NIOSSL

final class IMAPTransportState: @unchecked Sendable {
    let lock = NSLock()
    var channel: Channel?
    var capabilities: Set<NIOIMAPCore.Capability> = []
    var namespaces: NamespaceResponse?
    var isSessionAuthenticated = false
    var idleHandler: IdleHandler?
    var idleTerminationInProgress = false
    var generation = 0
    var authenticationGeneration = 0
}

/// A lifecycle and transport generation captured as one barrier.
final class IMAPTransportLifecycleToken: @unchecked Sendable {
    let transportGeneration: Int
    let lifecycleEpoch: UInt64?
    weak var lifecycleState: IMAPServerLifecycleState?

    init(
        transportGeneration: Int,
        lifecycleEpoch: UInt64? = nil,
        lifecycleState: IMAPServerLifecycleState? = nil
    ) {
        self.transportGeneration = transportGeneration
        self.lifecycleEpoch = lifecycleEpoch
        self.lifecycleState = lifecycleState
    }

    func publishChannelIfCurrent(_ channel: Channel, connection: IMAPConnection) -> Bool {
        guard let lifecycleState else {
            guard lifecycleEpoch == nil else { return false }
            return connection.transportState.lock.withLock {
                guard connection.transportState.generation == transportGeneration else { return false }
                connection.transportState.channel = channel
                return true
            }
        }
        return lifecycleState.publishChannelIfCurrent(
            channel, connection: connection, token: self
        )
    }
}

/// Internal connection wrapper used by IMAPServer to manage per-connection state.
final class IMAPConnection {
    enum TLSTransportMode: Equatable {
        case implicitTLS
        case plainText
        case startTLSIfAvailable
        case startTLSRequired
    }

    let host: String
    let port: Int
    let transportSecurity: MailTransportSecurity
    let certificateVerificationPolicy: MailCertificateVerificationPolicy
    let minimumTLSVersion: MailTLSMinimumVersion
    let responseBufferLimit: Int
    let parserLimits: IMAPParserLimits
    let group: EventLoopGroup
    let connectionID: String
    let connectionRole: String
    let connectionContext: String
    let transportState = IMAPTransportState()
    private var lifecyclePreparation: (@Sendable () throws -> IMAPTransportLifecycleToken)?
    var channel: Channel? {
        get { transportState.lock.withLock { transportState.channel } }
        set { transportState.lock.withLock { transportState.channel = newValue } }
    }
    var commandTagCounter: Int = 0
    var capabilities: Set<NIOIMAPCore.Capability> {
        get { transportState.lock.withLock { transportState.capabilities } }
        set { transportState.lock.withLock { transportState.capabilities = newValue } }
    }
    var namespaces: NamespaceResponse? {
        get { transportState.lock.withLock { transportState.namespaces } }
        set { transportState.lock.withLock { transportState.namespaces = newValue } }
    }
    var isSessionAuthenticated: Bool {
        get { transportState.lock.withLock { transportState.isSessionAuthenticated } }
        set { transportState.lock.withLock { transportState.isSessionAuthenticated = newValue } }
    }
    var idleHandler: IdleHandler? {
        get { transportState.lock.withLock { transportState.idleHandler } }
        set { transportState.lock.withLock { transportState.idleHandler = newValue } }
    }
    var idleTerminationInProgress: Bool {
        get { transportState.lock.withLock { transportState.idleTerminationInProgress } }
        set { transportState.lock.withLock { transportState.idleTerminationInProgress = newValue } }
    }
    let commandQueue = IMAPCommandQueue()
    let responseBuffer = UntaggedResponseBuffer()
    var startTLSUpgradeOverrideForTesting: (() async throws -> Void)?
    var openChannelOverrideForTesting: (() async throws -> Channel)?
    var transportGeneration: Int {
        get { transportState.lock.withLock { transportState.generation } }
        set { transportState.lock.withLock { transportState.generation = newValue } }
    }

    let logger: Logging.Logger
    let duplexLogger: IMAPLogger

    func captureTransportGeneration() -> Int {
        transportState.lock.withLock { transportState.generation }
    }

    func isCurrentTransportGeneration(_ generation: Int) -> Bool {
        transportState.lock.withLock { transportState.generation == generation }
    }

    func captureAuthenticationGeneration() -> Int {
        transportState.lock.withLock { transportState.authenticationGeneration }
    }

    func checkAuthenticationGeneration(_ generation: Int) throws {
        guard transportState.lock.withLock({ transportState.authenticationGeneration == generation }) else {
            throw CancellationError()
        }
    }

    /// Publish authentication only when the operation still owns the
    /// authentication generation it captured before starting.
    @discardableResult
    func publishAuthenticationIfCurrent(_ generation: Int) -> Bool {
        transportState.lock.withLock {
            guard transportState.authenticationGeneration == generation else { return false }
            transportState.isSessionAuthenticated = true
            return true
        }
    }

    func publishCapabilities(
        _ capabilities: Set<NIOIMAPCore.Capability>,
        authenticationGeneration: Int? = nil
    ) throws {
        try transportState.lock.withLock {
            if let authenticationGeneration,
               transportState.authenticationGeneration != authenticationGeneration {
                throw CancellationError()
            }
            transportState.capabilities = capabilities
        }
    }

    func publishNamespaces(
        _ namespaces: NamespaceResponse?,
        authenticationGeneration: Int? = nil
    ) throws {
        try transportState.lock.withLock {
            if let authenticationGeneration,
               transportState.authenticationGeneration != authenticationGeneration {
                throw CancellationError()
            }
            transportState.namespaces = namespaces
        }
    }

    func publishChannelIfCurrent(_ channel: Channel, token: IMAPTransportLifecycleToken) -> Bool {
        token.publishChannelIfCurrent(channel, connection: self)
    }

    func setLifecyclePreparation(
        _ preparation: @escaping @Sendable () throws -> IMAPTransportLifecycleToken
    ) {
        transportState.lock.withLock {
            lifecyclePreparation = preparation
        }
    }

    func prepareLifecycleForTransport() throws -> IMAPTransportLifecycleToken {
        let preparation = transportState.lock.withLock { lifecyclePreparation }
        return try preparation?()
            ?? IMAPTransportLifecycleToken(transportGeneration: captureTransportGeneration())
    }

    /// - Note: `minimumTLSVersion` and `parserLimits` deliberately have **no defaults.**
    ///   They used to, and `makeIdleConnection`/`makeNamedConnection` simply left them out — so
    ///   a server configured with a TLS 1.3 floor and 64 MiB parser limits spawned IDLE and named
    ///   connections with a TLS 1.2 floor and *unbounded* limits, while `IMAPServer`'s
    ///   documentation claimed the policy governed every transport. A default turns "forgot to
    ///   pass the security policy" into "chose the lax one", and neither the compiler nor a
    ///   reviewer can see the difference. Without defaults, omitting one is a build error.
    init(
        host: String,
        port: Int,
        transportSecurity: MailTransportSecurity = .automatic,
        certificateVerificationPolicy: MailCertificateVerificationPolicy = .fullVerification,
        minimumTLSVersion: MailTLSMinimumVersion,
        group: EventLoopGroup,
        loggerLabel: String,
        outboundLabel: String,
        inboundLabel: String,
        connectionID: String,
        connectionRole: String,
        responseBufferLimit: Int = IMAPServer.defaultResponseBufferLimit,
        parserLimits: IMAPParserLimits
    ) {
        self.host = host
        self.port = port
        self.transportSecurity = transportSecurity
        self.certificateVerificationPolicy = certificateVerificationPolicy
        self.minimumTLSVersion = minimumTLSVersion
        self.responseBufferLimit = responseBufferLimit
        self.parserLimits = parserLimits
        self.group = group
        self.connectionID = connectionID
        self.connectionRole = connectionRole
        self.connectionContext = "[imap \(host):\(port) role=\(connectionRole) conn=\(connectionID)]"

        var logger = Logging.Logger(label: loggerLabel)
        logger[metadataKey: "imap.host"] = .string(host)
        logger[metadataKey: "imap.port"] = .stringConvertible(port)
        logger[metadataKey: "imap.connection_id"] = .string(connectionID)
        logger[metadataKey: "imap.connection_role"] = .string(connectionRole)
        self.logger = logger

        var outboundLogger = Logging.Logger(label: outboundLabel)
        outboundLogger[metadataKey: "imap.host"] = .string(host)
        outboundLogger[metadataKey: "imap.port"] = .stringConvertible(port)
        outboundLogger[metadataKey: "imap.connection_id"] = .string(connectionID)
        outboundLogger[metadataKey: "imap.connection_role"] = .string(connectionRole)

        var inboundLogger = Logging.Logger(label: inboundLabel)
        inboundLogger[metadataKey: "imap.host"] = .string(host)
        inboundLogger[metadataKey: "imap.port"] = .stringConvertible(port)
        inboundLogger[metadataKey: "imap.connection_id"] = .string(connectionID)
        inboundLogger[metadataKey: "imap.connection_role"] = .string(connectionRole)
        self.duplexLogger = IMAPLogger(
            outboundLogger: outboundLogger,
            inboundLogger: inboundLogger,
            contextPrefix: connectionContext
        )
    }

    /// Legacy convenience initializer taking `useTLS` instead of a `MailTransportSecurity`.
    ///
    /// Security policy is explicit here for the same reason the designated initializer has no
    /// defaults: this call site was invisible to a grep for `IMAPConnection(` and only surfaced
    /// once the compiler demanded the arguments.
    convenience init(
        host: String,
        port: Int,
        useTLS: Bool?,
        group: EventLoopGroup,
        loggerLabel: String,
        outboundLabel: String,
        inboundLabel: String,
        connectionID: String,
        connectionRole: String,
        responseBufferLimit: Int = IMAPServer.defaultResponseBufferLimit,
        minimumTLSVersion: MailTLSMinimumVersion = .tlsv12,
        parserLimits: IMAPParserLimits = .default
    ) {
        self.init(
            host: host,
            port: port,
            transportSecurity: Self.resolveLegacyTransportSecurity(port: port, useTLS: useTLS),
            certificateVerificationPolicy: .fullVerification,
            minimumTLSVersion: minimumTLSVersion,
            group: group,
            loggerLabel: loggerLabel,
            outboundLabel: outboundLabel,
            inboundLabel: inboundLabel,
            connectionID: connectionID,
            connectionRole: connectionRole,
            responseBufferLimit: responseBufferLimit,
            parserLimits: parserLimits
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

    static func resolveTLSTransportMode(
        port: Int,
        transportSecurity: MailTransportSecurity
    ) throws -> TLSTransportMode {
        switch transportSecurity {
            case .automatic:
                switch port {
                    case 993:
                        return .implicitTLS
                    case 143:
                        return .startTLSIfAvailable
                    default:
                        throw IMAPError.invalidArgument(
                            "Port \(port) requires explicit transportSecurity because TLS mode cannot be inferred"
                        )
                }
            case .implicitTLS:
                return .implicitTLS
            case .startTLS:
                return .startTLSRequired
            case .plainText:
                return .plainText
        }
    }

    static func requiresSTARTTLSUpgrade(
        tlsTransportMode: TLSTransportMode,
        capabilities: [Capability]
    ) -> Bool {
        switch tlsTransportMode {
            case .startTLSIfAvailable, .startTLSRequired:
                return capabilities.contains(.startTLS)
            case .implicitTLS, .plainText:
                return false
        }
    }

    static func requiresMissingSTARTTLSError(
        tlsTransportMode: TLSTransportMode,
        capabilities: [Capability]
    ) -> Bool {
        tlsTransportMode == .startTLSRequired && !capabilities.contains(.startTLS)
    }

    var isConnected: Bool {
        guard let channel = self.channel else {
            return false
        }
        return channel.isActive
    }

    var capabilitiesSnapshot: Set<NIOIMAPCore.Capability> {
        capabilities
    }

    var certificateVerificationPolicyForTesting: MailCertificateVerificationPolicy {
        certificateVerificationPolicy
    }

    var responseBufferLimitForTesting: Int {
        responseBufferLimit
    }

    var namespacesSnapshot: NamespaceResponse? {
        namespaces
    }

    var isAuthenticated: Bool {
        isSessionAuthenticated
    }

    var identifier: String {
        connectionID
    }

    var role: String {
        connectionRole
    }

    func supportsCapability(_ check: (Capability) -> Bool) -> Bool {
        capabilities.contains(where: check)
    }

    func replaceCapabilitiesForTesting(_ capabilities: Set<NIOIMAPCore.Capability>) {
        self.capabilities = capabilities
    }

    func replaceChannelForTesting(_ channel: Channel?) {
        self.channel = channel
    }

    func replaceStartTLSUpgradeForTesting(_ upgrade: (() async throws -> Void)?) {
        self.startTLSUpgradeOverrideForTesting = upgrade
    }

    func replaceOpenChannelForTesting(_ open: (() async throws -> Channel)?) {
        self.openChannelOverrideForTesting = open
    }


    /// Invalidate authentication operations without closing the transport.
    ///
    /// Used by server teardown before it awaits graceful protocol cleanup. Any
    /// credential-bearing operation that has not enqueued its write is rejected.
    func invalidateAuthenticationGeneration() {
        transportState.lock.withLock {
            transportState.authenticationGeneration += 1
            transportState.isSessionAuthenticated = false
            transportState.capabilities = []
            transportState.namespaces = nil
        }
    }

    func connect() async throws {
        let generation = captureTransportGeneration()
        try await commandQueue.run { [self] in
            guard self.isCurrentTransportGeneration(generation) else {
                throw CancellationError()
            }
            try await self.connectBody(expectedGeneration: generation)
        }
    }

    /// Starts a connection using generations captured by its owning lease.
    func connect(expectedGeneration: Int, authenticationGeneration: Int) async throws {
        try await commandQueue.run { [self] in
            guard self.isCurrentTransportGeneration(expectedGeneration) else {
                throw CancellationError()
            }
            try self.checkAuthenticationGeneration(authenticationGeneration)
            try await self.connectBody(
                expectedGeneration: expectedGeneration,
                authenticationGeneration: authenticationGeneration
            )
        }
    }

    func done(timeoutSeconds: TimeInterval = 15) async throws {
        try await commandQueue.run { [self] in
            try await self.doneBody(timeoutSeconds: timeoutSeconds)
        }
    }

    func disconnect() async throws {
        try await commandQueue.run { [self] in
            try await self.disconnectBody()
        }
    }
}
