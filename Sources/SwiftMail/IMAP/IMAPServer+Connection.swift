import Foundation
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO

// MARK: - Connection and Login

extension IMAPServer {
    /// Immediately closes the primary transport without waiting on a queued command.
    public func forceCloseTransport() {
        primaryConnection.forceCloseTransport()
    }

    /// Immediately closes and evicts the exact named connection lease.
    public func forceCloseConnection(token: IMAPNamedConnectionToken) {
        if let pending = pendingNamedConnections[token.name], pending.token == token {
            pendingNamedConnections.removeValue(forKey: token.name)
            lifecycleState.unregister(pending.connection)
            pending.validity.invalidate()
            pending.connection.forceCloseTransport()
            let error = CancellationError()
            pending.waiters.forEach { $0.continuation.resume(throwing: error) }
            return
        }

        guard let entry = namedConnections[token.name], entry.token == token else { return }
        namedConnections.removeValue(forKey: token.name)
        lifecycleState.unregister(entry.connection)
        entry.handle.validity.invalidate()
        entry.connection.forceCloseTransport()
    }

    /// Immediately closes every in-flight named acquisition. Existing named
    /// leases are intentionally untouched; each pending entry is invalidated
    /// and force-closed independently.
    public func forceClosePendingNamedConnections() {
        let pendingEntries = pendingNamedConnections
        pendingNamedConnections.removeAll()
        let error = CancellationError()
        for pending in pendingEntries.values {
            lifecycleState.unregister(pending.connection)
            pending.validity.invalidate()
            pending.connection.forceCloseTransport()
            pending.waiters.forEach { $0.continuation.resume(throwing: error) }
        }
    }

    /// Gracefully closes and removes the exact named connection lease.
    public func closeConnection(token: IMAPNamedConnectionToken) async {
        guard let entry = namedConnections[token.name], entry.token == token else { return }
        namedConnections.removeValue(forKey: token.name)
        lifecycleState.unregister(entry.connection)
        entry.handle.validity.invalidate()
        try? await entry.connection.done()
        try? await entry.connection.disconnect()
    }

    /**
     Connect to the IMAP server using SSL/TLS

     This method establishes the IMAP transport connection and retrieves
     its capabilities. Port `993` defaults to implicit TLS, port `143` defaults to
     plain text with opportunistic STARTTLS.

     - Throws:
     - `IMAPError.connectionFailed` if the connection cannot be established
     - `NIOSSLError` if SSL/TLS negotiation fails
     - Note: Logs connection attempts and capability retrieval at info level
     */
    public func connect() async throws {
        let registrationEpoch = lifecycleState.captureRegistrationEpoch()
        guard lifecycleState.register(
            primaryConnection, registrationEpoch: registrationEpoch
        ) else {
            throw CancellationError()
        }
        try await primaryConnection.connect()
    }

    /**
     Fetch server capabilities

     This method explicitly requests the server's capabilities. It's called automatically
     after connection and login, but can be called manually if needed.

     - Throws: An error if the capability command fails
     - Returns: An array of server capabilities
     - Note: Updates the internal capabilities set with the server's response
     */
    @discardableResult public func fetchCapabilities() async throws -> [Capability] {
        try await primaryConnection.fetchCapabilities()
    }

    /**
     Check if the server supports a specific capability
     - Parameter capability: The capability to check for
     - Returns: True if the server supports the capability
     */
    func supportsCapability(_ check: (Capability) -> Bool) -> Bool {
        return primaryConnection.supportsCapability(check)
    }

    /**
     Check if the connection to the IMAP server is currently active
     - Returns: True if the connection is active and ready for commands
     */
    public var isConnected: Bool {
        primaryConnection.isConnected
    }

    /**
     Login to the IMAP server

     This method authenticates with the IMAP server using the provided credentials.
     After successful login, it updates the server capabilities as they may change
     after authentication.

     - Parameters:
     - username: The username for authentication
     - password: The password for authentication
     - Throws:
     - `IMAPError.loginFailed` if authentication fails
     - `IMAPError.connectionFailed` if not connected
     - Note: Logs login attempts at info level (without credentials)
     */
    public func login(username: String, password: String) async throws {
        let authenticationGeneration = primaryConnection.captureAuthenticationGeneration()
        try await primaryConnection.login(
            username: username, password: password,
            authenticationGeneration: authenticationGeneration
        )
        try storeAuthenticationIfCurrent(Authentication(
            method: .login(username: username, password: password),
            identification: clientIdentification
        ), generation: authenticationGeneration)
        try await identifyPrimaryConnectionIfNeeded(
            authenticationGeneration: authenticationGeneration
        )
        namespaces = primaryConnection.namespacesSnapshot
    }

    /// Authenticate using AUTHENTICATE PLAIN (RFC 4616) with optional SASL-IR (RFC 4959).
    ///
    /// When the server advertises `SASL-IR`, credentials are sent inline with the
    /// AUTHENTICATE command (saving a round trip). Otherwise falls back to the standard
    /// continuation-based exchange.
    ///
    /// - Parameters:
    ///   - username: The username (authcid) for authentication.
    ///   - password: The password for authentication.
    /// - Throws: ``IMAPError.unsupportedAuthMechanism`` if the server does not advertise AUTH=PLAIN,
    ///   or ``IMAPError.authFailed`` when authentication fails.
    public func authenticatePlain(username: String, password: String) async throws {
        let authenticationGeneration = primaryConnection.captureAuthenticationGeneration()
        try await primaryConnection.authenticatePlain(
            username: username, password: password,
            authenticationGeneration: authenticationGeneration
        )
        try storeAuthenticationIfCurrent(Authentication(
            method: .plain(username: username, password: password),
            identification: clientIdentification
        ), generation: authenticationGeneration)
        try await identifyPrimaryConnectionIfNeeded(
            authenticationGeneration: authenticationGeneration
        )
        namespaces = primaryConnection.namespacesSnapshot
    }

    /// Performs XOAUTH2 authentication for the current IMAP connection.
    /// - Parameters:
    ///   - email: The full mailbox address to authenticate as.
    ///   - accessToken: The OAuth 2.0 access token.
    /// - Throws: ``IMAPError.unsupportedAuthMechanism`` if the server does not advertise XOAUTH2 or
    ///   ``IMAPError.authFailed`` when authentication fails.
    public func authenticateXOAUTH2(email: String, accessToken: String) async throws {
        let authenticationGeneration = primaryConnection.captureAuthenticationGeneration()
        try await primaryConnection.authenticateXOAUTH2(
            email: email, accessToken: accessToken,
            authenticationGeneration: authenticationGeneration
        )
        try storeAuthenticationIfCurrent(Authentication(
            method: .xoauth2(email: email, accessTokenProvider: { accessToken }),
            identification: clientIdentification
        ), generation: authenticationGeneration)
        try await identifyPrimaryConnectionIfNeeded(
            authenticationGeneration: authenticationGeneration
        )
        namespaces = primaryConnection.namespacesSnapshot
    }

    /// Configures XOAUTH2 re-authentication to resolve the access token dynamically.
    /// Use this after a successful OAuth-backed login so automatic reconnects do not reuse a stale token.
    public func setXOAUTH2AccessTokenProvider(
        email: String,
        accessTokenProvider: @escaping @Sendable () async throws -> String
    ) {
        authentication = Authentication(
            method: .xoauth2(email: email, accessTokenProvider: accessTokenProvider),
            identification: clientIdentification,
            replayEpoch: lifecycleState.replayEpoch.capture(),
            replayFence: lifecycleState.replayEpoch
        )
    }

    /// Stores the RFC 2971 client identity replayed after every successful
    /// authentication on every connection this server opens (primary,
    /// dedicated IDLE connections, and transparent re-authentication).
    /// Some servers (e.g. NetEase 163/126) reject SELECT on any authenticated
    /// connection that has not identified itself; configuring this once makes
    /// every connection — including ones the server opens internally — send
    /// ID right after authenticating. Call it before
    /// `login`/`authenticatePlain`/`authenticateXOAUTH2`. Servers that do not
    /// advertise the ID capability are never sent the command, and a server
    /// refusing ID (NO/BAD) never fails the authentication — but an ID
    /// failure that kills the connection surfaces as an authentication error
    /// instead of handing back a dead session.
    public func setClientIdentification(_ identification: Identification?) {
        clientIdentification = identification
        authentication?.identification = identification
    }

    func storeAuthenticationIfCurrent(
        _ value: Authentication,
        generation: Int
    ) throws {
        // Keep this check immediately adjacent to publication. The actor cannot
        // suspend between the validation and assignment, so sign-out cannot
        // leave a stale credential replay after the authentication await.
        try primaryConnection.checkAuthenticationGeneration(generation)
        authentication = Authentication(
            method: value.method,
            identification: value.identification,
            replayEpoch: lifecycleState.replayEpoch.capture(),
            replayFence: lifecycleState.replayEpoch
        )
    }

    /// RFC 2971 replay for the primary connection's explicit authentication
    /// paths, with the same failure semantics as the internal replay in
    /// ``Authentication/identify(_:with:)``.
    private func identifyPrimaryConnectionIfNeeded(
        authenticationGeneration: Int? = nil
    ) async throws {
        guard let clientIdentification else { return }
        try await Authentication.identify(
            primaryConnection, with: clientIdentification,
            authenticationGeneration: authenticationGeneration
        )
    }

    /// Identify the client to the server using the `ID` command.
    /// - Parameter identification: Information describing the client. Pass the default value to send no information.
    /// - Returns: Information returned by the server.
    /// - Throws: ``IMAPError.commandNotSupported`` if the server does not support the command or
    ///   ``IMAPError.commandFailed`` on failure.
    public func id(_ identification: Identification = Identification()) async throws -> Identification {
        guard capabilities.contains(.id) else {
            throw IMAPError.commandNotSupported("ID command not supported by server")
        }

        let command = IDCommand(identification: identification)
        return try await executeCommand(command)
    }

    /**
     Disconnect from the server without sending a command

     This method immediately closes the connection to the server without sending
     a LOGOUT command. For a graceful disconnect, use logout() instead.

     - Throws: An error if the disconnection fails
     - Note: Logs disconnection at debug level
     */
    public func disconnect() async throws {
        try await closeAllConnections(clearAuthentication: false)
    }

    /// Retrieve (or create) a reusable named connection.
    ///
    /// Calling this method multiple times with the same `name` returns the same
    /// underlying authenticated connection handle.
    ///
    /// - Parameter name: Stable user-defined name for this connection.
    /// - Returns: A user-controlled named connection.
    /// - Throws: ``IMAPError/invalidArgument(_:)`` when `name` is empty or
    ///   ``IMAPError/commandFailed(_:)`` if authentication is not configured.
    public func connection(named name: String) async throws -> IMAPNamedConnection {
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedName.isEmpty else {
            throw IMAPError.invalidArgument("Connection name must not be empty")
        }

        if let existing = namedConnections[normalizedName] {
            return existing.handle
        }

        if pendingNamedConnections[normalizedName] != nil {
            let waiterID = UUID()
            return try await withTaskCancellationHandler(operation: {
                try await withCheckedThrowingContinuation { continuation in
                    pendingNamedConnections[normalizedName]?.waiters.append(
                        .init(id: waiterID, continuation: continuation)
                    )
                }
            }, onCancel: {
                Task { await self.cancelPendingWaiter(name: normalizedName, waiterID: waiterID) }
            })
        }

        guard let authentication else {
            throw IMAPError.commandFailed("Authentication required before creating a named connection")
        }

        let registrationEpoch = lifecycleState.captureRegistrationEpoch()
        nextNamedConnectionGeneration &+= 1
        let token = IMAPNamedConnectionToken(name: normalizedName, generation: nextNamedConnectionGeneration)
        let connection = makeNamedConnection(
            name: normalizedName, registrationEpoch: registrationEpoch
        )
        guard lifecycleState.isCurrentRegistration(connection, epoch: registrationEpoch) else {
            throw CancellationError()
        }
        let validity = IMAPNamedConnectionValidity()
        pendingNamedConnections[normalizedName] = PendingNamedConnection(
            connection: connection, token: token, validity: validity, waiters: []
        )

        let handle = IMAPNamedConnection(
            name: normalizedName,
            connection: connection,
            token: token,
            validity: validity,
            authenticateOnConnection: { connection in
                try await authentication.authenticate(on: connection)
            },
            authenticateOnConnectionWithGeneration: { connection, authenticationGeneration in
                try await authentication.authenticate(
                    on: connection, authenticationGeneration: authenticationGeneration
                )
            }
        )

        do {
            try await withTaskCancellationHandler(operation: {
                try await handle.connect()
            }, onCancel: {
                // This is deliberately synchronous and exact: the cancelled
                // creator cannot leave a transport running while its actor
                // operation unwinds.
                validity.invalidate()
                connection.forceCloseTransport()
            })
            guard let pending = pendingNamedConnections[normalizedName], pending.token == token else {
                try? await connection.disconnect()
                throw CancellationError()
            }

            namedConnections[normalizedName] = NamedConnection(
                connection: connection, handle: handle, token: token
            )
            pendingNamedConnections.removeValue(forKey: normalizedName)
            pending.waiters.forEach { $0.continuation.resume(returning: handle) }
            return handle
        } catch {
            let pending: PendingNamedConnection?
            if let current = pendingNamedConnections[normalizedName], current.token == token {
                pending = pendingNamedConnections.removeValue(forKey: normalizedName)
            } else {
                pending = nil
            }
            lifecycleState.unregister(connection)
            try? await connection.disconnect()
            pending?.waiters.forEach { $0.continuation.resume(throwing: error) }
            throw error
        }
    }

    private func cancelPendingWaiter(name: String, waiterID: UUID) {
        guard var pending = pendingNamedConnections[name],
              let index = pending.waiters.firstIndex(where: { $0.id == waiterID }) else { return }
        let waiter = pending.waiters.remove(at: index)
        pendingNamedConnections[name] = pending
        waiter.continuation.resume(throwing: CancellationError())
    }

    /**
     Logout from the IMAP server

     This method performs a clean logout from the server by sending the LOGOUT command
     and closing the connection. For an immediate disconnect, use disconnect() instead.

     - Throws:
     - `IMAPError.logoutFailed` if the logout fails
     - `IMAPError.connectionFailed` if not connected
     - Note: Logs logout at info level
     */
    public func logout() async throws {
        let command = LogoutCommand()
        var logoutError: Error?
        do {
            try await executeCommand(command)
        } catch {
            // LOGOUT is best effort, but its original protocol/timeout error
            // must remain the one visible to the caller.
            logoutError = error
        }

        do {
            // This runs on success, timeout, and every command failure path.
            // closeAllConnections fences replay credentials and force-closes
            // every transport before awaiting any teardown.
            try await closeAllConnections(clearAuthentication: true)
        } catch {
            if logoutError == nil {
                logoutError = error
            }
        }

        if let logoutError {
            throw logoutError
        }
    }

    /// Clears credentials retained for transparent reconnect authentication.
    /// The current transport is left untouched so callers can coordinate a
    /// graceful close separately.
    public func clearReplayCredentials() {
        authentication = nil
        lifecycleState.replayEpoch.invalidate()
        lifecycleState.invalidateAuthenticationGenerations()
    }

    /// Synchronously fences replay credentials and force-closes every transport.
    /// This is intentionally non-async so callers can start sign-out before
    /// yielding to actor cleanup or waiting for a stalled command.
    public nonisolated func beginSignOut() {
        lifecycleState.beginSignOut()
    }

    /// Synchronously force-closes every primary, named, pending, and IDLE
    /// transport. Use ``beginSignOut()`` when credentials must also be fenced.
    public nonisolated func forceCloseAll() {
        lifecycleState.forceCloseAll()
    }

    // MARK: - Connection Management Helpers

    func makeIdleConnection(
        sessionID: UUID,
        mailbox: String,
        group: EventLoopGroup,
        registrationEpoch: UInt64? = nil
    ) -> IMAPConnection {
        let shortID = String(sessionID.uuidString.prefix(8))
        let suffix = "idle-\(shortID)"
        let sanitizedMailbox = mailbox
            .replacingOccurrences(of: " ", with: "_")
            .replacingOccurrences(of: "/", with: "_")

        let loggerLabel = "com.cocoanetics.SwiftMail.IMAPServer.\(suffix)"
        let outboundLabel = "com.cocoanetics.SwiftMail.IMAP_OUT.\(suffix)"
        let inboundLabel = "com.cocoanetics.SwiftMail.IMAP_IN.\(suffix)"

        let connection = IMAPConnection(
            host: host,
            port: port,
            transportSecurity: transportSecurity,
            certificateVerificationPolicy: certificateVerificationPolicy,
            minimumTLSVersion: minimumTLSVersion,
            group: group,
            loggerLabel: loggerLabel,
            outboundLabel: outboundLabel,
            inboundLabel: inboundLabel,
            connectionID: shortID,
            connectionRole: "idle:\(sanitizedMailbox)",
            responseBufferLimit: responseBufferLimit,
            parserLimits: parserLimits
        )
        _ = lifecycleState.register(connection, registrationEpoch: registrationEpoch)
        return connection
    }

    func makeNamedConnection(
        name: String,
        registrationEpoch: UInt64? = nil
    ) -> IMAPConnection {
        let sanitizedName = sanitizedConnectionName(name)
        let suffix = "named-\(sanitizedName)"
        let shortID = String(sanitizedName.prefix(24))

        let loggerLabel = "com.cocoanetics.SwiftMail.IMAPServer.\(suffix)"
        let outboundLabel = "com.cocoanetics.SwiftMail.IMAP_OUT.\(suffix)"
        let inboundLabel = "com.cocoanetics.SwiftMail.IMAP_IN.\(suffix)"

        let connection = IMAPConnection(
            host: host,
            port: port,
            transportSecurity: transportSecurity,
            certificateVerificationPolicy: certificateVerificationPolicy,
            minimumTLSVersion: minimumTLSVersion,
            group: group,
            loggerLabel: loggerLabel,
            outboundLabel: outboundLabel,
            inboundLabel: inboundLabel,
            connectionID: "named-\(shortID)",
            connectionRole: "named:\(sanitizedName)",
            responseBufferLimit: responseBufferLimit,
            parserLimits: parserLimits
        )
        _ = lifecycleState.register(connection, registrationEpoch: registrationEpoch)
        return connection
    }

    func sanitizedConnectionName(_ name: String) -> String {
        let mapped = name.map { character -> Character in
            if character.isLetter || character.isNumber || character == "-" || character == "_" {
                return character
            }
            return "_"
        }
        let collapsed = String(mapped)
            .replacingOccurrences(of: "__", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        if collapsed.isEmpty {
            return "connection"
        }
        return String(collapsed.prefix(48))
    }

    func endIdleSession(id: UUID) async throws {
        guard let entry = idleConnections.removeValue(forKey: id) else { return }
        await teardownIdleEntry(entry)
    }

    /// Complete teardown of a dedicated IDLE entry. The cycle task must be
    /// stopped before the connection is closed: the resilient runner is
    /// self-healing, so a socket that merely closes underneath it counts as a
    /// dropped connection and is re-dialed. Stopping is gated by the session
    /// lifecycle, which lets `disconnect()` and the session's own `done()`
    /// race safely; whichever loses the gate leaves cleanup to the winner.
    private func teardownIdleEntry(_ entry: IdleConnection) async {
        lifecycleState.unregister(entry.connection)
        if let lifecycle = entry.lifecycle, let cycleTask = entry.cycleTask {
            guard await lifecycle.beginStop(cycleTask: cycleTask) else { return }
            try? await entry.connection.done()
            try? await entry.connection.disconnect()
            await cycleTask.value
            // The runner may have completed a reconnect it had already started
            // when the cancellation landed (NIO connect/auth/select are not
            // cancellation-interruptible). Close whatever it left behind so
            // teardown never relies on the group shutdown to reap a re-dialed
            // socket.
            try? await entry.connection.disconnect()
        } else {
            // The cycle task never started (the session is still connecting);
            // there is only the connection and its group to release. idle(on:)'s
            // failure path may shut the group a second time, which is harmless.
            try? await entry.connection.done()
            try? await entry.connection.disconnect()
        }
        try? await entry.idleGroup.shutdownGracefully()
    }

    func closeAllConnections(clearAuthentication: Bool = true) async throws {
        if clearAuthentication {
            // Fence replay publication before any teardown await.
            authentication = nil
            lifecycleState.replayEpoch.invalidate()
            lifecycleState.invalidateAuthenticationGenerations()
        }

        // Snapshot and evict every entry first. Cancellation and force-close
        // are deliberately synchronous so no teardown await can leave another
        // transport (or an IDLE reconnect) alive.
        let idleEntries = idleConnections
        idleConnections.removeAll()

        let pendingEntries = pendingNamedConnections
        pendingNamedConnections.removeAll()

        let namedEntries = namedConnections
        namedConnections.removeAll()

        for entry in idleEntries.values {
            lifecycleState.unregister(entry.connection)
            entry.cycleTask?.cancel()
            entry.connection.forceCloseTransport()
        }

        let cancellationError = CancellationError()
        for pending in pendingEntries.values {
            lifecycleState.unregister(pending.connection)
            pending.validity.invalidate()
            pending.connection.forceCloseTransport()
            pending.waiters.forEach { $0.continuation.resume(throwing: cancellationError) }
        }

        for entry in namedEntries.values {
            lifecycleState.unregister(entry.connection)
            entry.handle.validity.invalidate()
            entry.connection.forceCloseTransport()
        }

        primaryConnection.forceCloseTransport()

        // All transports are fenced/closed above. The remaining awaits only
        // release task and event-loop resources and cannot trigger a reconnect.
        for entry in idleEntries.values {
            await teardownIdleEntry(entry)
        }

        for entry in namedEntries.values {
            try? await entry.connection.disconnect()
        }

        try? await primaryConnection.disconnect()

        clearMailboxState()
        lifecycleState.finishSignOut()
    }
}
