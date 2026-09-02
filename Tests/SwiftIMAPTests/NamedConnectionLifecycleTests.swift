import Foundation
import NIO
import Testing
@testable import SwiftMail

private actor PostOperationGate {
    private var started = false
    private var continuation: CheckedContinuation<Void, Never>?

    func wait() async {
        started = true
        await withCheckedContinuation { continuation = $0 }
    }

    func isStarted() -> Bool { started }

    func release() {
        continuation?.resume()
        continuation = nil
    }
}

@Suite(.serialized)
struct NamedConnectionLifecycleTests {
    @Test
    func forceCloseFailsPendingWaitersAndFencesTransport() async throws {
        let server = IMAPServer(host: "localhost", port: 1, useTLS: false)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let connection = makeConnection(group: group)
        let validity = IMAPNamedConnectionValidity()
        let token = IMAPNamedConnectionToken(name: "pending", generation: 1)
        await server.installPendingForTesting(
            .init(connection: connection, token: token, validity: validity, waiters: [])
        )

        let waiter = Task {
            try await server.waitForPendingForTesting(name: "pending")
        }
        for _ in 0..<100 where await server.pendingWaiterCountForTesting(name: "pending") == 0 {
            try await Task.sleep(nanoseconds: 1_000_000)
        }

        await server.forceCloseConnection(token: token)
        do {
            _ = try await waiter.value
            Issue.record("force close should fail pending waiters")
        } catch {
            #expect(error is CancellationError)
        }
        #expect(await server.pendingNamedConnections["pending"] == nil)
        #expect(connection.captureTransportGeneration() == 1)
        try? await group.shutdownGracefully()
    }

    #if os(macOS)
        @Test
        func forceClosePendingNamedAcquisitionCancelsConnectAndAuth() async throws {
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("swiftmail-pending-\(UUID().uuidString)")
            let maildir = root.appendingPathComponent("Maildir")
            try FileManager.default.createDirectory(
                at: maildir.appendingPathComponent("cur"), withIntermediateDirectories: true
            )
            try FileManager.default.createDirectory(
                at: maildir.appendingPathComponent("new"), withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }

            let testServer = try IMAPTestServer(
                host: "localhost", port: 0, username: "u", password: "p",
                loginResponseDelay: 1, maildirURL: maildir
            )
            try testServer.start()
            try await testServer.run {
                let server = IMAPServer(host: "127.0.0.1", port: testServer.port, useTLS: false)
                try await server.connect()
                try await server.login(username: "u", password: "p")

                let acquisition = Task { try await server.connection(named: "pending-auth") }
                try await Task.sleep(nanoseconds: 50_000_000)
                let start = ContinuousClock.now
                await server.forceClosePendingNamedConnections()
                do {
                    _ = try await acquisition.value
                    Issue.record("pending acquisition should be cancelled")
                } catch {
                    // NIO may surface the force-close as a transport error
                    // rather than Swift concurrency's CancellationError.
                    #expect(error is CancellationError || error is IMAPError)
                }
                #expect(start.duration(to: .now) < .seconds(1))
                try await server.disconnect()
            }
        }
    #endif

    @Test
    func postOperationInvalidationForceClosesBoundTransport() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let connection = makeConnection(group: group)
        let validity = IMAPNamedConnectionValidity()
        let token = IMAPNamedConnectionToken(name: "post-operation", generation: 1)
        let gate = PostOperationGate()
        let handle = IMAPNamedConnection(
            name: token.name,
            connection: connection,
            token: token,
            validity: validity,
            authenticateOnConnection: { connection in
                await gate.wait()
                // The production server supplies this generation-aware
                // closure; a stale callback must not publish auth state.
                connection.isSessionAuthenticated = true
            },
            authenticateOnConnectionWithGeneration: { connection, generation in
                try connection.checkAuthenticationGeneration(generation)
                await gate.wait()
                try connection.checkAuthenticationGeneration(generation)
                connection.isSessionAuthenticated = true
            }
        )

        let authentication = Task { try await handle.ensureAuthenticated() }
        while !(await gate.isStarted()) {
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        validity.invalidate()
        await gate.release()
        do {
            try await authentication.value
            Issue.record("invalidated authentication should fail")
        } catch {
            #expect(error is IMAPError || error is CancellationError)
        }
        #expect(connection.captureTransportGeneration() == 1)
        #expect(!connection.isAuthenticated)
        try? await group.shutdownGracefully()
    }

    @Test
    func staleHandleCannotReconnectAndDelayedCleanupCannotEvictReplacement() async throws {
        let server = IMAPServer(host: "localhost", port: 1, useTLS: false)
        let oldGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let oldConnection = makeConnection(group: oldGroup)
        let oldToken = IMAPNamedConnectionToken(name: "reusable", generation: 1)
        let oldValidity = IMAPNamedConnectionValidity()
        let oldHandle = IMAPNamedConnection(
            name: oldToken.name, connection: oldConnection, token: oldToken,
            validity: oldValidity, authenticateOnConnection: { _ in }
        )
        await server.installNamedForTesting(.init(
            connection: oldConnection, handle: oldHandle, token: oldToken
        ))
        await server.forceCloseConnection(token: oldToken)

        do {
            try await oldHandle.connect()
            Issue.record("an evicted handle must not reconnect")
        } catch {
            #expect(error is IMAPError)
        }

        let replacementGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let replacementConnection = makeConnection(group: replacementGroup)
        let replacementToken = IMAPNamedConnectionToken(name: "reusable", generation: 2)
        let replacementValidity = IMAPNamedConnectionValidity()
        let replacementHandle = IMAPNamedConnection(
            name: replacementToken.name, connection: replacementConnection,
            token: replacementToken, validity: replacementValidity,
            authenticateOnConnection: { _ in }
        )
        await server.installNamedForTesting(.init(
            connection: replacementConnection, handle: replacementHandle, token: replacementToken
        ))
        await server.forceCloseConnection(token: oldToken)
        #expect(await server.namedConnections["reusable"]?.token == replacementToken)
        try? await oldGroup.shutdownGracefully()
        try? await replacementGroup.shutdownGracefully()
    }

    private func makeConnection(group: EventLoopGroup) -> IMAPConnection {
        IMAPConnection(
            host: "localhost", port: 1, useTLS: false, group: group,
            loggerLabel: "test.lifecycle", outboundLabel: "test.lifecycle.out",
            inboundLabel: "test.lifecycle.in", connectionID: "lifecycle",
            connectionRole: "test"
        )
    }
}

private extension IMAPServer {
    func installPendingForTesting(_ pending: PendingNamedConnection) {
        pendingNamedConnections[pending.token.name] = pending
    }

    func installNamedForTesting(_ entry: NamedConnection) {
        namedConnections[entry.token.name] = entry
    }

    func waitForPendingForTesting(name: String) async throws -> IMAPNamedConnection {
        try await withCheckedThrowingContinuation { continuation in
            pendingNamedConnections[name]?.waiters.append(
                .init(id: UUID(), continuation: continuation)
            )
        }
    }

    func pendingWaiterCountForTesting(name: String) -> Int {
        pendingNamedConnections[name]?.waiters.count ?? 0
    }
}
