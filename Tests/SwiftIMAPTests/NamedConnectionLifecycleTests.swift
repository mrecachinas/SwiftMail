import Foundation
import NIO
import Testing
@testable import SwiftMail

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
            pendingNamedConnections[name]?.waiters.append(continuation)
        }
    }

    func pendingWaiterCountForTesting(name: String) -> Int {
        pendingNamedConnections[name]?.waiters.count ?? 0
    }
}
