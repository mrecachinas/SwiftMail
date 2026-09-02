import Foundation
import NIO
import NIOEmbedded
import NIOIMAP
import NIOIMAPCore
import Testing
@testable import SwiftMail

@Suite(.serialized)
struct AuthenticationGenerationFenceTests {
    @Test
    func invalidatedGenerationCannotPublishAuthentication() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let connection = makeConnection(group: group)
        let generation = connection.captureAuthenticationGeneration()
        let gate = PublicationGate()
        let box = ConnectionBox(connection)

        let publication = Task {
            await gate.waitUntilReleased()
            return box.connection.publishAuthenticationIfCurrent(generation)
        }
        _ = connection.forceCloseTransport()
        await gate.release()

        #expect(await publication.value == false)
        #expect(!connection.isAuthenticated)
        try? await group.shutdownGracefully()
    }

    @Test
    func staleGenerationCannotReconnectForPostAuthenticationCommand() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let connection = makeConnection(group: group)
        let generation = connection.captureAuthenticationGeneration()
        _ = connection.forceCloseTransport()

        do {
            _ = try await connection.executeCommand(
                CapabilityCommand(), authenticationGeneration: generation
            )
            Issue.record("stale post-auth command should be fenced")
        } catch {
            #expect(error is CancellationError)
        }
        try? await group.shutdownGracefully()
    }

    @Test
    func staleGenerationFencesEveryAuthenticationMechanism() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let connection = makeConnection(group: group)
        let generation = connection.captureAuthenticationGeneration()
        _ = connection.forceCloseTransport()

        for mechanism in ["LOGIN", "PLAIN", "XOAUTH2"] {
            do {
                switch mechanism {
                    case "LOGIN":
                        try await connection.login(
                            username: "user", password: "password",
                            authenticationGeneration: generation
                        )
                    case "PLAIN":
                        try await connection.authenticatePlain(
                            username: "user", password: "password",
                            authenticationGeneration: generation
                        )
                    default:
                        try await connection.authenticateXOAUTH2(
                            email: "user@example.com", accessToken: "token",
                            authenticationGeneration: generation
                        )
                }
                Issue.record("stale \(mechanism) authentication should be fenced")
            } catch {
                #expect(error is CancellationError)
            }
        }
        try? await group.shutdownGracefully()
    }

    @Test
    func invalidationWhileOpenIsPendingClosesUnpublishedChannel() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let connection = makeConnection(group: group)
        let openedChannel = EmbeddedChannel()
        let gate = OpenChannelGate()
        connection.replaceOpenChannelForTesting {
            await gate.waitUntilReleased()
            return openedChannel
        }

        let connect = Task { try await connection.connect() }
        while !(await gate.isStarted()) {
            try await Task.sleep(nanoseconds: 1_000_000)
        }

        _ = connection.forceCloseTransport()
        await gate.release()

        do {
            try await connect.value
            Issue.record("stale open should fail")
        } catch {
            #expect(error is CancellationError)
        }
        #expect(!openedChannel.isActive)
        try? await group.shutdownGracefully()
    }

    @Test
    func staleAuthenticationCannotBePublishedAfterReplayCredentialsAreCleared() async throws {
        let server = IMAPServer(host: "localhost", port: 1, useTLS: false)
        let connection = await server.primaryConnection
        let generation = connection.captureAuthenticationGeneration()
        await server.clearReplayCredentials()

        let value = IMAPServer.Authentication(
            method: .login(username: "user", password: "password"),
            identification: nil
        )
        do {
            try await server.storeAuthenticationIfCurrent(value, generation: generation)
            Issue.record("stale authentication should not be published")
        } catch {
            #expect(error is CancellationError)
        }
        #expect(await server.authentication == nil)
    }

    #if os(macOS)
        @Test
        func retainedNamedHandleCannotReplayCredentialsAfterClear() async throws {
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("swiftmail-replay-\(UUID().uuidString)")
            let maildir = root.appendingPathComponent("Maildir")
            try FileManager.default.createDirectory(
                at: maildir.appendingPathComponent("cur"), withIntermediateDirectories: true
            )
            try FileManager.default.createDirectory(
                at: maildir.appendingPathComponent("new"), withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }

            let testServer = try IMAPTestServer(
                host: "localhost", port: 0, username: "u", password: "p", maildirURL: maildir
            )
            try testServer.start()
            try await testServer.run {
                let server = IMAPServer(host: "127.0.0.1", port: testServer.port, useTLS: false)
                try await server.connect()
                try await server.login(username: "u", password: "p")
                let handle = try await server.connection(named: "cached")

                await server.clearReplayCredentials()
                do {
                    try await handle.connect()
                    Issue.record("a retained handle must not replay cleared credentials")
                } catch {
                    #expect(error is CancellationError || error is IMAPError)
                }
                try? await server.disconnect()
            }
        }
    #endif

    @Test
    func failedLogoutStillClearsReplayCredentialsAndClosesTransport() async throws {
        let server = IMAPServer(host: "127.0.0.1", port: 1, useTLS: false)
        await server.setXOAUTH2AccessTokenProvider(email: "user@example.com") { "token" }

        do {
            try await server.logout()
            Issue.record("logout should fail when the transport cannot connect")
        } catch {
            // The connection failure is the original logout error; cleanup
            // must still fence and clear the replay credential.
        }

        #expect(await server.authentication == nil)
        #expect(!(await server.isConnected))
    }

    private func makeConnection(group: EventLoopGroup) -> IMAPConnection {
        IMAPConnection(
            host: "localhost", port: 1, useTLS: false, group: group,
            loggerLabel: "test.auth-generation", outboundLabel: "test.auth-generation.out",
            inboundLabel: "test.auth-generation.in", connectionID: "auth-generation",
            connectionRole: "test"
        )
    }

    private actor OpenChannelGate {
        private var started = false
        private var continuation: CheckedContinuation<Void, Never>?

        func waitUntilReleased() async {
            started = true
            await withCheckedContinuation { continuation = $0 }
        }

        func isStarted() -> Bool { started }

        func release() {
            continuation?.resume()
            continuation = nil
        }
    }
}

private actor PublicationGate {
    private var released = false
    private var waiter: CheckedContinuation<Void, Never>?

    func waitUntilReleased() async {
        if released { return }
        await withCheckedContinuation { waiter = $0 }
    }

    func release() {
        released = true
        waiter?.resume()
        waiter = nil
    }
}

private final class ConnectionBox: @unchecked Sendable {
    let connection: IMAPConnection

    init(_ connection: IMAPConnection) {
        self.connection = connection
    }
}
