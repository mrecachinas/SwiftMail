import NIO
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
        await gate.release()
        _ = connection.forceCloseTransport()

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

    private func makeConnection(group: EventLoopGroup) -> IMAPConnection {
        IMAPConnection(
            host: "localhost", port: 1, useTLS: false, group: group,
            loggerLabel: "test.auth-generation", outboundLabel: "test.auth-generation.out",
            inboundLabel: "test.auth-generation.in", connectionID: "auth-generation",
            connectionRole: "test"
        )
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
