import Foundation
import Logging
import NIO
import NIOIMAP
import NIOIMAPCore

/// Handler responsible for managing the IMAP AUTHENTICATE PLAIN exchange (RFC 4616).
///
/// When the server supports SASL-IR (RFC 4959), credentials are sent inline
/// with the AUTHENTICATE command. Otherwise, the handler waits for the server's
/// continuation challenge before sending credentials.
final class PlainAuthenticationHandler: BaseIMAPCommandHandler<[Capability]>, IMAPCommandHandler, @unchecked Sendable {
    typealias CredentialWriter = @Sendable (Channel, ByteBuffer) throws -> EventLoopFuture<Void>

    private var collectedCapabilities: [Capability] = []
    private var credentials: ByteBuffer
    private let credentialWriter: CredentialWriter?
    private var shouldSendOnChallenge: Bool
    private let sentInlineInitialResponse: Bool
    private var fallbackContinuationSent = false

    init(
        commandTag: String,
        promise: EventLoopPromise<[Capability]>,
        credentials: ByteBuffer,
        expectsChallenge: Bool,
        credentialWriter: CredentialWriter? = nil
    ) {
        self.credentials = credentials
        self.credentialWriter = credentialWriter
        self.shouldSendOnChallenge = expectsChallenge
        self.sentInlineInitialResponse = !expectsChallenge
        super.init(commandTag: commandTag, promise: promise)
    }

    override init(commandTag: String, promise: EventLoopPromise<[Capability]>) {
        fatalError("Use init(commandTag:promise:credentials:expectsChallenge:) instead")
    }

    override func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = unwrapInboundIn(data)

        if case .authenticationChallenge(let challenge) = response {
            let challengeIsEmpty = challenge.readableBytes == 0 ||
                (challenge.getString(at: challenge.readerIndex, length: challenge.readableBytes) ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

            let sendCredentials = lock.withLock { () -> Bool in
                if shouldSendOnChallenge {
                    shouldSendOnChallenge = false
                    return true
                }

                // Compatibility fallback: some servers advertise SASL-IR but still emit an
                // empty continuation before consuming credentials. Allow one retry.
                if sentInlineInitialResponse && !fallbackContinuationSent && challengeIsEmpty {
                    fallbackContinuationSent = true
                    return true
                }
                return false
            }

            if sendCredentials {
                sendContinuation(context: context)
            }
        }

        super.channelRead(context: context, data: data)
    }

    /// Move the credential buffer out before crossing the NIO boundary. The
    /// writer supplied by IMAPConnection performs the generation/channel check
    /// while holding the same lock used by transport invalidation.
    private func sendContinuation(context: ChannelHandlerContext) {
        let credentialBuffer = lock.withLock {
            let value = credentials
            credentials = ByteBuffer()
            return value
        }

        do {
            let future: EventLoopFuture<Void>
            if let credentialWriter {
                future = try credentialWriter(context.channel, credentialBuffer)
            } else {
                // Legacy direct-handler tests have no connection generation to
                // fence. Production authentication always supplies a writer.
                future = IMAPCredentialWriteFallback.write(
                    IMAPClientHandler.OutboundIn.part(.continuationResponse(credentialBuffer)),
                    on: context.channel
                )
            }
            future.cascadeFailure(to: promise)
        } catch {
            failWithError(error)
        }
    }

    override func handleTaggedOKResponse(_ response: TaggedResponse) {
        super.handleTaggedOKResponse(response)

        let capabilities = lock.withLock { collectedCapabilities }
        if !capabilities.isEmpty {
            succeedWithResult(capabilities)
        } else if case .ok(let responseText) = response.state,
                  let code = responseText.code,
                  case .capability(let caps) = code {
            succeedWithResult(caps)
        } else {
            succeedWithResult([])
        }
    }

    override func handleTaggedErrorResponse(_ response: TaggedResponse) {
        failWithError(IMAPError.authFailed(String(describing: response.state)))
    }

    override func handleError(_ error: Error) {
        failWithError(error)
    }

    override func handleUntaggedResponse(_ response: Response) -> Bool {
        if super.handleUntaggedResponse(response) {
            return true
        }

        switch response {
            case .untagged(.capabilityData(let capabilities)):
                lock.withLock { collectedCapabilities = capabilities }
            default:
                break
        }

        return false
    }
}
