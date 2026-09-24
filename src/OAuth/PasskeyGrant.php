<?php declare(strict_types=1);

namespace Actualize\Passkey\OAuth;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Doctrine\DBAL\Connection;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\OAuth\Scope\WriteScope;
use Shopware\Core\Framework\Api\OAuth\User\User;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Custom OAuth2 grant: turns a verified admin WebAuthn assertion into a
 * standard admin access token. Mirrors ShopwareGrantType — the `administration`
 * client is non-confidential, so `validateClient()` is intentionally NOT called.
 */
class PasskeyGrant extends AbstractGrant
{
    private const GRANT_TYPE = 'passkey';

    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly LoggerInterface $logger,
        private readonly AdminLoginPolicy $loginPolicy,
        private readonly Connection $connection,
    ) {
        $this->setRefreshTokenRepository($refreshTokenRepository);
    }

    public function getIdentifier(): string
    {
        return self::GRANT_TYPE;
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        // Checked before the ceremony so an SSO-only shop never even consumes a challenge.
        if (!$this->loginPolicy->allowsNonSsoLogin()) {
            $this->logger->notice('Passkey admin login rejected: the shop allows SSO login only');
            throw OAuthServerException::invalidGrant();
        }

        $client = $this->getClientEntityOrFail('administration', $request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        $userId = $this->resolveUserId($request);
        $user = new User($userId);
        $userIdentifier = $user->getIdentifier();

        $finalizedScopes = $this->scopeRepository->finalizeScopes(
            $scopes,
            $this->getIdentifier(),
            $client,
            $userIdentifier
        );

        // Core keeps `write` only for the password and SSO grants and strips it from every other
        // one. The admin's token refresh hardcodes scope=write, and league rejects any scope the
        // refresh token lacks — without this, every refresh 400s and logs the user out.
        $finalizedScopes[] = new WriteScope();

        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $userIdentifier, $finalizedScopes);
        $responseType->setAccessToken($accessToken);

        $refreshToken = $this->issueRefreshToken($accessToken);
        if ($refreshToken !== null) {
            $responseType->setRefreshToken($refreshToken);
        }

        return $responseType;
    }

    /**
     * @return non-empty-string
     */
    private function resolveUserId(ServerRequestInterface $request): string
    {
        $responseJson = $this->getRequestParameter('passkey_response', $request);
        $challengeId = $this->getRequestParameter('passkey_challenge_id', $request);
        if (!is_string($responseJson) || $responseJson === '' || !is_string($challengeId) || $challengeId === '') {
            throw OAuthServerException::invalidRequest('passkey_response');
        }

        $host = $request->getUri()->getHost();

        try {
            // Grant runs pre-controller with no request-scoped context; CLI context is the
            // store-compliant system context here.
            $userId = $this->authenticationCeremony->verify(
                Realm::Admin,
                $responseJson,
                $challengeId,
                $host,
                Context::createCLIContext()
            );
        } catch (\Throwable $e) {
            // In 5.3.5 CounterException does NOT extend AuthenticatorResponseVerificationException,
            // and realm/lookup failures throw RuntimeException — treat every failure as invalid grant.
            $this->logger->notice('Passkey admin authentication failed', ['exception' => $e]);
            throw OAuthServerException::invalidGrant();
        }

        // AuthenticationCeremony::verify() is typed `string`, not `non-empty-string` — defend
        // against an empty resolved id before it reaches User's non-empty-string constructor.
        if ($userId === '') {
            throw OAuthServerException::invalidGrant();
        }

        $user = $this->connection->fetchAssociative(
            'SELECT `active`, `username` FROM `user` WHERE `id` = :id',
            ['id' => Uuid::fromHexToBytes($userId)]
        );

        // Same check as core's password grant, done before any token is issued: the
        // per-request active check alone would still leave a refresh token persisted.
        if ($user === false || !(bool) $user['active']) {
            $this->logger->notice('Passkey admin login rejected: the user is inactive');
            throw OAuthServerException::invalidGrant();
        }

        // The inactivity screen sends the logged-out user's name: core pins its password
        // re-login to that user, and the usernameless prompt must not let another admin
        // take over the old session's tabs. Refused here, before a token exists.
        $expectedUsername = $this->getRequestParameter('passkey_expected_username', $request);
        if (is_string($expectedUsername) && $expectedUsername !== '' && $expectedUsername !== $user['username']) {
            $this->logger->notice('Passkey admin login rejected: passkey belongs to a different user');
            throw OAuthServerException::invalidGrant();
        }

        return $userId;
    }
}
