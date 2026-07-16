<?php declare(strict_types=1);

namespace Actualize\Passkey\OAuth;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Shopware\Core\Framework\Api\OAuth\User\User;
use Shopware\Core\Framework\Context;

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
            throw OAuthServerException::invalidGrant();
        }

        // AuthenticationCeremony::verify() is typed `string`, not `non-empty-string` — defend
        // against an empty resolved id before it reaches User's non-empty-string constructor.
        if ($userId === '') {
            throw OAuthServerException::invalidGrant();
        }

        return $userId;
    }
}
