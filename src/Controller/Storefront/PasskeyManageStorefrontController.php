<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Storefront;

use Actualize\Passkey\Controller\Store\PasskeyManageStoreApiController;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Psr\Log\LoggerInterface;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Customer-facing passkey self-service on the storefront account profile page.
 * Never touch the repository directly: always call the store-api route
 * in-process, so the eligibility guard, the password step-up and the rate
 * limiting stay in exactly one place.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class PasskeyManageStorefrontController extends StorefrontController
{
    public function __construct(
        private readonly PasskeyManageStoreApiController $manageStoreApi,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route(
        path: '/account/passkey/register-challenge',
        name: 'frontend.account.passkey.register.challenge',
        defaults: ['XmlHttpRequest' => true, PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['POST'],
    )]
    public function registerChallenge(
        Request $request,
        RequestDataBag $data,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): Response {
        try {
            return $this->manageStoreApi->registerChallenge($request, $data, $context, $customer);
        } catch (ConstraintViolationException) {
            // Wrong/missing step-up password: let the JS ceremony fail fast,
            // before ever prompting the browser's WebAuthn UI.
            return new JsonResponse(['error' => 'invalid_password'], Response::HTTP_BAD_REQUEST);
        }
    }

    #[Route(
        path: '/account/passkey/register',
        name: 'frontend.account.passkey.register',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['POST'],
    )]
    public function register(Request $request, RequestDataBag $data, SalesChannelContext $context, CustomerEntity $customer): Response
    {
        try {
            $this->manageStoreApi->register($request, $data, $context, $customer);
            $this->addFlash(self::SUCCESS, $this->trans('act-passkey.manage.registerSuccess'));
        } catch (\Throwable) {
            // Wrong step-up password, a stale challenge and a rate-limit hit all
            // share one generic flash — never leak a 500 for a failed enrollment.
            $this->addFlash(self::DANGER, $this->trans('act-passkey.manage.error'));
        }

        if ($request->request->has('redirectTo') || $request->query->has('redirectTo')) {
            return $this->createActionResponse($request);
        }

        return $this->redirectToRoute('frontend.account.profile.page');
    }

    #[Route(
        path: '/account/passkey/{id}/rename',
        name: 'frontend.account.passkey.rename',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['POST'],
        requirements: ['id' => '[0-9a-f]{32}'],
    )]
    public function rename(string $id, RequestDataBag $data, SalesChannelContext $context, CustomerEntity $customer): Response
    {
        try {
            $this->manageStoreApi->rename($id, $data, $context, $customer);
            $this->addFlash(self::SUCCESS, $this->trans('act-passkey.manage.renameSuccess'));
        } catch (ConstraintViolationException) {
            // The only validation on rename is the name length.
            $this->addFlash(self::DANGER, $this->trans(
                'act-passkey.manage.nameTooLong',
                ['%max%' => CredentialRepository::MAX_NAME_LENGTH]
            ));
        } catch (\Throwable $exception) {
            // Delegates to the store-api controller, whose rename has no logging
            // catch of its own, so this wrapper records the swallowed failure.
            $this->logger->warning('Passkey rename failed', ['exception' => $exception]);
            $this->addFlash(self::DANGER, $this->trans('act-passkey.manage.error'));
        }

        return $this->redirectToRoute('frontend.account.profile.page');
    }

    #[Route(
        path: '/account/passkey/{id}/delete',
        name: 'frontend.account.passkey.delete',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['POST'],
        requirements: ['id' => '[0-9a-f]{32}'],
    )]
    public function delete(string $id, Request $request, RequestDataBag $data, SalesChannelContext $context, CustomerEntity $customer): Response
    {
        try {
            $this->manageStoreApi->delete($id, $request, $data, $context, $customer);
            $this->addFlash(self::SUCCESS, $this->trans('act-passkey.manage.deleteSuccess'));
        } catch (\Throwable $exception) {
            // Wrong step-up password or a rate-limit hit -> same generic error flash.
            // The store-api delete has no logging catch, so record it here.
            $this->logger->warning('Passkey delete failed', ['exception' => $exception]);
            $this->addFlash(self::DANGER, $this->trans('act-passkey.manage.error'));
        }

        return $this->redirectToRoute('frontend.account.profile.page');
    }
}
