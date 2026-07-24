<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Unit\WebAuthn\Ceremony;

use Actualize\Passkey\WebAuthn\Ceremony\WebauthnSerializer;
use PHPUnit\Framework\TestCase;

final class WebauthnSerializerTest extends TestCase
{
    public function testOversizedCredentialJsonIsRejectedBeforeParsing(): void
    {
        $serializer = new WebauthnSerializer();
        $oversized = str_repeat('x', WebauthnSerializer::MAX_CREDENTIAL_JSON_BYTES + 1);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('exceeds the maximum allowed size');
        $serializer->deserializeCredential($oversized);
    }

    public function testWithinLimitJsonReachesTheDeserializer(): void
    {
        $serializer = new WebauthnSerializer();

        // Well under the limit but not a valid credential: it must fail inside the
        // deserializer, NOT via the size guard — proving the guard only trips on size.
        try {
            $serializer->deserializeCredential('{"not":"a credential"}');
            self::fail('expected a deserialization failure for a bogus credential');
        } catch (\Throwable $exception) {
            self::assertStringNotContainsString('exceeds the maximum allowed size', $exception->getMessage());
        }
    }
}
