<?php

declare(strict_types=1);

namespace Lohres\JwtHelper;

use DateTimeImmutable;
use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use JsonException;
use Lcobucci\Clock\FrozenClock;
use Monolog\Logger;
use RuntimeException;
use Throwable;

/**
 * Class JwtHelper
 * Helper class for JWT verification.
 * @package Lohres\JwtHelper
 */
class JwtHelper
{
    private const string APP_NAME = "appName";
    private const string KEYS_PATH = "keysPath";
    private array $config;
    private ?Logger $logger;

    public function __construct(array $config, ?Logger $logger = null)
    {
        $this->config = $config;
        $this->logger = $logger;
        $this->logger?->debug(message: "JwtHelper initialized");
    }

    /**
     * @param string $token
     * @return array
     * @throws InvalidArgumentException
     * @throws JsonException
     * @throws RuntimeException
     */
    public function checkToken(string $token): array
    {
        $this->logger?->debug(message: "check token $token");
        $jws = $this->getTokenData(token: $token);
        if (
            !$this->checkHeader(jws: $jws) ||
            !$this->verifyToken(jws: $jws) ||
            is_bool(value: $this->checkClaim(jws: $jws))
        ) {
            $this->logger?->debug(message: "token not valid");
            throw new RuntimeException(message: "Forbidden", code: 403);
        }
        return json_decode(json: $jws->getPayload(), associative: true, flags: JSON_THROW_ON_ERROR);
    }

    /**
     * @param JWS $jws
     * @return array|bool
     * @throws RuntimeException
     */
    private function checkClaim(JWS $jws): array|bool
    {
        $this->checkConfig();
        try {
            $clock = new FrozenClock(now: new DateTimeImmutable(datetime: "now"));
            $claims = json_decode(json: $jws->getPayload(), associative: true, flags: JSON_THROW_ON_ERROR);
            $claimCheckerManager = new ClaimCheckerManager(checkers: [
                new IssuedAtChecker(clock: $clock),
                new NotBeforeChecker(clock: $clock),
                new ExpirationTimeChecker(clock: $clock),
                new AudienceChecker(audience: $this->config[self::APP_NAME])
            ]);
            $this->logger?->debug(message: "check claim");
            return $claimCheckerManager->check(claims: $claims, mandatoryClaims: ["iss", "sub", "aud"]);
        } catch (Throwable $exception) {
            $this->logger?->error(message: $exception->getMessage(), context: [$exception->getTrace()]);
        }
        return false;
    }

    /**
     * @return void
     * @throws RuntimeException
     */
    private function checkConfig(): void
    {
        if (empty($this->config[self::APP_NAME]) || empty($this->config[self::KEYS_PATH])
        ) {
            throw new RuntimeException(message: "config for jwt invalid!");
        }
    }

    /**
     * @param JWS $jws
     * @return bool
     */
    private function checkHeader(JWS $jws): bool
    {
        try {
            $headerCheckerManager = new HeaderCheckerManager(
                checkers: [new AlgorithmChecker(supportedAlgorithms: ["HS256"])],
                tokenTypes: [new JWSTokenSupport()]
            );
            $this->logger?->debug(message: "check header");
            $headerCheckerManager->check(jwt: $jws, index: 0);
            return true;
        } catch (Throwable $exception) {
            $this->logger?->error(message: $exception->getMessage(), context: [$exception->getTrace()]);
        }
        return false;
    }

    /**
     * @param string $token
     * @return JWS
     * @throws InvalidArgumentException
     */
    private function getTokenData(string $token): JWS
    {
        $this->logger?->debug(message: "get token data for $token");
        return new JWSSerializerManager(serializers: [new CompactSerializer()])->unserialize(input: $token);
    }

    /**
     * @param JWS $jws
     * @return bool
     * @throws JsonException
     * @throws RuntimeException
     */
    private function verifyToken(JWS $jws): bool
    {
        $this->checkConfig();
        $this->logger?->debug(message: "verify token data");
        $key = $this->config[self::KEYS_PATH] . DIRECTORY_SEPARATOR . $this->config[self::APP_NAME] . ".cache";
        $jwk = JWK::createFromJson(json: file_get_contents(filename: $key));
        return new JWSVerifier(
            signatureAlgorithmManager: new AlgorithmManager(algorithms: [new HS256()])
        )->verifyWithKey(jws: $jws, jwk: $jwk, signature: 0);
    }
}
