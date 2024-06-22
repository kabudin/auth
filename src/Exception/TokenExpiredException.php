<?php
declare(strict_types=1);

namespace Bud\Auth\Exception;

use Bud\Auth\Jwt;

class TokenExpiredException extends \RuntimeException
{
    protected Jwt $jwt;

    protected int $statusCode;

    public function __construct(string $message, int $code = 402, \Throwable $previous = null)
    {
        $this->statusCode = $code;
        parent::__construct($message, $code, $previous);
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
    /**
     * @param Jwt $jwt
     * @return static
     */
    public function setJwt(Jwt $jwt): static
    {
        $this->jwt = $jwt;

        return $this;
    }

    public function getJwt(): Jwt
    {
        return $this->jwt;
    }
}
