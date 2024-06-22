<?php
declare(strict_types=1);

namespace Bud\Auth\Exception;

class AuthException extends \RuntimeException
{
    protected int $statusCode = 401;

    public function __construct(string $message, \Throwable $previous = null)
    {
        parent::__construct($message, 401, $previous);
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}
