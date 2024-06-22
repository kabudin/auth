<?php
declare(strict_types=1);

namespace Bud\Auth\Exception;

class PermissionException extends \RuntimeException
{
    protected int $statusCode = 403;

    public function __construct(string $message, \Throwable $previous = null)
    {
        parent::__construct($message, 403, $previous);
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}
