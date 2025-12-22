<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Exceptions;

use Exception;

class RateLimitExceededException extends Exception
{
    protected int $retryAfter;

    public function __construct(string $message = 'Rate limit exceeded', int $retryAfter = 60)
    {
        parent::__construct($message);
        $this->retryAfter = $retryAfter;
    }

    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}

