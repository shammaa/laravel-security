<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;

class CsrfProtectionService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Rotate CSRF token
     */
    public function rotateToken(): string
    {
        if (!isset($this->config['token_rotation']) || !$this->config['token_rotation']) {
            return Session::token();
        }

        $newToken = Str::random(40);
        Session::put('_token', $newToken);

        return $newToken;
    }

    /**
     * Validate CSRF token
     */
    public function validateToken(string $token): bool
    {
        return hash_equals(Session::token(), $token);
    }

    /**
     * Generate double submit cookie token
     */
    public function generateDoubleSubmitCookie(): string
    {
        if (!isset($this->config['double_submit_cookie']) || !$this->config['double_submit_cookie']) {
            return '';
        }

        $token = Str::random(40);
        cookie()->queue('csrf_token', $token, 120);

        return $token;
    }

    /**
     * Validate double submit cookie
     */
    public function validateDoubleSubmitCookie(string $formToken, string $cookieToken): bool
    {
        if (!isset($this->config['double_submit_cookie']) || !$this->config['double_submit_cookie']) {
            return true;
        }

        return hash_equals($formToken, $cookieToken);
    }
}

