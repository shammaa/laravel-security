<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Helpers;

use Shammaa\LaravelSecurity\Facades\Security;

if (!function_exists('security_sanitize')) {
    /**
     * Sanitize input
     */
    function security_sanitize($input)
    {
        return Security::sanitize($input);
    }
}

if (!function_exists('security_detect_sql_injection')) {
    /**
     * Detect SQL Injection
     */
    function security_detect_sql_injection(string $input): bool
    {
        return Security::detectSqlInjection($input);
    }
}

if (!function_exists('security_xss_filter')) {
    /**
     * Filter XSS
     */
    function security_xss_filter(string $html): string
    {
        return Security::xssFilter($html);
    }
}

if (!function_exists('security_rate_limit')) {
    /**
     * Rate limit
     */
    function security_rate_limit(string $key, int $maxAttempts = null, int $decayMinutes = null): bool
    {
        return Security::rateLimit($key, $maxAttempts, $decayMinutes);
    }
}

