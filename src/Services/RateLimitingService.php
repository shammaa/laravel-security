<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;

class RateLimitingService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Attempt rate limiting
     */
    public function attempt(string $key, int $maxAttempts = null, int $decayMinutes = null): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return true;
        }

        $maxAttempts = $maxAttempts ?? ($this->config['max_attempts'] ?? 60);
        $decayMinutes = $decayMinutes ?? ($this->config['decay_minutes'] ?? 1);

        $attempts = RateLimiter::attempts($key);

        if ($attempts >= $maxAttempts) {
            if (isset($this->config['block_on_exceed']) && $this->config['block_on_exceed']) {
                return false;
            }
        }

        RateLimiter::hit($key, $decayMinutes * 60);

        return true;
    }

    /**
     * Check if rate limit exceeded
     */
    public function tooManyAttempts(string $key, int $maxAttempts = null): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return false;
        }

        $maxAttempts = $maxAttempts ?? ($this->config['max_attempts'] ?? 60);

        return RateLimiter::tooManyAttempts($key, $maxAttempts);
    }

    /**
     * Get remaining attempts
     */
    public function remaining(string $key, int $maxAttempts = null): int
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return PHP_INT_MAX;
        }

        $maxAttempts = $maxAttempts ?? ($this->config['max_attempts'] ?? 60);

        return max(0, $maxAttempts - RateLimiter::attempts($key));
    }

    /**
     * Clear rate limit
     */
    public function clear(string $key): void
    {
        RateLimiter::clear($key);
    }

    /**
     * Check if IP is whitelisted
     */
    public function isWhitelisted(string $ip): bool
    {
        $whitelist = $this->config['whitelist_ips'] ?? [];
        return in_array($ip, $whitelist);
    }

    /**
     * Check if IP is blacklisted
     */
    public function isBlacklisted(string $ip): bool
    {
        $blacklist = $this->config['blacklist_ips'] ?? [];
        return in_array($ip, $blacklist);
    }

    /**
     * Get available at timestamp
     */
    public function availableAt(string $key): int
    {
        return RateLimiter::availableIn($key);
    }
}

