<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Illuminate\Support\Facades\Cache;
use Shammaa\LaravelSecurity\Events\BruteForceAttempt;
use Illuminate\Support\Facades\Event;

class AuthenticationSecurityService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Check if account is locked
     */
    public function isLocked(string $identifier): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return false;
        }

        if (!isset($this->config['brute_force_protection']) || !$this->config['brute_force_protection']) {
            return false;
        }

        $key = 'auth_lockout_' . md5($identifier);
        return Cache::has($key);
    }

    /**
     * Record failed login attempt
     */
    public function recordFailedAttempt(string $identifier): void
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return;
        }

        if (!isset($this->config['brute_force_protection']) || !$this->config['brute_force_protection']) {
            return;
        }

        $key = 'auth_attempts_' . md5($identifier);
        $maxAttempts = $this->config['max_login_attempts'] ?? 5;
        $lockoutDuration = $this->config['lockout_duration'] ?? 900;

        $attempts = Cache::get($key, 0) + 1;
        Cache::put($key, $attempts, now()->addMinutes(15));

        if ($attempts >= $maxAttempts) {
            $lockoutKey = 'auth_lockout_' . md5($identifier);
            Cache::put($lockoutKey, true, now()->addSeconds($lockoutDuration));
            
            Event::dispatch(new BruteForceAttempt($identifier, $attempts));
        }
    }

    /**
     * Clear failed attempts
     */
    public function clearFailedAttempts(string $identifier): void
    {
        $key = 'auth_attempts_' . md5($identifier);
        $lockoutKey = 'auth_lockout_' . md5($identifier);
        
        Cache::forget($key);
        Cache::forget($lockoutKey);
    }

    /**
     * Validate password strength
     */
    public function validatePasswordStrength(string $password): array
    {
        if (!isset($this->config['password_strength']) || !$this->config['password_strength']) {
            return ['valid' => true, 'errors' => []];
        }

        $errors = [];
        $minLength = $this->config['min_password_length'] ?? 8;

        if (strlen($password) < $minLength) {
            $errors[] = "Password must be at least {$minLength} characters long.";
        }

        if (isset($this->config['require_mixed_case']) && $this->config['require_mixed_case']) {
            if (!preg_match('/[a-z]/', $password) || !preg_match('/[A-Z]/', $password)) {
                $errors[] = 'Password must contain both uppercase and lowercase letters.';
            }
        }

        if (isset($this->config['require_numbers']) && $this->config['require_numbers']) {
            if (!preg_match('/[0-9]/', $password)) {
                $errors[] = 'Password must contain at least one number.';
            }
        }

        if (isset($this->config['require_symbols']) && $this->config['require_symbols']) {
            if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
                $errors[] = 'Password must contain at least one special character.';
            }
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
        ];
    }

    /**
     * Get remaining lockout time
     */
    public function getRemainingLockoutTime(string $identifier): int
    {
        $lockoutKey = 'auth_lockout_' . md5($identifier);
        $ttl = Cache::get($lockoutKey . '_ttl', 0);
        
        return max(0, $ttl - time());
    }
}

