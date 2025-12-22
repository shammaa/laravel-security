<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Listeners;

use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;
use Shammaa\LaravelSecurity\Services\RateLimitingService;
use Illuminate\Support\Facades\App;

class RateLimitUser
{
    protected RateLimitingService $rateLimiting;

    public function __construct()
    {
        $this->rateLimiting = App::make(RateLimitingService::class);
    }

    /**
     * Handle the event.
     */
    public function handle(SecurityThreatDetected $event): void
    {
        $ip = $event->ip;
        if (!$ip) {
            return;
        }

        // Apply stricter rate limiting for IPs with security threats
        $key = 'security_rate_limit:' . md5($ip);
        $this->rateLimiting->attempt($key, 10, 60); // 10 attempts per hour
    }
}

