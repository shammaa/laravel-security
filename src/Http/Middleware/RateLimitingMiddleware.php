<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Shammaa\LaravelSecurity\Services\RateLimitingService;
use Shammaa\LaravelSecurity\Exceptions\RateLimitExceededException;

class RateLimitingMiddleware
{
    protected RateLimitingService $rateLimiting;

    public function __construct(RateLimitingService $rateLimiting)
    {
        $this->rateLimiting = $rateLimiting;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, int $maxAttempts = null, int $decayMinutes = null): Response
    {
        $ip = $request->ip();
        $key = 'rate_limit:' . $ip . ':' . $request->path();

        // Check whitelist
        if ($this->rateLimiting->isWhitelisted($ip)) {
            return $next($request);
        }

        // Check blacklist
        if ($this->rateLimiting->isBlacklisted($ip)) {
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Your IP address has been blocked.',
            ], 403);
        }

        // Check rate limit
        if ($this->rateLimiting->tooManyAttempts($key, $maxAttempts)) {
            if (config('security.rate_limiting.block_on_exceed', true)) {
                $availableAt = $this->rateLimiting->availableAt($key);
                
                return response()->json([
                    'error' => 'Too many requests',
                    'message' => 'Please try again later.',
                    'retry_after' => $availableAt,
                ], 429)->withHeaders([
                    'Retry-After' => $availableAt,
                    'X-RateLimit-Limit' => $maxAttempts ?? config('security.rate_limiting.max_attempts', 60),
                    'X-RateLimit-Remaining' => 0,
                ]);
            }
        }

        $response = $next($request);

        // Record attempt
        $this->rateLimiting->attempt($key, $maxAttempts, $decayMinutes);

        // Add rate limit headers
        $remaining = $this->rateLimiting->remaining($key, $maxAttempts);
        $response->headers->set('X-RateLimit-Limit', $maxAttempts ?? config('security.rate_limiting.max_attempts', 60));
        $response->headers->set('X-RateLimit-Remaining', max(0, $remaining - 1));

        return $response;
    }
}

