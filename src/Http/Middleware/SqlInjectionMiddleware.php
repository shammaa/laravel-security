<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Shammaa\LaravelSecurity\Services\SqlInjectionDetector;

class SqlInjectionMiddleware
{
    protected SqlInjectionDetector $detector;

    public function __construct(SqlInjectionDetector $detector)
    {
        $this->detector = $detector;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($this->detector->detectArray($request->all())) {
            if (config('security.sql_injection.block_on_detect', true)) {
                return response()->json([
                    'error' => 'Invalid request',
                    'message' => 'Your request contains potentially dangerous content.',
                ], 400);
            }
        }

        return $next($request);
    }
}

