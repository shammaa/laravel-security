<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Shammaa\LaravelSecurity\Services\SecurityHeadersService;

class SecurityHeadersMiddleware
{
    protected SecurityHeadersService $headersService;

    public function __construct(SecurityHeadersService $headersService)
    {
        $this->headersService = $headersService;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Apply security headers
        $headers = $this->headersService->getHeaders();
        
        foreach ($headers as $name => $value) {
            $response->headers->set($name, $value);
        }

        return $response;
    }
}

