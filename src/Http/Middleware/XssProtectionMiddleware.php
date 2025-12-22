<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Shammaa\LaravelSecurity\Services\XssProtectionService;

class XssProtectionMiddleware
{
    protected XssProtectionService $xssProtection;

    public function __construct(XssProtectionService $xssProtection)
    {
        $this->xssProtection = $xssProtection;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Filter input for XSS
        $input = $request->all();
        $filtered = $this->filterArray($input);
        $request->merge($filtered);

        $response = $next($request);

        // Apply CSP header if enabled
        $csp = $this->xssProtection->getCspHeader();
        if ($csp) {
            $response->headers->set('Content-Security-Policy', $csp);
        }

        return $response;
    }

    /**
     * Filter array for XSS
     */
    protected function filterArray(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->filterArray($value);
            } elseif (is_string($value)) {
                $data[$key] = $this->xssProtection->filter($value);
            }
        }

        return $data;
    }
}

