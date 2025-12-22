<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Shammaa\LaravelSecurity\Services\InputSanitizerService;

class InputValidationMiddleware
{
    protected InputSanitizerService $sanitizer;

    public function __construct(InputSanitizerService $sanitizer)
    {
        $this->sanitizer = $sanitizer;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Sanitize all input
        $input = $request->all();
        $sanitized = $this->sanitizer->sanitizeRequest($input);
        $request->merge($sanitized);

        return $next($request);
    }
}

