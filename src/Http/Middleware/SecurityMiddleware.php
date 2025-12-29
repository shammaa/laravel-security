<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Shammaa\LaravelSecurity\Services\SecurityService;
use Shammaa\LaravelSecurity\Exceptions\SecurityException;

class SecurityMiddleware
{
    protected SecurityService $security;

    public function __construct(SecurityService $security)
    {
        $this->security = $security;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Check if IP is blocked
        if ($this->isIpBlocked($request->ip())) {
            return $this->blockedResponse($request);
        }

        // Sanitize input
        $this->sanitizeInput($request);

        // Check for SQL Injection
        if ($this->security->getSqlInjectionDetector()->detectArray($request->all())) {
            $this->handleThreat($request, 'sql_injection', 'SQL Injection attempt detected');
            if (config('security.sql_injection.block_on_detect', true)) {
                return $this->blockedResponse($request);
            }
        }

        // Check for XSS
        if ($this->checkXss($request)) {
            $this->handleThreat($request, 'xss', 'XSS attempt detected');
            if (config('security.xss.block_on_detect', true)) {
                return $this->blockedResponse($request);
            }
        }

        // Check for Command Injection
        if ($this->security->getCommandInjectionDetector()->detectArray($request->all())) {
            $this->handleThreat($request, 'command_injection', 'Command Injection attempt detected');
            if (config('security.command_injection.block_on_detect', true)) {
                return $this->blockedResponse($request);
            }
        }

        // Check for Path Traversal
        if ($this->checkPathTraversal($request)) {
            $this->handleThreat($request, 'path_traversal', 'Path Traversal attempt detected');
            if (config('security.path_traversal.block_on_detect', true)) {
                return $this->blockedResponse($request);
            }
        }

        // Apply security headers
        $response = $next($request);
        $this->applySecurityHeaders($response);

        return $response;
    }

    /**
     * Check if IP is blocked
     */
    protected function isIpBlocked(string $ip): bool
    {
        if (!config('security.ip_blocking.enabled', true)) {
            return false;
        }

        // Check whitelist
        $whitelist = config('security.ip_blocking.whitelist_ips', []);
        if (in_array($ip, $whitelist)) {
            return false;
        }

        try {
            $blockedIp = \Shammaa\LaravelSecurity\Models\BlockedIp::where('ip', $ip)
                ->where('is_blocked', true)
                ->where(function ($query) {
                    $query->whereNull('blocked_until')
                        ->orWhere('blocked_until', '>', now());
                })
                ->first();

            return $blockedIp !== null;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Sanitize input
     */
    protected function sanitizeInput(Request $request): void
    {
        if (!config('security.input.sanitize', true)) {
            return;
        }

        $input = $request->all();
        $sanitized = $this->security->getInputSanitizer()->sanitizeRequest($input);
        
        $request->merge($sanitized);
    }

    /**
     * Check for XSS
     */
    protected function checkXss(Request $request): bool
    {
        $data = $request->all();
        
        foreach ($data as $value) {
            if (is_array($value)) {
                if ($this->checkXssArray($value)) {
                    return true;
                }
            } elseif (is_string($value)) {
                $xssService = $this->security->getXssProtection();
                // Check if input contains XSS patterns
                foreach ($xssService->getPatterns() ?? [] as $pattern) {
                    if (preg_match($pattern, $value)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check XSS in array
     */
    protected function checkXssArray(array $data): bool
    {
        foreach ($data as $value) {
            if (is_array($value)) {
                if ($this->checkXssArray($value)) {
                    return true;
                }
            } elseif (is_string($value)) {
                $xssService = $this->security->getXssProtection();
                foreach ($xssService->getPatterns() ?? [] as $pattern) {
                    if (preg_match($pattern, $value)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check for Path Traversal
     */
    protected function checkPathTraversal(Request $request): bool
    {
        $path = $request->path();
        $query = $request->query();
        
        if ($this->security->getPathTraversalDetector()->detect($path)) {
            return true;
        }

        foreach ($query as $value) {
            if (is_string($value) && $this->security->getPathTraversalDetector()->detect($value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apply security headers
     */
    protected function applySecurityHeaders(Response $response): void
    {
        $headers = $this->security->getSecurityHeaders()->getHeaders();
        
        foreach ($headers as $name => $value) {
            $response->headers->set($name, $value);
        }
    }

    /**
     * Handle security threat
     */
    protected function handleThreat(Request $request, string $type, string $message): void
    {
        $this->security->getMonitoring()->logThreat($type, $message, $request);

        // Auto-block IP if configured
        if (config('security.ip_blocking.auto_block', true)) {
            $this->autoBlockIp($request->ip(), $type);
        }
    }

    /**
     * Auto-block IP
     */
    protected function autoBlockIp(string $ip, string $reason): void
    {
        // Check whitelist
        $whitelist = config('security.ip_blocking.whitelist_ips', []);
        if (in_array($ip, $whitelist)) {
            return;
        }

        try {
            $blockedIp = \Shammaa\LaravelSecurity\Models\BlockedIp::firstOrNew(['ip' => $ip]);
            $blockedIp->reason = $reason;
            $blockedIp->is_blocked = true;
            $blockedIp->blocked_at = now();
            
            $duration = config('security.ip_blocking.block_duration', 3600);
            $blockedIp->blocked_until = now()->addSeconds($duration);
            
            $blockedIp->save();
        } catch (\Exception $e) {
            // Log error but don't fail
        }
    }

    /**
     * Return blocked response
     */
    protected function blockedResponse(Request $request): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Your request has been blocked due to security reasons.',
            ], 403);
        }

        return response()->view('laravel-security::blocked', [], 403);
    }
}

