<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Detectors;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class AnomalyDetector
{
    /**
     * Detect anomalies in request
     */
    public function detect(Request $request): array
    {
        $anomalies = [];

        // Check for unusual user agent
        if ($this->isUnusualUserAgent($request->userAgent())) {
            $anomalies[] = 'unusual_user_agent';
        }

        // Check for unusual request size
        if ($this->isUnusualRequestSize($request)) {
            $anomalies[] = 'unusual_request_size';
        }

        // Check for unusual number of parameters
        if ($this->isUnusualParameterCount($request)) {
            $anomalies[] = 'unusual_parameter_count';
        }

        // Check for rapid requests
        if ($this->isRapidRequest($request)) {
            $anomalies[] = 'rapid_requests';
        }

        return [
            'anomalies' => $anomalies,
            'count' => count($anomalies),
        ];
    }

    /**
     * Check for unusual user agent
     */
    protected function isUnusualUserAgent(?string $userAgent): bool
    {
        if (!$userAgent) {
            return true;
        }

        // Check for common bot patterns
        $botPatterns = ['bot', 'crawler', 'spider', 'scraper'];
        foreach ($botPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                return false; // Known bot, not unusual
            }
        }

        // Check for very short or very long user agents
        $length = strlen($userAgent);
        if ($length < 10 || $length > 500) {
            return true;
        }

        return false;
    }

    /**
     * Check for unusual request size
     */
    protected function isUnusualRequestSize(Request $request): bool
    {
        $size = strlen(json_encode($request->all()));
        
        // Consider requests over 1MB as unusual
        return $size > 1048576;
    }

    /**
     * Check for unusual parameter count
     */
    protected function isUnusualParameterCount(Request $request): bool
    {
        $count = count($request->all());
        
        // Consider requests with over 100 parameters as unusual
        return $count > 100;
    }

    /**
     * Check for rapid requests
     */
    protected function isRapidRequest(Request $request): bool
    {
        $ip = $request->ip();
        $key = 'rapid_requests_' . md5($ip);
        
        $count = Cache::get($key, 0);
        Cache::put($key, $count + 1, now()->addMinute());

        // More than 10 requests per minute is considered rapid
        return $count > 10;
    }
}

