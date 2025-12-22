<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Shammaa\LaravelSecurity\Models\SecurityLog;
use Shammaa\LaravelSecurity\Models\SecurityEvent;

class SecurityMonitoringService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Log security threat
     */
    public function logThreat(string $type, string $message, Request $request = null, array $data = []): void
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return;
        }

        if (!isset($this->config['log_threats']) || !$this->config['log_threats']) {
            return;
        }

        $logData = [
            'type' => $type,
            'message' => $message,
            'ip' => $request ? $request->ip() : null,
            'user_agent' => $request ? $request->userAgent() : null,
            'url' => $request ? $request->fullUrl() : null,
            'method' => $request ? $request->method() : null,
            'data' => $data,
        ];

        // Log to database if model exists
        try {
            SecurityLog::create($logData);
        } catch (\Exception $e) {
            // Fallback to file logging
            Log::channel($this->config['log_channel'] ?? 'daily')->warning('Security Threat', $logData);
        }

        // Log to file
        Log::channel($this->config['log_channel'] ?? 'daily')->warning('Security Threat', $logData);

        // Send alert if configured
        if (isset($this->config['alert_on_threat']) && $this->config['alert_on_threat']) {
            $this->sendAlert($type, $message, $logData);
        }
    }

    /**
     * Log all requests (if enabled)
     */
    public function logRequest(Request $request): void
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return;
        }

        if (!isset($this->config['log_all_requests']) || !$this->config['log_all_requests']) {
            return;
        }

        $logData = [
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'headers' => $request->headers->all(),
        ];

        Log::channel($this->config['log_channel'] ?? 'daily')->info('Request Logged', $logData);
    }

    /**
     * Record security event
     */
    public function recordEvent(string $eventType, array $data = []): void
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return;
        }

        try {
            SecurityEvent::create([
                'event_type' => $eventType,
                'data' => $data,
                'ip' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ]);
        } catch (\Exception $e) {
            // Fallback to file logging
            Log::channel($this->config['log_channel'] ?? 'daily')->info('Security Event', [
                'event_type' => $eventType,
                'data' => $data,
            ]);
        }
    }

    /**
     * Send security alert
     */
    protected function sendAlert(string $type, string $message, array $data): void
    {
        $email = $this->config['alert_email'] ?? null;
        if (!$email) {
            return;
        }

        // You can implement email sending here
        // For now, just log it
        Log::channel($this->config['log_channel'] ?? 'daily')->critical('Security Alert', [
            'type' => $type,
            'message' => $message,
            'data' => $data,
            'alert_email' => $email,
        ]);
    }

    /**
     * Get security statistics
     */
    public function getStatistics(int $days = 7): array
    {
        try {
            $since = now()->subDays($days);

            $threats = SecurityLog::where('created_at', '>=', $since)
                ->selectRaw('type, COUNT(*) as count')
                ->groupBy('type')
                ->get()
                ->pluck('count', 'type')
                ->toArray();

            $events = SecurityEvent::where('created_at', '>=', $since)
                ->selectRaw('event_type, COUNT(*) as count')
                ->groupBy('event_type')
                ->get()
                ->pluck('count', 'event_type')
                ->toArray();

            return [
                'threats' => $threats,
                'events' => $events,
                'total_threats' => array_sum($threats),
                'total_events' => array_sum($events),
            ];
        } catch (\Exception $e) {
            return [
                'threats' => [],
                'events' => [],
                'total_threats' => 0,
                'total_events' => 0,
            ];
        }
    }
}

