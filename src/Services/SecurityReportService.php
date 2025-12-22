<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Shammaa\LaravelSecurity\Models\SecurityLog;
use Shammaa\LaravelSecurity\Models\SecurityEvent;
use Shammaa\LaravelSecurity\Models\BlockedIp;
use Illuminate\Support\Collection;

class SecurityReportService
{
    /**
     * Generate security report
     */
    public function generateReport(int $days = 30): array
    {
        $since = now()->subDays($days);

        $threats = $this->getThreatsReport($since);
        $events = $this->getEventsReport($since);
        $blockedIps = $this->getBlockedIpsReport();
        $statistics = $this->getStatistics($since);

        return [
            'period' => [
                'from' => $since->toDateTimeString(),
                'to' => now()->toDateTimeString(),
                'days' => $days,
            ],
            'threats' => $threats,
            'events' => $events,
            'blocked_ips' => $blockedIps,
            'statistics' => $statistics,
            'summary' => $this->generateSummary($threats, $events, $blockedIps),
        ];
    }

    /**
     * Get threats report
     */
    protected function getThreatsReport($since): array
    {
        try {
            return SecurityLog::where('created_at', '>=', $since)
                ->selectRaw('type, COUNT(*) as count, MAX(created_at) as last_occurrence')
                ->groupBy('type')
                ->orderBy('count', 'desc')
                ->get()
                ->map(function ($item) {
                    return [
                        'type' => $item->type,
                        'count' => $item->count,
                        'last_occurrence' => $item->last_occurrence,
                    ];
                })
                ->toArray();
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Get events report
     */
    protected function getEventsReport($since): array
    {
        try {
            return SecurityEvent::where('created_at', '>=', $since)
                ->selectRaw('event_type, COUNT(*) as count, MAX(created_at) as last_occurrence')
                ->groupBy('event_type')
                ->orderBy('count', 'desc')
                ->get()
                ->map(function ($item) {
                    return [
                        'event_type' => $item->event_type,
                        'count' => $item->count,
                        'last_occurrence' => $item->last_occurrence,
                    ];
                })
                ->toArray();
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Get blocked IPs report
     */
    protected function getBlockedIpsReport(): array
    {
        try {
            return BlockedIp::where('is_blocked', true)
                ->select('ip', 'reason', 'blocked_at', 'blocked_until')
                ->get()
                ->map(function ($item) {
                    return [
                        'ip' => $item->ip,
                        'reason' => $item->reason,
                        'blocked_at' => $item->blocked_at,
                        'blocked_until' => $item->blocked_until,
                    ];
                })
                ->toArray();
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Get statistics
     */
    protected function getStatistics($since): array
    {
        try {
            $totalThreats = SecurityLog::where('created_at', '>=', $since)->count();
            $totalEvents = SecurityEvent::where('created_at', '>=', $since)->count();
            $totalBlockedIps = BlockedIp::where('is_blocked', true)->count();
            $uniqueIps = SecurityLog::where('created_at', '>=', $since)->distinct('ip')->count('ip');

            return [
                'total_threats' => $totalThreats,
                'total_events' => $totalEvents,
                'total_blocked_ips' => $totalBlockedIps,
                'unique_ips' => $uniqueIps,
            ];
        } catch (\Exception $e) {
            return [
                'total_threats' => 0,
                'total_events' => 0,
                'total_blocked_ips' => 0,
                'unique_ips' => 0,
            ];
        }
    }

    /**
     * Generate summary
     */
    protected function generateSummary(array $threats, array $events, array $blockedIps): array
    {
        $totalThreats = array_sum(array_column($threats, 'count'));
        $totalEvents = array_sum(array_column($events, 'count'));

        $topThreat = !empty($threats) ? $threats[0] : null;
        $topEvent = !empty($events) ? $events[0] : null;

        return [
            'total_threats' => $totalThreats,
            'total_events' => $totalEvents,
            'blocked_ips_count' => count($blockedIps),
            'top_threat' => $topThreat,
            'top_event' => $topEvent,
            'risk_level' => $this->calculateRiskLevel($totalThreats, $totalEvents),
        ];
    }

    /**
     * Calculate risk level
     */
    protected function calculateRiskLevel(int $threats, int $events): string
    {
        $score = ($threats * 2) + $events;

        if ($score >= 100) {
            return 'high';
        } elseif ($score >= 50) {
            return 'medium';
        } else {
            return 'low';
        }
    }
}

