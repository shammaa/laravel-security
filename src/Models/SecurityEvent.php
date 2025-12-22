<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class SecurityEvent extends Model
{
    protected $fillable = [
        'event_type',
        'data',
        'ip',
        'user_agent',
    ];

    protected $casts = [
        'data' => 'array',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * Get table name
     */
    public function getTable(): string
    {
        return config('security.monitoring.events_table_name', 'security_events');
    }

    /**
     * Scope for filtering by event type
     */
    public function scopeOfType($query, string $eventType)
    {
        return $query->where('event_type', $eventType);
    }

    /**
     * Scope for filtering by IP
     */
    public function scopeForIp($query, string $ip)
    {
        return $query->where('ip', $ip);
    }

    /**
     * Scope for recent events
     */
    public function scopeRecent($query, int $days = 7)
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }
}

