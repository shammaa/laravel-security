<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class SecurityLog extends Model
{
    protected $fillable = [
        'type',
        'message',
        'ip',
        'user_agent',
        'url',
        'method',
        'data',
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
        return config('security.monitoring.table_name', 'security_logs');
    }

    /**
     * Scope for filtering by type
     */
    public function scopeOfType($query, string $type)
    {
        return $query->where('type', $type);
    }

    /**
     * Scope for filtering by IP
     */
    public function scopeForIp($query, string $ip)
    {
        return $query->where('ip', $ip);
    }

    /**
     * Scope for recent logs
     */
    public function scopeRecent($query, int $days = 7)
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }
}

