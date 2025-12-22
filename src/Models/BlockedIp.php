<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class BlockedIp extends Model
{
    protected $fillable = [
        'ip',
        'reason',
        'is_blocked',
        'blocked_at',
        'blocked_until',
    ];

    protected $casts = [
        'is_blocked' => 'boolean',
        'blocked_at' => 'datetime',
        'blocked_until' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * Get table name
     */
    public function getTable(): string
    {
        return config('security.ip_blocking.table_name', 'blocked_ips');
    }

    /**
     * Scope for blocked IPs
     */
    public function scopeBlocked($query)
    {
        return $query->where('is_blocked', true)
            ->where(function ($q) {
                $q->whereNull('blocked_until')
                    ->orWhere('blocked_until', '>', now());
            });
    }

    /**
     * Scope for specific IP
     */
    public function scopeForIp($query, string $ip)
    {
        return $query->where('ip', $ip);
    }

    /**
     * Check if IP is currently blocked
     */
    public function isCurrentlyBlocked(): bool
    {
        if (!$this->is_blocked) {
            return false;
        }

        if ($this->blocked_until === null) {
            return true; // Permanent block
        }

        return $this->blocked_until->isFuture();
    }

    /**
     * Unblock IP
     */
    public function unblock(): void
    {
        $this->is_blocked = false;
        $this->blocked_until = null;
        $this->save();
    }
}

