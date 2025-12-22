<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Listeners;

use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;
use Shammaa\LaravelSecurity\Models\BlockedIp;
use Illuminate\Support\Facades\Cache;

class BlockIpAddress
{
    /**
     * Handle the event.
     */
    public function handle(SecurityThreatDetected $event): void
    {
        if (!config('security.ip_blocking.auto_block', true)) {
            return;
        }

        $ip = $event->ip;
        if (!$ip) {
            return;
        }

        // Check whitelist
        $whitelist = config('security.ip_blocking.whitelist_ips', []);
        if (in_array($ip, $whitelist)) {
            return;
        }

        // Count attempts for this IP
        $key = 'security_attempts_' . md5($ip);
        $attempts = Cache::get($key, 0) + 1;
        Cache::put($key, $attempts, now()->addHours(1));

        $blockAfterAttempts = config('security.ip_blocking.block_after_attempts', 5);
        
        if ($attempts >= $blockAfterAttempts) {
            $blockedIp = BlockedIp::firstOrNew(['ip' => $ip]);
            $blockedIp->reason = "Multiple security threats detected ({$event->type})";
            $blockedIp->is_blocked = true;
            $blockedIp->blocked_at = now();
            
            $duration = config('security.ip_blocking.block_duration', 3600);
            $blockedIp->blocked_until = now()->addSeconds($duration);
            
            $blockedIp->save();
        }
    }
}

