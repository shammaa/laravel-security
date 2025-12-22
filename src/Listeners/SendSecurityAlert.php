<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Listeners;

use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

class SendSecurityAlert
{
    /**
     * Handle the event.
     */
    public function handle(SecurityThreatDetected $event): void
    {
        if (!config('security.monitoring.alert_on_threat', false)) {
            return;
        }

        $email = config('security.monitoring.alert_email');
        if (!$email) {
            return;
        }

        // Log alert
        Log::channel(config('security.monitoring.log_channel', 'daily'))->critical('Security Alert', [
            'type' => $event->type,
            'input' => $event->input,
            'pattern' => $event->pattern,
            'ip' => $event->ip,
            'user_agent' => $event->userAgent,
        ]);

        // You can implement email sending here
        // Mail::to($email)->send(new SecurityAlertMail($event));
    }
}

