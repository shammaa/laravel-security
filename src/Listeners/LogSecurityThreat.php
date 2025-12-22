<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Listeners;

use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;
use Shammaa\LaravelSecurity\Services\SecurityMonitoringService;
use Illuminate\Support\Facades\App;

class LogSecurityThreat
{
    protected SecurityMonitoringService $monitoring;

    public function __construct()
    {
        $this->monitoring = App::make(SecurityMonitoringService::class);
    }

    /**
     * Handle the event.
     */
    public function handle(SecurityThreatDetected $event): void
    {
        $this->monitoring->logThreat(
            $event->type,
            "Security threat detected: {$event->type}",
            request(),
            [
                'input' => $event->input,
                'pattern' => $event->pattern,
            ]
        );
    }
}

