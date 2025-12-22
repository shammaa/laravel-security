<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Commands;

use Illuminate\Console\Command;
use Shammaa\LaravelSecurity\Models\SecurityLog;
use Shammaa\LaravelSecurity\Models\SecurityEvent;

class CleanSecurityLogsCommand extends Command
{
    protected $signature = 'security:clean {--days=30 : Delete logs older than this many days} {--force : Force deletion without confirmation}';
    protected $description = 'Clean old security logs';

    public function handle(): int
    {
        $days = (int) $this->option('days');
        $force = $this->option('force');

        $cutoffDate = now()->subDays($days);

        $logsCount = SecurityLog::where('created_at', '<', $cutoffDate)->count();
        $eventsCount = SecurityEvent::where('created_at', '<', $cutoffDate)->count();

        if ($logsCount === 0 && $eventsCount === 0) {
            $this->info('No logs to clean.');
            return Command::SUCCESS;
        }

        if (!$force) {
            if (!$this->confirm("This will delete {$logsCount} log entries and {$eventsCount} event entries older than {$days} days. Continue?")) {
                $this->info('Operation cancelled.');
                return Command::SUCCESS;
            }
        }

        SecurityLog::where('created_at', '<', $cutoffDate)->delete();
        SecurityEvent::where('created_at', '<', $cutoffDate)->delete();

        $this->info("Cleaned {$logsCount} log entries and {$eventsCount} event entries.");

        return Command::SUCCESS;
    }
}

