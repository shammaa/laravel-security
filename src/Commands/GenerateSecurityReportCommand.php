<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Commands;

use Illuminate\Console\Command;
use Shammaa\LaravelSecurity\Services\SecurityReportService;
use Illuminate\Support\Facades\App;

class GenerateSecurityReportCommand extends Command
{
    protected $signature = 'security:report {--days=30 : Number of days to include in report} {--format=json : Output format (json, table)}';
    protected $description = 'Generate security report';

    public function handle(): int
    {
        $days = (int) $this->option('days');
        $format = $this->option('format');

        $this->info("Generating security report for the last {$days} days...");

        $reportService = App::make(SecurityReportService::class);
        $report = $reportService->generateReport($days);

        if ($format === 'table') {
            $this->displayTable($report);
        } else {
            $this->line(json_encode($report, JSON_PRETTY_PRINT));
        }

        return Command::SUCCESS;
    }

    protected function displayTable(array $report): void
    {
        $this->info("\n=== Security Report ===");
        $this->info("Period: {$report['period']['from']} to {$report['period']['to']}");

        $this->info("\n--- Threats ---");
        $this->table(
            ['Type', 'Count', 'Last Occurrence'],
            array_map(function ($threat) {
                return [
                    $threat['type'],
                    $threat['count'],
                    $threat['last_occurrence'],
                ];
            }, $report['threats'])
        );

        $this->info("\n--- Statistics ---");
        $stats = $report['statistics'];
        $this->line("Total Threats: {$stats['total_threats']}");
        $this->line("Total Events: {$stats['total_events']}");
        $this->line("Blocked IPs: {$stats['total_blocked_ips']}");
        $this->line("Unique IPs: {$stats['unique_ips']}");

        $summary = $report['summary'];
        $this->info("\n--- Summary ---");
        $this->line("Risk Level: " . strtoupper($summary['risk_level']));
        $this->line("Total Threats: {$summary['total_threats']}");
        $this->line("Total Events: {$summary['total_events']}");
    }
}

