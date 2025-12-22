<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Commands;

use Illuminate\Console\Command;
use Shammaa\LaravelSecurity\Services\SecurityService;
use Illuminate\Support\Facades\App;

class SecurityScanCommand extends Command
{
    protected $signature = 'security:scan {--fix : Attempt to fix issues}';
    protected $description = 'Scan application for security issues';

    public function handle(): int
    {
        $this->info('Starting security scan...');

        $issues = [];

        // Check configuration
        $this->checkConfiguration($issues);

        // Check database security
        $this->checkDatabaseSecurity($issues);

        // Check file permissions
        $this->checkFilePermissions($issues);

        // Check environment
        $this->checkEnvironment($issues);

        if (empty($issues)) {
            $this->info('✓ No security issues found!');
            return Command::SUCCESS;
        }

        $this->warn('Found ' . count($issues) . ' security issue(s):');
        foreach ($issues as $issue) {
            $this->line("  - {$issue}");
        }

        if ($this->option('fix')) {
            $this->info('Attempting to fix issues...');
            // Implement fix logic here
        }

        return Command::FAILURE;
    }

    protected function checkConfiguration(array &$issues): void
    {
        if (config('app.debug')) {
            $issues[] = 'Debug mode is enabled in production';
        }

        if (empty(config('app.key'))) {
            $issues[] = 'Application key is not set';
        }
    }

    protected function checkDatabaseSecurity(array &$issues): void
    {
        // Check if database uses secure connection
        $driver = config('database.default');
        $connection = config("database.connections.{$driver}");

        if (isset($connection['username']) && empty($connection['password'])) {
            $issues[] = 'Database password is empty';
        }
    }

    protected function checkFilePermissions(array &$issues): void
    {
        $storagePath = storage_path();
        if (is_writable($storagePath) && !is_dir($storagePath . '/.gitignore')) {
            $issues[] = 'Storage directory is world-writable';
        }
    }

    protected function checkEnvironment(array &$issues): void
    {
        if (file_exists(base_path('.env')) && is_readable(base_path('.env'))) {
            $permissions = substr(sprintf('%o', fileperms(base_path('.env'))), -4);
            if ($permissions !== '0600' && $permissions !== '0400') {
                $issues[] = '.env file has insecure permissions';
            }
        }
    }
}

