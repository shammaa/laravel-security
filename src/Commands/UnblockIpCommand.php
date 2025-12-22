<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Commands;

use Illuminate\Console\Command;
use Shammaa\LaravelSecurity\Models\BlockedIp;

class UnblockIpCommand extends Command
{
    protected $signature = 'security:unblock {ip : IP address to unblock}';
    protected $description = 'Unblock an IP address';

    public function handle(): int
    {
        $ip = $this->argument('ip');

        $blockedIp = BlockedIp::where('ip', $ip)->first();

        if (!$blockedIp) {
            $this->error("IP address '{$ip}' is not blocked.");
            return Command::FAILURE;
        }

        $blockedIp->unblock();

        $this->info("IP address '{$ip}' has been unblocked.");

        return Command::SUCCESS;
    }
}

