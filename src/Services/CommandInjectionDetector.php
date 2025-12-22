<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;
use Illuminate\Support\Facades\Event;

class CommandInjectionDetector
{
    protected array $config;
    protected array $patterns;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->patterns = $config['patterns'] ?? [];
    }

    /**
     * Detect command injection
     */
    public function detect(string $input): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return false;
        }

        if (!isset($this->config['detect_patterns']) || !$this->config['detect_patterns']) {
            return false;
        }

        foreach ($this->patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                if (isset($this->config['log_attempts']) && $this->config['log_attempts']) {
                    Event::dispatch(new SecurityThreatDetected('command_injection', $input, $pattern));
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Detect command injection in array
     */
    public function detectArray(array $data): bool
    {
        foreach ($data as $value) {
            if (is_array($value)) {
                if ($this->detectArray($value)) {
                    return true;
                }
            } elseif (is_string($value) && $this->detect($value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sanitize command
     */
    public function sanitize(string $command): string
    {
        // Remove dangerous characters
        $sanitized = preg_replace('/[;&|`$(){}]/', '', $command);
        
        // Remove dangerous functions
        $dangerousFunctions = ['exec', 'system', 'shell_exec', 'passthru', 'proc_open', 'popen', 'eval', 'assert'];
        foreach ($dangerousFunctions as $func) {
            $sanitized = preg_replace('/\b' . preg_quote($func, '/') . '\s*\(/i', '', $sanitized);
        }

        return trim($sanitized);
    }

    /**
     * Validate command against whitelist
     */
    public function validateCommand(string $command, array $whitelist): bool
    {
        $commandParts = explode(' ', $command);
        $baseCommand = $commandParts[0] ?? '';

        return in_array($baseCommand, $whitelist);
    }
}

