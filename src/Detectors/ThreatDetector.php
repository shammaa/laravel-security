<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Detectors;

use Shammaa\LaravelSecurity\Services\SqlInjectionDetector;
use Shammaa\LaravelSecurity\Services\XssProtectionService;
use Shammaa\LaravelSecurity\Services\CommandInjectionDetector;
use Shammaa\LaravelSecurity\Services\PathTraversalDetector;
use Illuminate\Support\Facades\App;

class ThreatDetector
{
    protected SqlInjectionDetector $sqlDetector;
    protected XssProtectionService $xssProtection;
    protected CommandInjectionDetector $cmdDetector;
    protected PathTraversalDetector $pathDetector;

    public function __construct()
    {
        $this->sqlDetector = App::make(SqlInjectionDetector::class);
        $this->xssProtection = App::make(XssProtectionService::class);
        $this->cmdDetector = App::make(CommandInjectionDetector::class);
        $this->pathDetector = App::make(PathTraversalDetector::class);
    }

    /**
     * Detect all threats in input
     */
    public function detectAll($input): array
    {
        $threats = [];

        if (is_array($input)) {
            $inputString = json_encode($input);
        } else {
            $inputString = (string) $input;
        }

        // SQL Injection
        if ($this->sqlDetector->detect($inputString)) {
            $threats[] = 'sql_injection';
        }

        // XSS
        $xssPatterns = $this->xssProtection->getPatterns() ?? [];
        foreach ($xssPatterns as $pattern) {
            if (preg_match($pattern, $inputString)) {
                $threats[] = 'xss';
                break;
            }
        }

        // Command Injection
        if ($this->cmdDetector->detect($inputString)) {
            $threats[] = 'command_injection';
        }

        // Path Traversal
        if ($this->pathDetector->detect($inputString)) {
            $threats[] = 'path_traversal';
        }

        return [
            'threats' => array_unique($threats),
            'count' => count(array_unique($threats)),
        ];
    }

    /**
     * Check if input is safe
     */
    public function isSafe($input): bool
    {
        $threats = $this->detectAll($input);
        return $threats['count'] === 0;
    }
}

