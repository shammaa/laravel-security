<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Validators;

use Shammaa\LaravelSecurity\Services\XssProtectionService;
use Illuminate\Support\Facades\App;

class XssValidator
{
    protected XssProtectionService $xssProtection;

    public function __construct()
    {
        $this->xssProtection = App::make(XssProtectionService::class);
    }

    /**
     * Validate input for XSS
     */
    public function validate(string $input): array
    {
        $patterns = $this->xssProtection->getPatterns() ?? [];
        $detected = false;
        $matchedPattern = null;

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                $detected = true;
                $matchedPattern = $pattern;
                break;
            }
        }

        return [
            'valid' => !$detected,
            'detected' => $detected,
            'pattern' => $matchedPattern,
        ];
    }

    /**
     * Clean input from XSS
     */
    public function clean(string $input): string
    {
        return $this->xssProtection->filter($input);
    }
}

