<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Validators;

use Shammaa\LaravelSecurity\Services\SqlInjectionDetector;
use Illuminate\Support\Facades\App;

class SqlInjectionValidator
{
    protected SqlInjectionDetector $detector;

    public function __construct()
    {
        $this->detector = App::make(SqlInjectionDetector::class);
    }

    /**
     * Validate input for SQL Injection
     */
    public function validate($input): array
    {
        if (is_array($input)) {
            $detected = $this->detector->detectArray($input);
        } else {
            $detected = $this->detector->detect((string) $input);
        }

        return [
            'valid' => !$detected,
            'detected' => $detected,
        ];
    }
}

