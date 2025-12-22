<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Shammaa\LaravelSecurity\Events\SqlInjectionAttempt;
use Illuminate\Support\Facades\Event;

class SqlInjectionDetector
{
    protected array $config;
    protected array $patterns;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->patterns = $config['patterns'] ?? [];
    }

    /**
     * Detect SQL Injection in string
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
                    Event::dispatch(new SqlInjectionAttempt($input, $pattern));
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Detect SQL Injection in array
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
     * Sanitize SQL query
     */
    public function sanitize(string $query): string
    {
        // Remove SQL comments
        $query = preg_replace('/--.*$/m', '', $query);
        $query = preg_replace('/\/\*.*?\*\//s', '', $query);

        // Remove dangerous SQL keywords
        $dangerousKeywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE', 'EXEC', 'EXECUTE'];
        foreach ($dangerousKeywords as $keyword) {
            $query = preg_replace('/\b' . preg_quote($keyword, '/') . '\b/i', '', $query);
        }

        return trim($query);
    }

    /**
     * Validate Eloquent query
     */
    public function validateQuery($query): bool
    {
        // Check if query uses parameter binding
        $queryString = (string) $query;
        
        // If query contains user input directly, it might be vulnerable
        // This is a basic check - in production, always use parameter binding
        return !$this->detect($queryString);
    }
}

