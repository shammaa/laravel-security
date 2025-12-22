<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

class InputSanitizerService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Sanitize input data
     */
    public function sanitize($input)
    {
        if (!isset($this->config['sanitize']) || !$this->config['sanitize']) {
            return $input;
        }

        if (is_array($input)) {
            return array_map([$this, 'sanitize'], $input);
        }

        if (!is_string($input)) {
            return $input;
        }

        $sanitized = $input;

        // Strip dangerous HTML tags
        if (isset($this->config['strip_tags']) && $this->config['strip_tags']) {
            $allowedTags = $this->config['allowed_tags'] ?? [];
            $sanitized = strip_tags($sanitized, '<' . implode('><', $allowedTags) . '>');
        }

        // Convert HTML entities
        if (isset($this->config['html_entities']) && $this->config['html_entities']) {
            $sanitized = htmlspecialchars($sanitized, ENT_QUOTES | ENT_HTML5, 'UTF-8', false);
        }

        // Remove SQL keywords (basic protection)
        if (isset($this->config['sql_keywords']) && $this->config['sql_keywords']) {
            $sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'UNION'];
            foreach ($sqlKeywords as $keyword) {
                $sanitized = preg_replace('/\b' . preg_quote($keyword, '/') . '\b/i', '', $sanitized);
            }
        }

        return $sanitized;
    }

    /**
     * Sanitize request data
     */
    public function sanitizeRequest(array $data): array
    {
        return $this->sanitize($data);
    }

    /**
     * Clean string from dangerous characters
     */
    public function clean(string $input): string
    {
        // Remove null bytes
        $cleaned = str_replace("\0", '', $input);

        // Remove control characters except newlines and tabs
        $cleaned = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $cleaned);

        return trim($cleaned);
    }
}

