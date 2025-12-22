<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Validators;

use Shammaa\LaravelSecurity\Services\SsrfProtectionService;
use Illuminate\Support\Facades\App;

class UrlValidator
{
    protected SsrfProtectionService $ssrfProtection;

    public function __construct()
    {
        $this->ssrfProtection = App::make(SsrfProtectionService::class);
    }

    /**
     * Validate URL
     */
    public function validate(string $url): array
    {
        // Basic URL validation
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return [
                'valid' => false,
                'errors' => ['Invalid URL format'],
            ];
        }

        // SSRF protection
        if (!$this->ssrfProtection->validateUrl($url)) {
            return [
                'valid' => false,
                'errors' => ['URL is not allowed (SSRF protection)'],
            ];
        }

        return [
            'valid' => true,
            'errors' => [],
        ];
    }

    /**
     * Sanitize URL
     */
    public function sanitize(string $url): string
    {
        return $this->ssrfProtection->sanitizeUrl($url);
    }
}

