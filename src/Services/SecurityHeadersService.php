<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

class SecurityHeadersService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Get all security headers
     */
    public function getHeaders(): array
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return [];
        }

        $headers = [];

        // Content-Security-Policy
        if (!empty($this->config['csp'])) {
            $headers['Content-Security-Policy'] = $this->config['csp'];
        }

        // X-Frame-Options
        if (!empty($this->config['x_frame_options'])) {
            $headers['X-Frame-Options'] = $this->config['x_frame_options'];
        }

        // X-Content-Type-Options
        if (!empty($this->config['x_content_type_options'])) {
            $headers['X-Content-Type-Options'] = $this->config['x_content_type_options'];
        }

        // X-XSS-Protection
        if (!empty($this->config['x_xss_protection'])) {
            $headers['X-XSS-Protection'] = $this->config['x_xss_protection'];
        }

        // Strict-Transport-Security
        if (!empty($this->config['strict_transport_security'])) {
            $headers['Strict-Transport-Security'] = $this->config['strict_transport_security'];
        }

        // Referrer-Policy
        if (!empty($this->config['referrer_policy'])) {
            $headers['Referrer-Policy'] = $this->config['referrer_policy'];
        }

        // Permissions-Policy
        if (!empty($this->config['permissions_policy'])) {
            $headers['Permissions-Policy'] = $this->config['permissions_policy'];
        }

        return $headers;
    }

    /**
     * Get specific header
     */
    public function getHeader(string $name): ?string
    {
        $headers = $this->getHeaders();
        return $headers[$name] ?? null;
    }

    /**
     * Set CSP header
     */
    public function setCsp(string $policy): void
    {
        $this->config['csp'] = $policy;
    }

    /**
     * Set X-Frame-Options
     */
    public function setXFrameOptions(string $value): void
    {
        $this->config['x_frame_options'] = $value;
    }
}

