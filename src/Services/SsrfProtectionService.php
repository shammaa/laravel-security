<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;
use Illuminate\Support\Facades\Event;

class SsrfProtectionService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Validate URL for SSRF
     */
    public function validateUrl(string $url): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return true;
        }

        // Parse URL
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            return false;
        }

        $host = $parsed['host'];
        $ip = gethostbyname($host);

        // Check if IP is internal/private
        if (isset($this->config['block_internal_ips']) && $this->config['block_internal_ips']) {
            if ($this->isInternalIp($ip)) {
                Event::dispatch(new SecurityThreatDetected('ssrf', $url, 'Internal IP detected'));
                return false;
            }
        }

        if (isset($this->config['block_private_ips']) && $this->config['block_private_ips']) {
            if ($this->isPrivateIp($ip)) {
                Event::dispatch(new SecurityThreatDetected('ssrf', $url, 'Private IP detected'));
                return false;
            }
        }

        // Check allowed domains
        $allowedDomains = $this->config['allowed_domains'] ?? [];
        if (!empty($allowedDomains)) {
            if (!in_array($host, $allowedDomains)) {
                return false;
            }
        }

        // Check blocked domains
        $blockedDomains = $this->config['blocked_domains'] ?? [];
        if (!empty($blockedDomains)) {
            if (in_array($host, $blockedDomains)) {
                Event::dispatch(new SecurityThreatDetected('ssrf', $url, 'Blocked domain'));
                return false;
            }
        }

        return true;
    }

    /**
     * Check if IP is internal
     */
    protected function isInternalIp(string $ip): bool
    {
        // Localhost
        if ($ip === '127.0.0.1' || $ip === '::1' || $ip === 'localhost') {
            return true;
        }

        // Check if IP is in internal ranges
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    /**
     * Check if IP is private
     */
    protected function isPrivateIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false;
    }

    /**
     * Sanitize URL
     */
    public function sanitizeUrl(string $url): string
    {
        $parsed = parse_url($url);
        if (!$parsed) {
            return '';
        }

        // Only allow http and https
        $scheme = $parsed['scheme'] ?? 'http';
        if (!in_array($scheme, ['http', 'https'])) {
            return '';
        }

        // Rebuild URL with only safe components
        $sanitized = $scheme . '://';
        
        if (isset($parsed['host'])) {
            $sanitized .= $parsed['host'];
        }
        
        if (isset($parsed['port'])) {
            $sanitized .= ':' . $parsed['port'];
        }
        
        if (isset($parsed['path'])) {
            $sanitized .= $parsed['path'];
        }
        
        if (isset($parsed['query'])) {
            $sanitized .= '?' . $parsed['query'];
        }
        
        if (isset($parsed['fragment'])) {
            $sanitized .= '#' . $parsed['fragment'];
        }

        return $sanitized;
    }
}

