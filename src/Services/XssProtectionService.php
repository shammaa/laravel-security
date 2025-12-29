<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Shammaa\LaravelSecurity\Events\XssAttempt;
use Illuminate\Support\Facades\Event;

class XssProtectionService
{
    protected array $config;
    protected array $patterns;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->patterns = $config['patterns'] ?? [];
    }

    /**
     * Filter XSS from input
     */
    public function filter(string $input): string
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return $input;
        }

        if (!isset($this->config['filter_input']) || !$this->config['filter_input']) {
            return $input;
        }

        $filtered = $input;

        // Remove dangerous patterns
        foreach ($this->patterns as $pattern) {
            if (preg_match($pattern, $filtered)) {
                if (isset($this->config['log_attempts']) && $this->config['log_attempts']) {
                    Event::dispatch(new XssAttempt($input, $pattern));
                }
                $filtered = preg_replace($pattern, '', $filtered);
            }
        }

        // Remove script tags and content
        $filtered = preg_replace('/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi', '', $filtered);

        // Remove event handlers
        $filtered = preg_replace('/\bon\w+\s*=\s*["\']?[^"\'>]*["\']?/i', '', $filtered);

        // Remove javascript: protocol
        $filtered = preg_replace('/javascript:/i', '', $filtered);

        // Remove data: URLs that might contain scripts
        $filtered = preg_replace('/data:text\/html/i', '', $filtered);

        // HTML entity encode
        $filtered = htmlspecialchars($filtered, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return $filtered;
    }

    /**
     * Filter XSS from output (for display)
     */
    public function filterOutput(string $output): string
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return $output;
        }

        if (!isset($this->config['filter_output']) || !$this->config['filter_output']) {
            return $output;
        }

        return $this->filter($output);
    }

    /**
     * Clean HTML while allowing safe tags
     */
    public function cleanHtml(string $html, array $allowedTags = []): string
    {
        if (empty($allowedTags)) {
            $allowedTags = ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
        }

        // Remove all tags except allowed
        $html = strip_tags($html, '<' . implode('><', $allowedTags) . '>');

        // Remove attributes from allowed tags (except href for links)
        $html = preg_replace_callback('/<(\w+)([^>]*)>/i', function ($matches) use ($allowedTags) {
            $tag = strtolower($matches[1]);
            if (in_array($tag, $allowedTags)) {
                if ($tag === 'a') {
                    // Allow href attribute for links
                    if (preg_match('/href\s*=\s*["\']([^"\']*)["\']/i', $matches[2], $hrefMatch)) {
                        $href = $hrefMatch[1];
                        // Validate URL
                        if (filter_var($href, FILTER_VALIDATE_URL) || strpos($href, '/') === 0) {
                            return '<a href="' . htmlspecialchars($href, ENT_QUOTES) . '">';
                        }
                    }
                }
                return '<' . $tag . '>';
            }
            return '';
        }, $html);

        return $html;
    }

    /**
     * Get Content Security Policy header
     */
    public function getCspHeader(): ?string
    {
        if (!isset($this->config['csp_enabled']) || !$this->config['csp_enabled']) {
            return null;
        }

        return config('security.headers.csp');
    }

    /**
     * Get XSS patterns
     */
    public function getPatterns(): array
    {
        return $this->patterns;
    }
}

