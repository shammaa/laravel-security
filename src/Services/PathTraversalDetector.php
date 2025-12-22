<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;
use Illuminate\Support\Facades\Event;

class PathTraversalDetector
{
    protected array $config;
    protected array $patterns;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->patterns = $config['patterns'] ?? [];
    }

    /**
     * Detect path traversal
     */
    public function detect(string $path): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return false;
        }

        if (!isset($this->config['detect_patterns']) || !$this->config['detect_patterns']) {
            return false;
        }

        foreach ($this->patterns as $pattern) {
            if (preg_match($pattern, $path)) {
                if (isset($this->config['log_attempts']) && $this->config['log_attempts']) {
                    Event::dispatch(new SecurityThreatDetected('path_traversal', $path, $pattern));
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Sanitize path
     */
    public function sanitize(string $path, string $baseDirectory = null): string
    {
        // Remove path traversal sequences
        $sanitized = str_replace(['../', '..\\', '..%2F', '..%5C'], '', $path);
        
        // Remove null bytes
        $sanitized = str_replace("\0", '', $sanitized);

        // Normalize path
        $sanitized = str_replace('\\', '/', $sanitized);
        $sanitized = preg_replace('/\/+/', '/', $sanitized);
        $sanitized = trim($sanitized, '/');

        // If base directory is provided, ensure path is within it
        if ($baseDirectory) {
            $realPath = realpath($baseDirectory . '/' . $sanitized);
            $realBase = realpath($baseDirectory);
            
            if ($realPath && $realBase && strpos($realPath, $realBase) !== 0) {
                return '';
            }
        }

        return $sanitized;
    }

    /**
     * Validate path is within base directory
     */
    public function validatePath(string $path, string $baseDirectory): bool
    {
        $realPath = realpath($baseDirectory . '/' . $path);
        $realBase = realpath($baseDirectory);

        if (!$realPath || !$realBase) {
            return false;
        }

        return strpos($realPath, $realBase) === 0;
    }

    /**
     * Get safe path
     */
    public function getSafePath(string $path, string $baseDirectory): string
    {
        $sanitized = $this->sanitize($path, $baseDirectory);
        
        if (empty($sanitized)) {
            return $baseDirectory;
        }

        return $baseDirectory . '/' . $sanitized;
    }
}

