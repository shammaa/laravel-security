<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Detectors;

use Illuminate\Http\Request;

class AttackPatternDetector
{
    /**
     * Detect attack patterns
     */
    public function detect(Request $request): array
    {
        $patterns = [];

        // Check for directory traversal attempts
        if ($this->detectDirectoryTraversal($request)) {
            $patterns[] = 'directory_traversal';
        }

        // Check for file inclusion attempts
        if ($this->detectFileInclusion($request)) {
            $patterns[] = 'file_inclusion';
        }

        // Check for code injection attempts
        if ($this->detectCodeInjection($request)) {
            $patterns[] = 'code_injection';
        }

        // Check for header injection attempts
        if ($this->detectHeaderInjection($request)) {
            $patterns[] = 'header_injection';
        }

        return [
            'patterns' => $patterns,
            'count' => count($patterns),
        ];
    }

    /**
     * Detect directory traversal
     */
    protected function detectDirectoryTraversal(Request $request): bool
    {
        $data = json_encode($request->all());
        return preg_match('/\.\.\//', $data) || preg_match('/\.\.\\\\/', $data);
    }

    /**
     * Detect file inclusion
     */
    protected function detectFileInclusion(Request $request): bool
    {
        $data = json_encode($request->all());
        $patterns = [
            '/include\s*\(/i',
            '/require\s*\(/i',
            '/include_once\s*\(/i',
            '/require_once\s*\(/i',
            '/file_get_contents\s*\(/i',
            '/readfile\s*\(/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $data)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect code injection
     */
    protected function detectCodeInjection(Request $request): bool
    {
        $data = json_encode($request->all());
        $patterns = [
            '/eval\s*\(/i',
            '/assert\s*\(/i',
            '/preg_replace\s*\(.*\/e/i',
            '/create_function\s*\(/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $data)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect header injection
     */
    protected function detectHeaderInjection(Request $request): bool
    {
        $data = json_encode($request->all());
        
        // Check for newline characters that could be used for header injection
        return preg_match('/[\r\n]/', $data);
    }
}

