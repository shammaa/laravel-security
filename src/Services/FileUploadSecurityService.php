<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

class FileUploadSecurityService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Validate uploaded file
     */
    public function validate(UploadedFile $file): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return true;
        }

        // Check file size
        if ($file->getSize() > ($this->config['max_size'] ?? 10240) * 1024) {
            return false;
        }

        // Check extension
        $extension = strtolower($file->getClientOriginalExtension());
        $allowedExtensions = array_map('strtolower', $this->config['allowed_extensions'] ?? []);
        if (!in_array($extension, $allowedExtensions)) {
            return false;
        }

        // Check MIME type
        $mimeType = $file->getMimeType();
        $allowedMimeTypes = $this->config['allowed_mime_types'] ?? [];
        if (!in_array($mimeType, $allowedMimeTypes)) {
            return false;
        }

        // Scan file content (magic bytes)
        if (isset($this->config['scan_content']) && $this->config['scan_content']) {
            if (!$this->scanFileContent($file)) {
                return false;
            }
        }

        // Block executable files
        if (isset($this->config['block_executable']) && $this->config['block_executable']) {
            $executableExtensions = ['exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar', 'sh', 'php', 'asp', 'aspx', 'jsp'];
            if (in_array($extension, $executableExtensions)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Scan file content using magic bytes
     */
    protected function scanFileContent(UploadedFile $file): bool
    {
        $handle = fopen($file->getRealPath(), 'rb');
        if (!$handle) {
            return false;
        }

        $bytes = fread($handle, 4);
        fclose($handle);

        if (!$bytes) {
            return false;
        }

        // Check magic bytes
        $magicBytes = bin2hex($bytes);
        $extension = strtolower($file->getClientOriginalExtension());

        // Validate magic bytes match extension
        $magicBytesMap = [
            'jpg' => ['ffd8ffe0', 'ffd8ffe1', 'ffd8ffe2'],
            'png' => ['89504e47'],
            'gif' => ['47494638'],
            'pdf' => ['25504446'],
        ];

        if (isset($magicBytesMap[$extension])) {
            return in_array($magicBytes, $magicBytesMap[$extension]);
        }

        return true; // If no magic bytes check for this extension, allow it
    }

    /**
     * Generate secure filename
     */
    public function generateSecureFilename(UploadedFile $file): string
    {
        if (!isset($this->config['rename_files']) || !$this->config['rename_files']) {
            return $file->getClientOriginalName();
        }

        $extension = $file->getClientOriginalExtension();
        $filename = uniqid('file_', true) . '_' . time() . '.' . $extension;

        return $filename;
    }

    /**
     * Store file securely
     */
    public function storeSecurely(UploadedFile $file, string $path = null): string
    {
        $path = $path ?? ($this->config['secure_directory'] ?? storage_path('app/uploads'));
        
        // Ensure directory exists
        if (!is_dir($path)) {
            mkdir($path, 0755, true);
        }

        $filename = $this->generateSecureFilename($file);
        $fullPath = $path . '/' . $filename;

        $file->move($path, $filename);

        return $fullPath;
    }

    /**
     * Get file info
     */
    public function getFileInfo(UploadedFile $file): array
    {
        return [
            'original_name' => $file->getClientOriginalName(),
            'mime_type' => $file->getMimeType(),
            'size' => $file->getSize(),
            'extension' => $file->getClientOriginalExtension(),
            'is_valid' => $this->validate($file),
        ];
    }
}

