<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Validators;

use Illuminate\Http\UploadedFile;
use Shammaa\LaravelSecurity\Services\FileUploadSecurityService;
use Illuminate\Support\Facades\App;

class FileValidator
{
    protected FileUploadSecurityService $fileSecurity;

    public function __construct()
    {
        $this->fileSecurity = App::make(FileUploadSecurityService::class);
    }

    /**
     * Validate uploaded file
     */
    public function validate(UploadedFile $file): array
    {
        $valid = $this->fileSecurity->validate($file);

        if (!$valid) {
            return [
                'valid' => false,
                'errors' => ['File validation failed'],
            ];
        }

        return [
            'valid' => true,
            'errors' => [],
            'info' => $this->fileSecurity->getFileInfo($file),
        ];
    }

    /**
     * Validate file size
     */
    public function validateSize(UploadedFile $file, int $maxSize): bool
    {
        return $file->getSize() <= ($maxSize * 1024);
    }

    /**
     * Validate file extension
     */
    public function validateExtension(UploadedFile $file, array $allowedExtensions): bool
    {
        $extension = strtolower($file->getClientOriginalExtension());
        $allowed = array_map('strtolower', $allowedExtensions);
        
        return in_array($extension, $allowed);
    }

    /**
     * Validate MIME type
     */
    public function validateMimeType(UploadedFile $file, array $allowedMimeTypes): bool
    {
        $mimeType = $file->getMimeType();
        return in_array($mimeType, $allowedMimeTypes);
    }
}

