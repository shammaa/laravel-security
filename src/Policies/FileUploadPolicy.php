<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Policies;

use Illuminate\Foundation\Auth\User;
use Illuminate\Http\UploadedFile;

class FileUploadPolicy
{
    /**
     * Determine if user can upload files
     */
    public function upload(User $user): bool
    {
        // Add your authorization logic here
        return true;
    }

    /**
     * Determine if user can upload specific file type
     */
    public function uploadFileType(User $user, string $mimeType): bool
    {
        // Add your authorization logic here
        return true;
    }

    /**
     * Determine if user can upload file of specific size
     */
    public function uploadFileSize(User $user, int $size): bool
    {
        // Add your authorization logic here
        return true;
    }
}

