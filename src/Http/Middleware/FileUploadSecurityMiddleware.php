<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Shammaa\LaravelSecurity\Services\FileUploadSecurityService;

class FileUploadSecurityMiddleware
{
    protected FileUploadSecurityService $fileSecurity;

    public function __construct(FileUploadSecurityService $fileSecurity)
    {
        $this->fileSecurity = $fileSecurity;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Validate uploaded files
        foreach ($request->allFiles() as $file) {
            if (is_array($file)) {
                foreach ($file as $f) {
                    if (!$this->fileSecurity->validate($f)) {
                        return response()->json([
                            'error' => 'Invalid file',
                            'message' => 'The uploaded file is not allowed.',
                        ], 400);
                    }
                }
            } else {
                if (!$this->fileSecurity->validate($file)) {
                    return response()->json([
                        'error' => 'Invalid file',
                        'message' => 'The uploaded file is not allowed.',
                    ], 400);
                }
            }
        }

        return $next($request);
    }
}

