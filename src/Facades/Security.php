<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Facades;

use Illuminate\Support\Facades\Facade;
use Shammaa\LaravelSecurity\Services\SecurityService;

/**
 * @method static mixed sanitize($input)
 * @method static bool detectSqlInjection(string $query)
 * @method static string xssFilter(string $html)
 * @method static bool rateLimit(string $key, int $maxAttempts = null, int $decayMinutes = null)
 * @method static bool validateFile($file)
 * @method static string storeFile($file, string $path = null)
 * @method static array checkPassword(string $password)
 * @method static bool isLocked(string $identifier)
 * @method static void recordFailedLogin(string $identifier)
 * @method static void clearFailedLogins(string $identifier)
 * @method static \Shammaa\LaravelSecurity\Services\InputSanitizerService getInputSanitizer()
 * @method static \Shammaa\LaravelSecurity\Services\SqlInjectionDetector getSqlInjectionDetector()
 * @method static \Shammaa\LaravelSecurity\Services\XssProtectionService getXssProtection()
 * @method static \Shammaa\LaravelSecurity\Services\CsrfProtectionService getCsrfProtection()
 * @method static \Shammaa\LaravelSecurity\Services\FileUploadSecurityService getFileUploadSecurity()
 * @method static \Shammaa\LaravelSecurity\Services\RateLimitingService getRateLimiting()
 * @method static \Shammaa\LaravelSecurity\Services\SecurityHeadersService getSecurityHeaders()
 * @method static \Shammaa\LaravelSecurity\Services\AuthenticationSecurityService getAuthenticationSecurity()
 * @method static \Shammaa\LaravelSecurity\Services\AuthorizationSecurityService getAuthorizationSecurity()
 * @method static \Shammaa\LaravelSecurity\Services\CommandInjectionDetector getCommandInjectionDetector()
 * @method static \Shammaa\LaravelSecurity\Services\PathTraversalDetector getPathTraversalDetector()
 * @method static \Shammaa\LaravelSecurity\Services\XxeProtectionService getXxeProtection()
 * @method static \Shammaa\LaravelSecurity\Services\SsrfProtectionService getSsrfProtection()
 * @method static \Shammaa\LaravelSecurity\Services\IdorProtectionService getIdorProtection()
 * @method static \Shammaa\LaravelSecurity\Services\SecurityMonitoringService getMonitoring()
 * @method static \Shammaa\LaravelSecurity\Services\SecurityReportService getReportService()
 *
 * @see \Shammaa\LaravelSecurity\Services\SecurityService
 */
class Security extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'security';
    }
}

