<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

class SecurityService
{
    public function __construct(
        protected InputSanitizerService $inputSanitizer,
        protected SqlInjectionDetector $sqlInjectionDetector,
        protected XssProtectionService $xssProtection,
        protected CsrfProtectionService $csrfProtection,
        protected FileUploadSecurityService $fileUploadSecurity,
        protected RateLimitingService $rateLimiting,
        protected SecurityHeadersService $securityHeaders,
        protected AuthenticationSecurityService $authenticationSecurity,
        protected AuthorizationSecurityService $authorizationSecurity,
        protected CommandInjectionDetector $commandInjectionDetector,
        protected PathTraversalDetector $pathTraversalDetector,
        protected XxeProtectionService $xxeProtection,
        protected SsrfProtectionService $ssrfProtection,
        protected IdorProtectionService $idorProtection,
        protected SecurityMonitoringService $monitoring,
        protected SecurityReportService $reportService,
        protected array $config
    ) {
    }

    public function sanitize($input)
    {
        return $this->inputSanitizer->sanitize($input);
    }

    public function detectSqlInjection(string $query): bool
    {
        return $this->sqlInjectionDetector->detect($query);
    }

    public function xssFilter(string $html): string
    {
        return $this->xssProtection->filter($html);
    }

    public function rateLimit(string $key, int $maxAttempts = null, int $decayMinutes = null): bool
    {
        return $this->rateLimiting->attempt($key, $maxAttempts, $decayMinutes);
    }

    /**
     * Validate uploaded file (simplified)
     */
    public function validateFile($file): bool
    {
        return $this->fileUploadSecurity->validate($file);
    }

    /**
     * Store file securely (simplified)
     */
    public function storeFile($file, string $path = null): string
    {
        return $this->fileUploadSecurity->storeSecurely($file, $path);
    }

    /**
     * Check password strength (simplified)
     */
    public function checkPassword(string $password): array
    {
        return $this->authenticationSecurity->validatePasswordStrength($password);
    }

    /**
     * Check if account is locked (simplified)
     */
    public function isLocked(string $identifier): bool
    {
        return $this->authenticationSecurity->isLocked($identifier);
    }

    /**
     * Record failed login attempt (simplified)
     */
    public function recordFailedLogin(string $identifier): void
    {
        $this->authenticationSecurity->recordFailedAttempt($identifier);
    }

    /**
     * Clear failed login attempts (simplified)
     */
    public function clearFailedLogins(string $identifier): void
    {
        $this->authenticationSecurity->clearFailedAttempts($identifier);
    }

    public function getInputSanitizer(): InputSanitizerService
    {
        return $this->inputSanitizer;
    }

    public function getSqlInjectionDetector(): SqlInjectionDetector
    {
        return $this->sqlInjectionDetector;
    }

    public function getXssProtection(): XssProtectionService
    {
        return $this->xssProtection;
    }

    public function getCsrfProtection(): CsrfProtectionService
    {
        return $this->csrfProtection;
    }

    public function getFileUploadSecurity(): FileUploadSecurityService
    {
        return $this->fileUploadSecurity;
    }

    public function getRateLimiting(): RateLimitingService
    {
        return $this->rateLimiting;
    }

    public function getSecurityHeaders(): SecurityHeadersService
    {
        return $this->securityHeaders;
    }

    public function getAuthenticationSecurity(): AuthenticationSecurityService
    {
        return $this->authenticationSecurity;
    }

    public function getAuthorizationSecurity(): AuthorizationSecurityService
    {
        return $this->authorizationSecurity;
    }

    public function getCommandInjectionDetector(): CommandInjectionDetector
    {
        return $this->commandInjectionDetector;
    }

    public function getPathTraversalDetector(): PathTraversalDetector
    {
        return $this->pathTraversalDetector;
    }

    public function getXxeProtection(): XxeProtectionService
    {
        return $this->xxeProtection;
    }

    public function getSsrfProtection(): SsrfProtectionService
    {
        return $this->ssrfProtection;
    }

    public function getIdorProtection(): IdorProtectionService
    {
        return $this->idorProtection;
    }

    public function getMonitoring(): SecurityMonitoringService
    {
        return $this->monitoring;
    }

    public function getReportService(): SecurityReportService
    {
        return $this->reportService;
    }
}

