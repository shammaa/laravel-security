<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use DOMDocument;
use LibXMLError;

class XxeProtectionService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Parse XML safely
     */
    public function parseXml(string $xml): ?DOMDocument
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return $this->parseXmlUnsafe($xml);
        }

        // Disable external entity loading
        $oldValue = libxml_disable_entity_loader(
            isset($this->config['disable_entity_loader']) && $this->config['disable_entity_loader']
        );

        // Disable external entities
        if (isset($this->config['disable_external_entities']) && $this->config['disable_external_entities']) {
            libxml_set_external_entity_loader(function () {
                return null;
            });
        }

        $dom = new DOMDocument();
        $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

        // Restore old value
        libxml_disable_entity_loader($oldValue);

        return $dom;
    }

    /**
     * Parse XML without protection (for testing)
     */
    protected function parseXmlUnsafe(string $xml): ?DOMDocument
    {
        $dom = new DOMDocument();
        @$dom->loadXML($xml);
        return $dom;
    }

    /**
     * Validate XML
     */
    public function validateXml(string $xml): array
    {
        $errors = [];
        
        libxml_use_internal_errors(true);
        
        $dom = $this->parseXml($xml);
        
        $libxmlErrors = libxml_get_errors();
        libxml_clear_errors();

        foreach ($libxmlErrors as $error) {
            $errors[] = $this->formatLibXmlError($error);
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'dom' => $dom,
        ];
    }

    /**
     * Format LibXML error
     */
    protected function formatLibXmlError(LibXMLError $error): string
    {
        $level = match ($error->level) {
            LIBXML_ERR_WARNING => 'Warning',
            LIBXML_ERR_ERROR => 'Error',
            LIBXML_ERR_FATAL => 'Fatal Error',
            default => 'Unknown',
        };

        return sprintf(
            '%s: %s in line %d, column %d',
            $level,
            trim($error->message),
            $error->line,
            $error->column
        );
    }

    /**
     * Check for XXE in XML
     */
    public function detectXxe(string $xml): bool
    {
        // Check for external entity declarations
        if (preg_match('/<!ENTITY\s+[^>]*SYSTEM\s+[^>]*>/i', $xml)) {
            return true;
        }

        // Check for external DTD references
        if (preg_match('/<!DOCTYPE\s+[^>]*SYSTEM\s+[^>]*>/i', $xml)) {
            return true;
        }

        return false;
    }
}

