<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Validators;

use Illuminate\Validation\Validator;

class InputValidator
{
    /**
     * Validate input data
     */
    public function validate(array $data, array $rules): array
    {
        $validator = \Validator::make($data, $rules);

        if ($validator->fails()) {
            return [
                'valid' => false,
                'errors' => $validator->errors()->all(),
            ];
        }

        return [
            'valid' => true,
            'errors' => [],
        ];
    }

    /**
     * Validate required fields
     */
    public function validateRequired(array $data, array $required): array
    {
        $missing = [];

        foreach ($required as $field) {
            if (!isset($data[$field]) || empty($data[$field])) {
                $missing[] = $field;
            }
        }

        return [
            'valid' => empty($missing),
            'missing' => $missing,
        ];
    }

    /**
     * Validate data types
     */
    public function validateTypes(array $data, array $typeRules): array
    {
        $errors = [];

        foreach ($typeRules as $field => $type) {
            if (!isset($data[$field])) {
                continue;
            }

            $value = $data[$field];
            $valid = match ($type) {
                'string' => is_string($value),
                'integer' => is_int($value),
                'float' => is_float($value),
                'boolean' => is_bool($value),
                'array' => is_array($value),
                'email' => filter_var($value, FILTER_VALIDATE_EMAIL) !== false,
                'url' => filter_var($value, FILTER_VALIDATE_URL) !== false,
                default => true,
            };

            if (!$valid) {
                $errors[] = "Field '{$field}' must be of type '{$type}'";
            }
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
        ];
    }
}

