<?php

declare(strict_types=1);

namespace ReallySimplePlugins\RSS\Core\Features\Pro\HibpPasswordCheck;

/**
 * Service class for HIBP (Have I Been Pwned) password checking.
 * Handles the API communication and password validation logic.
 */
class HibpPasswordCheckService
{
    private const HIBP_API_URL = 'https://api.pwnedpasswords.com/range/';

    /**
     * Check if a password has been pwned using the Have I Been Pwned API.
     *
     * Uses k-anonymity to securely check passwords without sending the full
     * password or hash to the API. Only the first 5 characters of the SHA1
     * hash are sent. The API returns all known breached hash suffixes matching
     * that prefix, and we check locally if our full hash suffix is in that list.
     *
     * @see https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
     */
    public function checkPassword($password): int
    {
        $hash = $this->extractPasswordHash($password);

        if ($hash === '') {
            return 0;
        }

        $hashSuffix = substr($hash, 5);
        $responseBody = $this->fetchPwnedPasswordsRange($hash);

        if ($responseBody === '') {
            return 0;
        }

        return $this->findHashInResponse($responseBody, $hashSuffix);
    }

    /**
     * Fetch the HIBP API response for a hash prefix.
     *
     * Sends only the first 5 characters of the hash to the API (k-anonymity).
     * The API returns all breached password hash suffixes that start with
     * this prefix, allowing us to check locally without exposing the password.
     */
    private function fetchPwnedPasswordsRange(string $hash): string
    {
        $hashPrefix = substr($hash, 0, 5);
        $url = self::HIBP_API_URL . $hashPrefix;
        $response = wp_remote_get($url);

        if (is_wp_error($response)) {
            return '';
        }

        return wp_remote_retrieve_body($response);
    }

    /**
     * Find a hash suffix in the HIBP API response and return the pwned count.
     *
     * The API response contains lines in format "HASH_SUFFIX:COUNT", e.g.:
     * "0018A45C4D1DEF81644B54AB7F969B88D65:21" means this password hash was
     * found 21 times in breached password databases. We compare our hash
     * suffix against each line to find a match.
     */
    private function findHashInResponse(string $responseBody, string $hashSuffix): int
    {
        $lines = explode("\n", $responseBody);

        foreach ($lines as $line) {
            $parts = explode(':', $line);

            if (count($parts) !== 2) {
                continue;
            }

            $suffix = $parts[0];
            $count = $parts[1];

            if (strcasecmp($suffix, $hashSuffix) !== 0) {
                continue;
            }

            return (int) trim($count);
        }

        return 0;
    }

    /**
     * Get password from user by ID.
     */
    public function getPasswordFromUserWithId(int $userId): string
    {
        $user = get_user_by('ID', $userId);

        if (!$user) {
            return '';
        }

        if (empty($user->user_pass)) {
            return '';
        }

        return $user->user_pass;
    }

    /**
     * Extract password and generate SHA1 hash from various input types.
     *
     * WordPress hooks like profile_update pass different data types depending
     * on context. Third-party plugins (e.g., Thrive Architect) may incorrectly
     * pass unexpected types like stdClass. This method normalizes all input
     * types to extract the password string safely, returning an empty string
     * for unsupported types to prevent fatal errors.
     *
     * @param mixed $userData Data from WordPress hooks (WP_User, array, string, or unexpected types)
     * @return string The uppercase SHA1 hash, or empty string if extraction fails
     */
    private function extractPasswordHash($userData): string
    {
        // Plain password string from form input
        if (is_string($userData)) {
            return strtoupper(sha1($userData));
        }

        // WordPress sometimes passes user data as array
        if (is_array($userData) && isset($userData['user_pass'])) {
            return strtoupper(sha1($userData['user_pass']));
        }

        // WordPress sometimes passes WP_User object
        if (!$userData instanceof \WP_User) {
            return '';
        }

        if (!isset($userData->data->user_pass)) {
            return '';
        }

        return strtoupper(sha1($userData->data->user_pass));
    }
}
