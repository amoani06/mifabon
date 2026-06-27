<?php

declare(strict_types=1);

namespace ReallySimplePlugins\RSS\Core\Features\Pro\HibpPasswordCheck;

use ReallySimplePlugins\RSS\Core\Interfaces\FeatureInterface;

class HibpPasswordCheckController implements FeatureInterface
{
    private HibpPasswordCheckService $service;

    public function __construct(HibpPasswordCheckService $service)
    {
        $this->service = $service;
    }

    public function register(): void
    {
        add_action('user_register', [$this, 'checkPasswordOnSet'], 10, 2);
        add_action('password_reset', [$this, 'checkPasswordOnSet'], 10, 2);
        add_action('profile_update', [$this, 'checkPasswordOnSet'], 10, 2);

        add_filter('registration_errors', [$this, 'checkPasswordOnRegistration'], 10, 3);
        add_action('validate_password_reset', [$this, 'checkPasswordOnReset'], 10, 2);
        add_filter('user_profile_update_errors', [$this, 'checkPasswordOnProfileUpdate'], 10, 3);
    }

    /**
     * Check password after user registration or password change.
     *
     * Hooked to three actions with different arguments:
     *
     * | Action         | Arg 1         | Arg 2            |
     * |----------------|---------------|------------------|
     * | user_register  | int $user_id  | array $userdata  |
     * | password_reset | WP_User $user | string $new_pass |
     * | profile_update | int $user_id  | WP_User          |
     *
     * Because password_reset passes WP_User instead of int, we handle both.
     *
     * @param int|\WP_User $userOrId
     * @param string|array|\WP_User $passwordOrUserData
     */
    public function checkPasswordOnSet($userOrId, $passwordOrUserData = ''): void
    {
        $userId = $userOrId instanceof \WP_User ? (int) $userOrId->ID : (int) $userOrId;

        // If we came here via password_reset, this will be a string
        if (is_string($passwordOrUserData)) {
            $this->service->checkPassword($passwordOrUserData);
            return;
        }

        // If we came here via user_register, or profile_update, we get the
        // password from the user ID
        $password = $this->service->getPasswordFromUserWithId($userId);

        if (empty($password)) {
            return;
        }

        $this->service->checkPassword($password);
    }

    /**
     * Check password on user registration form submission.
     */
    public function checkPasswordOnRegistration(\WP_Error $errors, string $sanitizedUserLogin, string $userEmail): \WP_Error
    {
        if (empty($_POST['user_pass'])) {
            return $errors;
        }

        $pwnedCount = $this->service->checkPassword($_POST['user_pass']);

        if ($pwnedCount === 0) {
            return $errors;
        }

        $errors->add(
            'rsssl_password_pwned',
            sprintf(
                __("Warning: This password has been found in %d data breaches. Please choose a different password.", "really-simple-ssl"),
                $pwnedCount
            )
        );

        return $errors;
    }

    /**
     * Check password on password reset form submission.
     */
    public function checkPasswordOnReset(\WP_Error $errors, $user): \WP_Error
    {
        if (empty($_POST['pass1'])) {
            return $errors;
        }

        $pwnedCount = $this->service->checkPassword($_POST['pass1']);

        if ($pwnedCount === 0) {
            return $errors;
        }

        $customError = sprintf(
            __("Warning: This password has been found in %d data breaches. Please choose a different password.", "really-simple-ssl"),
            $pwnedCount
        );

        $errors->add('rsssl_password_pwned', $customError);

        add_filter('login_errors', function ($error) use ($customError) {
            return $customError;
        });

        return $errors;
    }

    /**
     * Check password on profile update form submission.
     */
    public function checkPasswordOnProfileUpdate(\WP_Error $errors, bool $update, object $user): \WP_Error
    {
        if (empty($_POST['pass1'])) {
            return $errors;
        }

        $pwnedCount = $this->service->checkPassword($_POST['pass1']);

        if ($pwnedCount === 0) {
            return $errors;
        }

        $errors->add(
            'rsssl_password_pwned',
            sprintf(
                __("Warning: This password has been found in %d data breaches. Please choose a different password.", "really-simple-ssl"),
                $pwnedCount
            )
        );

        return $errors;
    }
}
