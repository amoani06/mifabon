<?php
namespace RSSSL\Pro\Security\WordPress\Passkey;

/**
 * File: class-rsssl-passkey-user-admin.php
 *
 * Provides a passkey-only reset workflow for WordPress users when 2FA is disabled.
 * This handler overrides default 2FA reset behavior, focusing on cleaning up and
 * resetting passkey configurations. It also ensures any lingering 2FA artifacts
 * (recovery codes, session tokens, status flags) are cleared, guaranteeing a
 * fully clean slate for future authentication flows.
 *
 * @package RSSSL\Pro\Security\WordPress\Passkey
 */

use RSSSL\Security\WordPress\Two_Fa\Controllers\Rsssl_Two_Fa_User_Controller;
use RSSSL\Security\WordPress\Two_Fa\Models\Rsssl_Two_FA_Data_Parameters;
use RSSSL\Security\WordPress\Two_Fa\Repositories\Rsssl_Two_Fa_User_Repository;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Fa_Status;


/**
 * Class RSSSL_Passkey_User_Admin
 *
 * Handles administrative passkey resets for users. When 2FA is disabled,
 * this class bypasses standard 2FA reset checks and focuses on:
 *   1. Deleting all existing passkey configurations.
 *   2. Resetting underlying 2FA metadata to enforce fresh authentication.
 *
 * @package RSSSL\Pro\Security\WordPress\Passkey
 */
class RSSSL_Passkey_User_Admin {
	/**
	 * Get the single instance of this class.
	 *
	 * @return RSSSL_Passkey_User_Admin
	 */
	private static $instance;

	public function __construct() {
		// if the user is not logged in, it don't need to do anything.
		if (!rsssl_admin_logged_in()) {
			return;
		}
		if (isset(self::$instance)) {
			wp_die();
		}
		self::$instance = $this;
		add_filter('rsssl_do_action', [$this, 'two_fa_table'], 10, 3);
	}

	/**
	 * Generates the two-factor authentication table data based on the action and data parameters.
	 *
	 * @param array $response The initial response data.
	 * @param string $action The action to perform.
	 * @param array $data The data needed for the action.
	 *
	 * @return array The updated response data.
	 */
	public function two_fa_table(array $response, string $action, array $data): array
	{
		$new_response = $response;
		if (rsssl_user_can_manage()) {
			switch ($action) {
				case 'two_fa_table':
					$data_parameters = new Rsssl_Two_FA_Data_Parameters($data);
					$userRepository = new Rsssl_Two_Fa_User_Repository();
					// Create the controller.
					return (new Rsssl_Two_Fa_User_Controller($userRepository))->getUsersForAdminOverview($data_parameters);
				case 'two_fa_reset_user':
					// if the user has been disabled, it needs to reset the two-factor authentication.
					$user = get_user_by('id', $data['id']);

					if ($user) {
						// Assuming the user is an instance of WP_User and only passkey is enabled.
						// Delete the passkey configuration for the user.
						delete_user_meta($user->ID, 'rsssl_passkey_configured');
						// Reset the two-factor authentication status for the user.
						// Delete all 2fa related user meta.
						Rsssl_Two_Fa_Status::delete_two_fa_meta($user->ID);
						// Set the rsssl_two_fa_last_login to now, so the user will be forced to use 2fa.
						update_user_meta($user->ID, 'rsssl_two_fa_last_login', gmdate('Y-m-d H:i:s'));
					}
					if (!$user) {
						$new_response['request_success'] = false;
					}
					break;

				default:
					// Default case if no action matches.
					break;
			}
		}
		return $new_response;
	}
}