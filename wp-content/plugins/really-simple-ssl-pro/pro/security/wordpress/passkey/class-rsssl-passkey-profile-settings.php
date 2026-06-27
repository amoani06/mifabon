<?php
/**
 * Registers the passkey profile-settings hooks.
 *
 * @package ReallySimpleSSL\Pro\Security\WordPress\Passkey
 */

namespace RSSSL\Pro\Security\WordPress\Passkey;

use RSSSL\Pro\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Passkey;
use RSSSL\Pro\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Totp;
use RSSSL\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Email;
use RSSSL\Security\WordPress\Two_Fa\RSSSL_Passkey_List_Table;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Fa_Authentication;

/**
 * Hook registrar for user-profile passkey settings.
 *
 * Only responsibility: wire WP actions to dedicated handler classes.
 */
class Rsssl_Passkey_Profile_Settings {
    /**
     * Register all WordPress hooks for passkey profile settings.
     *
     * - Displays the Passkey settings section on user profile screens.
     * - Enqueues necessary scripts and styles in the admin.
     * - Saves Passkey configuration when the user profile is updated.
     *
     * @return void
     */
	public static function init(): void {
		// 2FA already renders the passkey table when login_protection_enabled is true.
		// only render here when passkey is enabled and 2FA is not.
		if ( (bool) rsssl_get_option( 'login_protection_enabled' ) ||
             ! (bool) rsssl_get_option( 'enable_passkey_login' )
        ) {
			return;
		}
		// Show Passkey section on profile
		add_action( 'show_user_profile', [ __CLASS__, 'render_settings' ] );
		add_action( 'edit_user_profile', [ __CLASS__, 'render_settings' ] );

		// Save Passkey setting
		add_action( 'personal_options_update', [ __CLASS__, 'save_settings' ] );
		add_action( 'edit_user_profile_update', [ __CLASS__, 'save_settings' ] );

		add_action( 'admin_enqueue_scripts',[ __CLASS__, 'enqueue_scripts' ], 10, 1 );
		add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue_styles' ], 10, 1 );
	}

	public static function render_settings( \WP_User $user ): void {
		// Only show passkey settings on the current user's own profile.
		if ( get_current_user_id() !== (int) $user->ID ) {
			return;
		}
		wp_nonce_field( 'rsssl_passkey_profile', 'rsssl_passkey_profile_nonce' );
		$enabled = get_user_meta( $user->ID, 'rsssl_passkey_configured', true );
		?>
        <h2><?php esc_html_e( 'Passkey Login', 'really-simple-ssl' ); ?></h2>
        <table class="form-table">
            <tr>
                <th>
                    <label for="rsssl_passkey_enabled">
						<?php esc_html_e( 'Enable Passkey login', 'really-simple-ssl' ); ?>
                    </label>
                </th>
                <td>
                    <input
                            type="checkbox"
                            name="rsssl_passkey_configured"
                            id="rsssl_passkey_configured"
                            value="configured"
						<?php checked( $enabled, 'configured' ); ?>
                    />
                </td>
            <tr id="rsssl_step_three_onboarding">
                <td colspan="2">
                    <p class="passkey-integration" id="passkey-integration">
                    </p>
                </td>
            </tr>
				<?php

				if ( rsssl_get_option( 'enable_passkey_login', false ) ) {
				?>
            <tr style="padding: 0;" id="passkey-table">
                <!-- Datatable for the Passkey -->
                <td colspan="2" style="padding: 0;">
					<?php RSSSL_Passkey_List_Table::display_table() ?>
                </td>
            </tr>
			<?php
			}
			?>
            </tr>
        </table>
		<?php
	}

	/**
	 * Enqueues the RSSSL profile settings script.
	 *
	 * @param string $hook
	 * @return void
	 */
	public static function enqueue_scripts( string $hook ): void {
		if ( ! in_array( $hook, [ 'profile.php', 'user-edit.php' ], true ) ) {
			return;
		}
		// When on user-edit.php and editing someone else's profile, do not enqueue.
		if ( 'user-edit.php' === $hook ) {
			$edited_user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( $edited_user_id && $edited_user_id !== get_current_user_id() ) {
				return;
			}
		}
		$path      = trailingslashit( rsssl_url ) . 'assets/features/two-fa/assets.min.js';
		$file_path = trailingslashit( rsssl_path ) . 'assets/features/two-fa/assets.min.js';
		$user      = get_user_by( 'ID', get_current_user_id() );
        // We get the transalatables from the two-fa passkey class.
        add_filter( 'rsssl_two_factor_translatables', [ Rsssl_Two_Factor_Passkey::class, 'translatables' ] );
		// We check if the backup codes are available.
		wp_register_script( 'rsssl-profile-settings', $path, [], filemtime( $file_path ), true );
		wp_enqueue_script( 'rsssl-profile-settings' );
		wp_localize_script( 'rsssl-profile-settings', 'rsssl_profile', [
			'ajax_url'      => admin_url( 'admin-ajax.php' ),
			'nonce'         => wp_create_nonce( 'wp_rest' ),
			'root'          => esc_url_raw( rest_url( Rsssl_Passkey::REST_NAMESPACE ) ),
			'user_id'       => get_current_user_id(),
			'origin'        => 'profile',
			'redirect_to'   => 'rsssl_no_redirect', //added this for comparison in the json output.
			'login_nonce'   => Rsssl_Two_Fa_Authentication::create_login_nonce( get_current_user_id() )['rsssl_key'],
			'user_name'     => $user->display_name,
			'display_name'  => $user->user_nicename . ' (' . $user->user_email . ')',
			'translatables' => apply_filters( 'rsssl_two_factor_translatables', [] ),
		] );
	}

	/**
	 * Enqueues the RSSSL profile settings stylesheet.
	 *
	 * @param string $hook
	 * @return void
	 */
	public static function enqueue_styles( string $hook ): void {
		if ( ! in_array( $hook, [ 'profile.php', 'user-edit.php' ], true ) ) {
			return;
		}
		// When on user-edit.php and editing someone else's profile, do not enqueue.
		if ( 'user-edit.php' === $hook ) {
			$edited_user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( $edited_user_id && $edited_user_id !== get_current_user_id() ) {
				return;
			}
		}
		$path      = trailingslashit( rsssl_url ) . 'assets/features/two-fa/styles.min.css';
		$file_path = trailingslashit( rsssl_path ) . 'assets/features/two-fa/styles.min.css';
		wp_enqueue_style( 'rsssl-profile-style', $path, [], filemtime( $file_path ) );
	}

	public static function save_settings(): void {
		if ( ! current_user_can( 'edit_user', get_current_user_id() ) ) {
			return;
		}
		if (
			empty( $_POST['rsssl_passkey_profile_nonce'] ) ||
			! wp_verify_nonce( wp_unslash( $_POST['rsssl_passkey_profile_nonce'] ), 'rsssl_passkey_profile' )
		) {
			return;
		}
		$value = isset( $_POST['rsssl_passkey_configured'] ) ? '1' : '0';
        if ( ! (bool) $value ) {
            // If the user disables passkey login, we also remove all their registered passkeys.
            Rsssl_Two_Factor_Passkey::set_user_status( get_current_user_id(), 'disabled' );
            Rsssl_Two_Factor_Totp::set_user_status( get_current_user_id(), 'disabled' );
            Rsssl_Two_Factor_Email::set_user_status( get_current_user_id(), 'disabled' );
        }
	}
}
