<?php

namespace RSSSL\Pro\Security\WordPress\Two_Fa\Providers;

require_once rsssl_path . 'mailer/class-mail.php';

use Exception;
use RSSSL\Pro\Security\WordPress\Passkey\Rsssl_Public_Credential_Resource;
use RSSSL\Pro\Security\WordPress\Two_Fa\Controllers\Rsssl_WebAuthn_Controller;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Factor;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Factor_On_Board_Api;
use RSSSL\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Provider;
use RSSSL\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Provider_Interface;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Factor_Settings;
use WP_User;

/**
 * Class Rsssl_Two_Factor_Passkey
 *
 * This class represents the Passkey two-factor authentication provider.
 *
 * @package Your_Namespace
 */
class Rsssl_Two_Factor_Passkey extends Rsssl_Two_Factor_Provider implements Rsssl_Two_Factor_Provider_Interface {

    public const METHOD = 'passkey';
    public const NAME = 'Passkey';
    const SECRET_META_KEY = 'rsssl_two_fa_passkey_secret';

    /**
     * Ensures only one instance of this class exists in memory at any one time.
     *
     * @since 0.1-dev
     */
    public static function get_instance() {
        static $instance;
        $class = __CLASS__;
        if ( ! is_a( $instance, $class ) ) {
            $instance = new $class();
        }
	    add_filter( 'rsssl_two_factor_translatables', array( self::class, 'translatables' ) );
        return $instance;
    }

    /**
     * Class constructor.
     *
     * @since 0.1-dev
     */
    protected function __construct() {
        add_action( 'rsssl_two_factor_user_options_' . __CLASS__, array( $this, 'user_options' ) );
//          $this->enqueue_scripts();
        parent::__construct();

    }

    /**
     * Returns translatable strings for the provider. Also checks the correct timing of the translations.
     *
     */
    public static function translatables(array $translatables): array
    {
        $new_translatables = [
	        'log_in_with_passkey' => __('Log in with Passkey', 'really-simple-ssl'),
    		'webauthn_not_available' => __('WebAuthn is not available on this browser or device.', 'really-simple-ssl'),
			'unknown_error' => __('An unknown error occurred.', 'really-simple-ssl'),
			'response_error' => __('Error in response from server.', 'really-simple-ssl'),
			'passkey_not_found' => __('Passkey not found. Please try again.', 'really-simple-ssl'),
			'username_required' => __('Please enter your username to log in with a passkey.', 'really-simple-ssl'),
			'passkey_login_error' => __('An error occurred during passkey login.', 'really-simple-ssl'),
			'passkey_registration_error' => __('An error occurred during passkey registration.', 'really-simple-ssl'),
			'passkey_login_success' => __('Passkey login successful.', 'really-simple-ssl'),
			'passkey_configuration' => __('Passkey Configuration', 'really-simple-ssl'),
			'error_assertion' => __('Error during assertion.', 'really-simple-ssl'),
			'notice_inform'=> __('Click the button below to register your passkey. You will be asked to verify your identity with your device.', 'really-simple-ssl'),
			'register_passkey' => __('Register Passkey', 'really-simple-ssl'),
			'network_not_ok' => __('Network response was not ok.', 'really-simple-ssl'),
			'error_complete_registration' => __('Could not complete registration.', 'really-simple-ssl'),
			'usb' => __('USB Security Key', 'really-simple-ssl'),
			'nfc' => __('NFC Device', 'really-simple-ssl'),
			'ble' => __('Bluetooth Device', 'really-simple-ssl'),
			'internal' => __('Built-in Authenticator', 'really-simple-ssl'),
			'cross_platform' => __('Cross-platform Authenticator', 'really-simple-ssl'),
			'unknown' => __('Unknown Device', 'really-simple-ssl'),
			'pending' => __('Pending...', 'really-simple-ssl'),
			'success' => __('Success!', 'really-simple-ssl'),
			'failed' => __('Failed!', 'really-simple-ssl'),
			'login' => __('Logging in...', 'really-simple-ssl'),
			'login_failed' => __('Login failed. Please try again.', 'really-simple-ssl'),
            'or' => __('Or', 'really-simple-ssl'),
			'no_passkey_found' => __('No passkey was found and the user needs to login.', 'really-simple-ssl'),
			'register_your_passkey' => __('Register your Passkey', 'really-simple-ssl'),
        ];
        return array_merge($new_translatables, $translatables);
    }

	/**
	 * Starts the TOTP controller.
	 *
	 * @param string $namespace The namespace for the controller.
	 * @param string $version The version for the controller.
	 */
    public static function start_controller(string $namespace, string $version, $featureVersion):void
    {
        new Rsssl_WebAuthn_Controller($namespace, $version, $featureVersion);
    }

    public function get_label(): ?string {
        return _x('Passkey', 'Provider label', 'really-simple-ssl');
    }

    /**
     * Generates the authentication page for a given user.
     *
     * @param WP_User $user The user for whom the authentication page is being generated.
     * The user object must be an instance of WP_User.
     * @return void
     *
     * This method includes the template file for the authentication page and
     * generates the necessary HTML code for the page. It also adds a hidden input field
     * with the value of the user's username and a button for passkey validation.
     *
     */
    public function authentication_page(WP_User $user): void
    {
        require_once ABSPATH . '/wp-admin/includes/template.php';
		$passkey_login_enabled = (bool) rsssl_get_option( 'enable_passkey_login', false );
		$passkey_login_block_reason = $passkey_login_enabled
			? \rsssl_get_passkey_login_enable_block_reason()
			: '';
		$is_passkey_login_available = $passkey_login_enabled && $passkey_login_block_reason === '';
        ?>
        <p class="validation_button_holder"><input type="hidden" name="user_login" id="user_login" class="input" value="<?php echo esc_attr( $user->user_login ); ?>" size="20" />
           <!-- Passkey Button login -->
            <button
                    id="rsssl-passkey-button"
                    class="button button-primary"
                    data-autorun="<?php echo esc_attr( $is_passkey_login_available ? 'enabled' : 'disabled' ); ?>"
				<?php disabled( ! $is_passkey_login_available ); ?>
				<?php if ( ! $is_passkey_login_available ) : ?>
                    title="<?php echo esc_attr( $passkey_login_block_reason ); ?>"
				<?php endif; ?>
            ><?php esc_html_e('Validate Using Passkey', 'really-simple-ssl'); ?></button>
        </p>
		<?php if ( ! $is_passkey_login_available ) : ?>
            <p id="rsssl-passkey-error" class="message" style="color:red;"><?php echo esc_html( $passkey_login_block_reason ); ?></p>
		<?php endif; ?>
        <?php
    }

    /**
     * Validates the authentication for a user.
     *
     * @param WP_User $user The user to validate authentication for.
     * This function needs to be in it for provider reasons however with passkey this is not an option.
     *
     * @return bool True if authentication is valid, false otherwise.
     *
     * @since 1.29
     */
    public function validate_authentication(WP_User $user): bool
    {
	    return get_user_meta($user->ID, self::SECRET_META_KEY, true);
    }

    public function enqueue_scripts(): void
    {
        $path = rsssl_path . 'assets/features/two-fa/assets.min.js';
        wp_enqueue_script('rsssl-passkey', $path, array(), filemtime( $path ), true);
        wp_localize_script('rsssl-passkey', 'rsssl_validate', array(
            'root' => esc_url_raw(rest_url(Rsssl_Two_Factor_On_Board_Api::NAMESPACE)),
            'user_id' => get_current_user_id(),
            'redirect_to' => admin_url(), //added this for comparison in the json output.
            'login_nonce' => wp_create_nonce('rsssl_login_nonce'),
            'translatables' => Rsssl_Two_Factor::translatables()

        ));
    }

    /**
     * Checks if the application is available for a specific user.
     *
     * @param WP_User $user The user for which to check availability.
     * @return bool True if the application is available, false otherwise.
     *
     * @since 1.29.0
     */
    public function is_available_for_user(WP_User $user): bool
    {
        return true;
    }

    /**
     * Checks if the user is forced to use passkey as the two-factor authentication method.
     *
     * @param WP_User $user The user object.
     *
     * @return bool Whether the user is forced to use passkey.
     * @since 0.1-dev
     *
     */
    public static function is_forced(WP_User $user): bool
    {
        // If there is no user logged in, it can't check if the user is forced.
        if ( ! $user->exists() ) {
            return false;
        }
        return Rsssl_Two_Factor_Settings::get_role_status( 'passkey', $user->ID ) === 'forced';
    }

    public static function get_selection_option( $user, bool $checked = false ): void {
        // Get the preferred method meta, which could be a string or an array.
        $preferred_method_meta = get_user_meta( $user->ID, 'rsssl_two_fa_set_provider', true );
        // Normalize the preferred method to always be an array.
        $preferred_methods = is_array( $preferred_method_meta ) ? $preferred_method_meta : (array) $preferred_method_meta;
        // Check if 'Rsssl_Two_Factor_Email' is the preferred method.
        $is_preferred      = in_array( 'Rsssl_Two_Factor_Passkey', $preferred_methods, true );
        $is_enabled        = (bool) get_user_meta( $user->ID, self::SECRET_META_KEY, true );
        $badge_class       = $is_enabled ? 'badge-enabled' : 'badge-default';
        $enabled_text      = $is_enabled ? esc_html__( 'Enabled', 'really-simple-ssl' ) : esc_html__( 'Disabled', 'really-simple-ssl' );
        $checked_attribute = $checked ? 'checked' : '';
        $title             = esc_html__( 'Passkey', 'really-simple-ssl' );
        $description       = esc_html__( 'Authenticate via Passkey', 'really-simple-ssl' );

        // Check if any of the user's roles are in the forced roles list.
        $user_roles      = ! empty( $user->roles ) && is_array( $user->roles ) ? $user->roles : [];
        $forced_roles    = (array) rsssl_get_option( 'two_fa_forced_roles' );
        $is_forcible     = ! empty( array_intersect( $user_roles, $forced_roles ) );

        // Load the template.
        rsssl_load_template(
            'selectable-option.php',
            array(
                'badge_class'       => $badge_class,
                'enabled_text'      => $enabled_text,
                'checked_attribute' => $checked_attribute,
                'title'             => $title,
                'type'              => 'passkey', // Used this to identify the provider.
                'forcible'          => $is_forcible,
                'description'       => $description,
                'user'              => $user,
            ),
            rsssl_path . 'assets/templates/two_fa'
        );
    }

    /**
     * Check if a user is enabled based on their role.
     *
     * @param  WP_User $user  The user object to check.
     *
     * @return bool Whether the user is enabled or not.
     */
    public static function is_enabled( WP_User $user ): bool {
        if ( ! $user->exists() ) {
            return false;
        }
       return rsssl_get_option('enable_passkey_login', false);
    }

    /**
     * Set user status for two-factor authentication.
     *
     * @param int    $user_id User ID.
     * @param string $status The status to set.
     *
     * @return void
     */
    public static function set_user_status( int $user_id, string $status ): void {
        update_user_meta( $user_id, 'rsssl_two_fa_status_passkey', $status );
        // Additional logic for Passkey as standalone.
        if ( $status === 'disabled') {
            // set the passkey_configured to empty.
            update_user_meta( $user_id, 'rsssl_passkey_configured' , 'ignored');
            // delete all the passkey data.
            $resource = Rsssl_Public_Credential_Resource::get_instance();
            if ( is_null( $resource ) ) {
                return;
            }

            $resource->delete_all_user_data( $user_id );
        }
    }

    public static function is_optional(WP_User $user): bool
    {
        $forced_roles = (array) rsssl_get_option('two_fa_forced_roles', []);
        $roles = $user->roles;

        // Guard clause: if roles is not an array, no overlap possible.
        if ( ! is_array( $roles ) ) {
            return false;
        }

        // For multisite, get the strictest role across all sites.
        if ( is_multisite() ) {
            $strict_roles = Rsssl_Two_Factor_Settings::get_strictest_role_across_sites( $user->ID, array( 'passkey' ) );

            // Array conversion for possible single-role.
            if ( is_string( $strict_roles ) ) {
                $strict_roles = ( '' === $strict_roles ) ? null : array( $strict_roles );
            }

            // No valid roles from multisite, no overlap possible.
            if ( empty( $strict_roles ) || ! is_array( $strict_roles ) ) {
                return false;
            }

            $roles = $strict_roles;
        }

        // Check if any user role is in the forced roles list.
        return ! empty( array_intersect( $roles, $forced_roles ) );
    }

    public static function is_configured(WP_User $user): bool
    {
        $status = get_user_meta( $user->ID, 'rsssl_two_fa_status_passkey', true );
        return 'active' === $status;
    }

    public static function reset_meta_data(int $user_id): void
    {
        delete_user_meta($user_id, self::SECRET_META_KEY);
        delete_user_meta($user_id, 'rsssl_two_fa_status_passkey');
        $resource = Rsssl_Public_Credential_Resource::get_instance();
        if (is_null($resource)) {
            return;
        }
        // deleting all the passkey data.
        $resource->delete_all_user_data( $user_id );
    }
}
