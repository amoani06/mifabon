<?php
declare(strict_types=1);
/**
 * Passkey integration for Really Simple SSL Pro.
 *
 * Handles registration of scripts, the onboarding flow, and REST controller setup
 * for passkey-based two-factor authentication.
 *
 * @package   ReallySimpleSSL\Pro\Security\WordPress\Passkey
 * @author    Really Simple Plugins
 * @link      https://really-simple-ssl.com
 */

namespace RSSSL\Pro\Security\WordPress\Passkey;

use Exception;
use RSSSL\Pro\Security\WordPress\Passkey\Capability\Rsssl_Passkey_Capability;
use RSSSL\Pro\Security\WordPress\Passkey\Models\Rsssl_Webauthn;
use RSSSL\Pro\Security\WordPress\Passkey\Policy\Rsssl_Secure_Auth_Policy;
use RSSSL\Pro\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Passkey;
use RSSSL\Security\WordPress\Two_Fa\Controllers\Rsssl_Base_Controller;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Fa_Authentication;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Factor;
use RSSSL\Security\WordPress\Two_Fa\Traits\Rsssl_Two_Fa_Helper;
use WP_User;

/**
 * Bootstraps passkey-based two-factor authentication.
 *
 * - Registers enqueue scripts and login hooks
 * - Triggers onboarding UI if needed
 * - Delegates to the REST & base controllers
 *
 * @package ReallySimpleSSL\Pro\Security\WordPress\Passkey
 */
class Rsssl_Passkey {
	use Rsssl_Two_Fa_Helper;

	private const PLUGIN_SLUG = 'really-simple-security';
	private const API_VERSION = 'v1';
	private const TWO_FA_VERSION = 'v2';
    private const POLICY_LOCKED_OUT = 'rsssl_locked_out';

	private const POLICY_ENFORCED = 'rsssl_enforced';

	public const REST_NAMESPACE = self::PLUGIN_SLUG . '/' . self::API_VERSION . '/two-fa/' . self::TWO_FA_VERSION;

	private static ?self $instance = null;

	/**  Holds the user who’s in the middle of onboarding  */
	private static ?WP_User $onboarding_user = null;

	private ?Rsssl_Login_Flow_Decider $decider = null;


	/**
	 * Retrieve single instance.
	 *
	 * @return self
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Run hooks
	 * @return void
	 */
	public static function run_hooks(): void {
		if ( ( defined( 'RSSSL_DISABLE_2FA' ) && RSSSL_DISABLE_2FA )
		     || ( defined( 'RSSSL_SAFE_MODE' ) && RSSSL_SAFE_MODE )
		) {
			return;
		}
		// if 2fa is enabled, we need to run the hooks. Since this is a feature of the two-factor authentication, we check if the login protection is enabled.
		// if so 2fa takes over and this is not needed.
		$instance = self::get_instance();
        add_filter( 'login_message', [ $instance, 'maybe_print_locked_out_message' ] );
		add_filter( 'login_message', [ $instance, 'maybe_print_passkey_enforced_message' ] );
		if ( rsssl_get_option( 'login_protection_enabled', false ) === 1) {
			// we only load the scripts if the login protection is enabled.
            $instance->register_login_assets_hooks();

			return;
		}

		// Services
		$policy            = new Rsssl_Secure_Auth_Policy();
		$cap               = new Rsssl_Passkey_Capability();
		$skip              = new Rsssl_Skip_Strategy();
		$instance->decider = new Rsssl_Login_Flow_Decider( $policy, $cap, $skip );

		// Check if the passkey table is enabled.
		add_action( 'init', [ Rsssl_Webauthn::class, 'maybe_install_table' ] );
        $instance->register_login_assets_hooks();

		// after successful login, maybe kick off the passkey setup
        if (rsssl_get_option( 'login_protection_enabled', false ) == 0) {
            add_action( 'wp_authenticate', [ $instance, 'maybe_start_passkey_onboarding' ], 100, 2 );
        }

		/*
		 * Start the controller for the passkey this is needed for all the logic to work.
		 */
		Rsssl_Two_Factor_Passkey::start_controller( self::PLUGIN_SLUG, self::API_VERSION, self::TWO_FA_VERSION );
		// We add the skip functionality to the two-factor authentication.
		new Rsssl_Base_Controller( self::PLUGIN_SLUG, self::API_VERSION, self::TWO_FA_VERSION );

		if ( rsssl_admin_logged_in() ) {
			( new RSSSL_Passkey_User_Admin() );
		}

		// We add the passkey profile settings to the user profile.
		Rsssl_Passkey_Profile_Settings::init();
	}

    /**
     * Register login assets hooks.
     */
    private function register_login_assets_hooks(): void {
        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_onboarding_scripts' ] );
        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_onboarding_styles' ] );
    }

	/**
	 * Enqueue onboarding styles
	 * @return void
	 */
	public function enqueue_onboarding_styles(): void {
		$uri       = trailingslashit( rsssl_url ) . 'assets/features/two-fa/styles.min.css';
		$file_path = trailingslashit( rsssl_path ) . 'assets/features/two-fa/styles.min.css';

		if ( file_exists( $file_path ) ) {
			wp_enqueue_style( 'rsssl-passkey-settings', $uri, [], filemtime( $file_path ) );
		}
	}

    /**
     * Resolve verified user ID from the posted login name.
     */
    private function get_verified_user_id_from_request(): int {
        $raw = isset($_POST['log']) ? wp_unslash($_POST['log']) : '';
        $raw = is_string($raw) ? trim($raw) : '';

        if ($raw === '') {
            return 0;
        }

        if (is_email($raw)) {
            $user = get_user_by('email', sanitize_email($raw));
        } else {
            $user = get_user_by('login', sanitize_user($raw));
        }

        if (!$user) {
            return 0;
        }

        $capability = new Rsssl_Passkey_Capability();

        // Only expose the verified user ID when the login flow can continue with a passkey.
        if ( $capability->user_has_registered_passkey( $user ) ||
            is_user_logged_in()
        ) {
            return (int) $user->ID;
        }
        return 0;
    }

	/**
	 * Create a login nonce for a verified user or return empty string.
	 */
	private function maybe_create_login_nonce( int $verified_user_id ): string {
		if ( $verified_user_id > 0 ) {
			$nonce = Rsssl_Two_Fa_Authentication::create_login_nonce( $verified_user_id );
			return isset( $nonce['rsssl_key'] ) ? (string) $nonce['rsssl_key'] : '';
		}

		return '';
	}

    /**
     * Retrieve the redirect_to parameter safely, with a sane default.
     */
    private function get_redirect_to(): string {
        return isset( $_REQUEST['redirect_to'] )
            ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) )
            : admin_url();
    }

	/**
	 * Enqueue onboarding scripts
	 * @return void
	 */
	public function enqueue_onboarding_scripts(): void {
		$uri       = trailingslashit( rsssl_url ) . 'assets/features/two-fa/assets.min.js';
		$file_path = trailingslashit( rsssl_path ) . 'assets/features/two-fa/assets.min.js';
		if ( ! file_exists( $file_path ) ) {
			return;
		}

		$this->fallback_enqueue_script( $uri, $file_path );

		$passkey_login_block_reason = '';
		if ( (bool) rsssl_get_option( 'enable_passkey_login', false ) ) {
			$passkey_login_block_reason = \rsssl_get_passkey_login_enable_block_reason();
		}

		$verified_user_id = $this->get_verified_user_id_from_request();
		$login_nonce      = '';
		$user_id          = $verified_user_id;

		add_filter( 'rsssl_two_factor_translatables', [ Rsssl_Two_Factor_Passkey::class, 'translatables' ] );

		if ( self::$onboarding_user instanceof WP_User ) {
			$user_id     = (int) self::$onboarding_user->ID;
			$login_nonce = $this->maybe_create_login_nonce( $user_id );
		}

		wp_localize_script( 'rsssl-passkey-login', 'rsssl_login', [
			'origin'                     => 'passkey',
			'root'                       => esc_url_raw( rest_url( self::REST_NAMESPACE ) ),
			'login_nonce'                => $login_nonce,
			'redirect_to'                => $this->get_redirect_to(),
			'passkey_login_block_reason' => $passkey_login_block_reason,
			'translatables'              => apply_filters( 'rsssl_two_factor_translatables', [] ),
			'user_id'                    => $user_id,
		] );
	}

	/**
	 * Fallback enqueue script for browsers that do not support module scripts
	 *
	 * @param string $uri
	 * @param string $file_path
	 *
	 * @return void
	 */
	private function fallback_enqueue_script( string $uri, string $file_path ): void {
		wp_enqueue_script( 'rsssl-passkey-login', $uri, [], filemtime( $file_path ), true );
		add_filter( 'script_loader_tag', static function ( $tag, $handle ) {
			if ( $handle !== 'rsssl-passkey-login' ) {
				return $tag;
			}

			return str_replace( ' src', ' type="module" src', $tag );
		}, 10, 2 );
	}

	/**
	 * Starts the passkey onboarding process if the user has requested it.
	 *
	 * @throws Exception
	 */
	public function maybe_start_passkey_onboarding(string $username, string $password): void {
        $user = get_user_by( 'login', $username );
        if ( ! $user ) {
            return;
        }
        // Authenticate the user with the password, without triggering the full `authenticate` filter chain.
        // This prevents the base Two-Factor flow from hijacking the onboarding login attempt.
        $authenticated_user = wp_authenticate_username_password( null, $username, $password );
        if ( is_wp_error( $authenticated_user ) ) {
            return;
        }

        if ( ! $authenticated_user instanceof WP_User || (int) $authenticated_user->ID !== (int) $user->ID ) {
            return;
        }

        $capability = new Rsssl_Passkey_Capability();

        // Keep rsssl_passkey_configured aligned with the stored credential state before
        // the onboarding checks below read that meta value.
        $capability->maybe_sync_registered_passkey_meta( $user );
        $passkey_status = (string) get_user_meta( $user->ID, 'rsssl_passkey_configured', true );

        // Determine if secure authentication is enforced for this user (fallback-safe)
        $enforced = ( new Rsssl_Secure_Auth_Policy() )->is_enforced_for_user( $user );

        // Multisite-specific fix: this "ignored" state can be left behind by 2FA
        // disable/reset flows as well, not only by skipping passkey onboarding.
        // If 2FA is disabled while passkeys stay enabled, clear that stale state
        // so passkey onboarding can show again.
        if (
            is_multisite()
            && ! $enforced
            && $passkey_status === 'ignored'
            && rsssl_get_option( 'enable_passkey_login', false )
            && (
                in_array( get_user_meta( $user->ID, 'rsssl_two_fa_status_email', true ), array( 'active', 'open' ), true )
                || in_array( get_user_meta( $user->ID, 'rsssl_two_fa_status_totp', true ), array( 'active', 'open' ), true )
            )
        ) {
            delete_user_meta( $user->ID, 'rsssl_passkey_configured' );
            $passkey_status = '';
        }

		// Use the decider (when available) to determine the flow
		$decision = $this->decider ? $this->decider->decide( $user ) : null;


		if ( $enforced && is_array( $decision ) && isset( $decision['flow'] ) && $decision['flow'] === Rsssl_Login_Flow::PASSKEY_REQUIRED ) {
			$this->show_passkey_confirmation( $user );
		}

        // If already configured, we never start onboarding
        if ( $passkey_status === 'configured' ) {
            return;
        }

        // If user previously chose to ignore AND is not enforced, respect that choice
        if ( $passkey_status === 'ignored' && ! $enforced ) {
            return;
        }



        // If enforced and the decider says locked out, redirect with clear message
        if ( $enforced && is_array( $decision ) && isset( $decision['flow'] ) && $decision['flow'] === Rsssl_Login_Flow::LOCKED_OUT ) {
            wp_redirect( wp_login_url() . '?' . self::POLICY_LOCKED_OUT . '=1' );
            exit;
        }

        // Onboarding still needs a temporary authenticated user context.
        remove_filter( 'send_auth_cookies', '__return_false', PHP_INT_MAX );
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID );

        // Enforce onboarding for specific flows
        if ( is_array( $decision ) && isset( $decision['flow'] ) ) {
            if ( $decision['flow'] === Rsssl_Login_Flow::FORCE_PASSKEY_ENROLLMENT ||
                 $decision['flow'] === Rsssl_Login_Flow::PASSKEY_OPTIONAL ) {
                self::$onboarding_user = $user;
                $this->passkey_onboarding_html( $user, $decision );
                exit;
            }
            // In all other flows do nothing here.
            return;
        }

        // Backward compatibility fallback: if no decider is set but enforcement is true and user isn't configured,
        // require onboarding. Otherwise, do nothing.
        if ( $enforced ) {
            self::$onboarding_user = $user;
            $this->passkey_onboarding_html( $user, [ 'flow' => Rsssl_Login_Flow::FORCE_PASSKEY_ENROLLMENT ] );
            exit;
        }
	}

	/**
	 * Render the standalone passkey confirmation step after password validation.
	 *
	 * @throws Exception
	 */
	private function show_passkey_confirmation( WP_User $user ): void {
		$login_nonce = Rsssl_Two_Fa_Authentication::create_login_nonce( $user->ID );
		if ( ! is_array( $login_nonce ) || empty( $login_nonce['rsssl_key'] ) ) {
			wp_die(
				esc_html__( 'Failed to create a login nonce.', 'really-simple-ssl' ),
				'',
				array( 'response' => 403 )
			);
		}

		Rsssl_Two_Factor::login_html(
			$user,
			(string) $login_nonce['rsssl_key'],
			$this->get_redirect_to(),
			'',
			Rsssl_Two_Factor_Passkey::class
		);
		exit;
	}

	/**
	 * Render onboarding UI and halt execution.
	 *
	 * @throws Exception if nonce generation fails
	 */
	private function passkey_onboarding_html( WP_User $user, $loginFlow ): void {
		// Variables needed for the template and scripts
		$redirect_to = admin_url();

		// Ensure login_header and login_footer functions are available
		if ( ! function_exists( 'login_header' ) ) {
			include_once rsssl_path . 'security/wordpress/two-fa/function-login-header.php';
		}

		if ( ! function_exists( 'login_footer' ) ) {
			include_once rsssl_path . 'security/wordpress/two-fa/function-login-footer.php';
		}

		login_header(
			__( 'Passkey Setup', 'really-simple-ssl' ),
			'',
			null
		);

        // The flow decider is not complete and although these options are not relative now,
        // they could be relative later, since rework is being done now, i decided to pass them here for now
        // instead of doing a separate check in the template and the scripts.

        $is_today = isset( $loginFlow['is_today'] ) ? $loginFlow['is_today'] : false;
        $grace_period = isset( $loginFlow['grace_period'] ) ? $loginFlow['grace_period'] : 0;
        $is_forced = isset( $loginFlow['is_forced'] ) ? $loginFlow['is_forced'] : 0;
        $show_skip = isset( $loginFlow['show_skip'] ) ? $loginFlow['show_skip'] : 0;

		rsssl_load_template(
			'onboarding.php',
			compact(
                'is_today',
                'grace_period',
                'is_forced',
                'show_skip'
            ),
			rsssl_path . 'pro/assets/templates/passkey/'
		);

		login_footer();

		if ( ob_get_level() > 0 ) {
			ob_flush();
		}
		flush();
		exit;
	}

	/**
	 * Show a clear message on the login screen when a user has been locked out
	 * via the passkey enforcement redirect (?rsssl_locked_out=1).
	 *
	 * @param string $message Existing login message HTML.
	 * @return string Modified login message HTML.
	 */
	public function maybe_print_locked_out_message( string $message ): string {
		if ( isset( $_GET[ self::POLICY_LOCKED_OUT ] ) && (string) $_GET[ self::POLICY_LOCKED_OUT ] === '1' ) {
			$locked = '<div id="login_error" class="notice notice-error">' . esc_html__( 'Your account has been temporarily locked due to security policies. Please contact the administrator to regain access.', 'really-simple-ssl' ) . '</div>';
			return $locked . $message;
		}
		return $message;
	}


	/**
	 * Show a clear message on the login screen when a user has been locked out
	 * via the passkey enforcement redirect (?rsssl_locked_out=1).
	 *
	 * @param string $message Existing login message HTML.
	 * @return string Modified login message HTML.
	 */
	public function maybe_print_passkey_enforced_message( string $message ): string {
		if ( isset( $_GET[ self::POLICY_ENFORCED ] ) && (string) $_GET[ self::POLICY_ENFORCED ] === '1' ) {
			$locked = '<div id="login_error" class="notice notice-error">' . esc_html__( 'Your account has been configured for passkey and is enforced please login using passkey.', 'really-simple-ssl' ) . '</div>';
			return $locked . $message;
		}
		return $message;
	}
}

Rsssl_Passkey::run_hooks();
