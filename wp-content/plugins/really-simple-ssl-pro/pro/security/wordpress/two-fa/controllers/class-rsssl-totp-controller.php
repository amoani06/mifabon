<?php
namespace RSSSL\Pro\Security\WordPress\Two_Fa\Controllers;

use Exception;
use RSSSL\Pro\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Totp;
use RSSSL\Pro\Security\WordPress\Two_Fa\Rsssl_Two_Factor_Backup_Codes;
use RSSSL\Security\WordPress\Two_Fa\Controllers\Rsssl_Abstract_Controller;
use RSSSL\Security\WordPress\Two_Fa\Models\Rsssl_Request_Parameters;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Class Rsssl_Totp_Controller
 *
 * This class is responsible for verifying the Two-Factor Authentication (TFA) code using Time-based One-Time Password (TOTP) method.
 * It provides a static method 'verify_2fa_code_totp' that takes a WP_REST_Request object as the input and returns a WP_REST_Response object.
 *
 * @package YourPackage
 */
final class Rsssl_Totp_Controller extends Rsssl_Abstract_Controller
{

    protected const METHOD = 'POST';
    protected const FEATURE_ROUTE = '/two-fa';

    protected string $namespace;

    public function __construct($namespace, $version, $featureVersion)
    {
        parent::__construct($namespace, $version, $featureVersion);
        add_action('rest_api_init', array($this, 'register_api_routes'));
    }

	/**
	 * Register the API routes.
	 * @throws Exception
	 */
	public function register_api_routes(): void
    {
        $this->route($this->namespace,
            self::METHOD,
            'save_default_method_totp',
            array($this, 'verify_2fa_code_totp'),
	        null,
            $this->build_args(array('user_id', 'login_nonce', 'provider', 'key', 'two-factor-totp-authcode'), array('redirect_to'))
        );
    }

    /**
     * Verifies the 2FA code for TOTP.
     *
     * @param WP_REST_Request $request The REST request object.
     *
     * @return WP_REST_Response The REST response object.
     */
    public function verify_2fa_code_totp( WP_REST_Request $request ): WP_REST_Response {
        $parameters = new Rsssl_Request_Parameters( $request );

        try {
            $user = $this->check_login_and_get_user($parameters->user_id, $parameters->login_nonce);
        } catch (Exception $e) {
            return new WP_REST_Response(['message' => $e->getMessage()], 403);
        }

		// Do not let a password-step nonce replace an existing 2FA method.
		if ( $this->has_configured_provider( $user ) ) {
			return new WP_REST_Response(
				array(
					'error' => __( 'Two-Factor Authentication must be completed before it can be changed.', 'really-simple-ssl' ),
				),
				403
			);
		}

        // Check if the provider.
        if ( 'totp' !== $parameters->provider ) {
            return new WP_REST_Response( array( 'message' => __('Invalid provider', 'really-simple-ssl') ), 400 );
        }

        //This is an extra check so someone who thinks to use backup codes can't use them.
        $code_backup = Rsssl_Two_Factor_Backup_Codes::sanitize_code_from_request( 'authcode', 8 );
        if ( $code_backup && Rsssl_Two_Factor_Backup_Codes::validate_code( $user->ID, $code_backup, false ) ) {
            $error_message = __('Invalid Two Factor Authentication code.', 'really-simple-ssl');
            return new WP_REST_Response( array( 'message' => $error_message ), 400 );
        }

        if ( Rsssl_Two_Factor_Totp::setup_totp( $user, $parameters->key, $parameters->code ) ) {
            // Mark all other statuses as inactive.
            self::set_active_provider($user->ID, 'totp' );
            // Finally we redirect the user to the redirect_to page.
            return $this->authenticate_and_redirect( $user->ID, $parameters->redirect_to );
        }

        // We get the error message from the setup_totp function.
        $error_message = get_transient( 'rsssl_error_message_' . $user->ID );
        // We delete the transient.
        delete_transient( 'rsssl_error_message_' . $user->ID );
        return  new WP_REST_Response( array( 'message' => $error_message ), 400 );
    }
}
