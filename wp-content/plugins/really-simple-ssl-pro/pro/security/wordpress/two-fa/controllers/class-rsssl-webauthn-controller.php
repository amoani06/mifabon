<?php
/** @noinspection PhpMultipleClassDeclarationsInspection */
/** @noinspection TransitiveDependenciesUsageInspection */

/**
 * Provides the controller for the WebAuthn API.
 *
 * @package REALLY_SIMPLE_SSL
 *
 * @noinspection
 */

namespace RSSSL\Pro\Security\WordPress\Two_Fa\Controllers;

require_once rsssl_path . 'pro/lib/webauthn/bootstrap.php';

use Exception;
use JsonException;
use RSSSL\Pro\Security\WordPress\Passkey\Rsssl_Public_Credential_Resource;
use RSSSL\Pro\Security\WordPress\Passkey\Rsssl_User_Entity_Creator;
use RSSSL\Pro\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Passkey;
use RSSSL\Security\WordPress\Two_Fa\Controllers\Rsssl_Abstract_Controller;
use RSSSL\Security\WordPress\Two_Fa\Models\Rsssl_Request_Parameters;
use RSSProVendor\Base64Url\Base64Url;
use RSSProVendor\Nyholm\Psr7\Factory\Psr17Factory;
use RSSProVendor\Psr\Http\Message\ServerRequestInterface;
use RSSProVendor\Webauthn\PublicKeyCredentialCreationOptions;
use RSSProVendor\Webauthn\PublicKeyCredentialDescriptor;
use RSSProVendor\Webauthn\PublicKeyCredentialOptions;
use RSSProVendor\Webauthn\PublicKeyCredentialRequestOptions;
use RSSProVendor\Webauthn\PublicKeyCredentialRpEntity;
use RSSProVendor\Webauthn\Server;
use RuntimeException;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;

final class Rsssl_WebAuthn_Controller extends Rsssl_Abstract_Controller
{

    private Server $server;
    private Rsssl_Public_Credential_Resource $credentialRepository;

    /**
     * Constructor for the class.
     *
     * Initializes the class by creating an instance of PublicKeyCredentialRpEntity,
     * initializing the credentialRepository property, and creating an instance of Server class.
     *
     * @return void
     */
    public function __construct($namespace, $version, $featureVersion)
    {
        parent::__construct($namespace, $version, $featureVersion);
        add_action('rest_api_init', array($this, 'register_api_routes'));
        $rpEntity = new PublicKeyCredentialRpEntity(
            get_bloginfo('name'),
            parse_url(home_url(), PHP_URL_HOST)
        );

        $this->credentialRepository = new Rsssl_Public_Credential_Resource();
        $this->server = new Server($rpEntity, $this->credentialRepository);
        $this->server->setMetadataStatementRepository(new Rsssl_User_Entity_Creator());
    }

    /**
     * Retrieves the server request.
     *
     * This method creates a server request object using the Psr17Factory and returns it.
     *
     * @return ServerRequestInterface The server request object.
     */
    public function create_server_request(): ServerRequestInterface
    {
        return (new Psr17Factory())->createServerRequest('POST', home_url($_SERVER['REQUEST_URI']));
    }

    /**
     * Starts the registration process for a user.
     *
     * @param WP_REST_Request $request The REST request object containing the necessary information.
     *
     * @return WP_REST_Response Returns a WP_REST_Response object with the registration options,
     *                           or an error response if the user is not authenticated or not found.
     */
    public function start_registration(WP_REST_Request $request): WP_REST_Response
    {
        $parameters = new Rsssl_Request_Parameters($request);
        try {
            $user = $this->check_login_and_get_user($parameters->user_id, $parameters->login_nonce);
        } catch (Exception $e) {
            return new WP_REST_Response(['message' => $e->getMessage()], 403);
        }

        // Pre-auth nonce is not enough to add a passkey after 2FA exists.
        // Logged-in owners already passed 2FA and may manage their profile.
        if ($this->has_configured_provider($user) && ! $this->is_logged_in_owner($user)) {
            return new WP_REST_Response(
                [
                    'error' => __('Two-Factor Authentication must be completed before it can be changed.', 'really-simple-ssl'),
                ],
                403
            );
        }

        $userEntity = $this->credentialRepository->create_public_key_credential_user_entity($user, $user->ID);
        $creationOptions = $this->server->generatePublicKeyCredentialCreationOptions($userEntity);

        update_user_meta($parameters->user_id, 'webauthn_creation_options', $creationOptions->jsonSerialize());

        return new WP_REST_Response($creationOptions->jsonSerialize(), 200);
    }

    /**
     * Completes the registration process for a user.
     *
     * @param WP_REST_Request $request The REST request object.
     *
     * @return WP_REST_Response Returns a REST response object.
     *
     * @throws Exception If there was an error during the registration process.
     */
    public function complete_registration(WP_REST_Request $request): WP_REST_Response
    {
        $parameters = new Rsssl_Request_Parameters($request);
        try {
            $user = $this->check_login_and_get_user($parameters->user_id, $parameters->login_nonce);
        } catch (Exception $e) {
            return new WP_REST_Response(['message' => $e->getMessage()], 403);
        }

        // Pre-auth nonce is not enough to finish passkey setup after 2FA exists.
        // Logged-in owners already passed 2FA and may manage their profile.
        if ($this->has_configured_provider($user) && ! $this->is_logged_in_owner($user)) {
            return new WP_REST_Response(
                [
                    'error' => __('Two-Factor Authentication must be completed before it can be changed.', 'really-simple-ssl'),
                ],
                403
            );
        }

        if (is_wp_error($user)) {
            /** @var WP_Error $user */
            return new WP_REST_Response(['message' => $user->get_error_message()], $user->get_error_data()['status']);
        }

        $data = json_decode($request->get_body(), true, 512, JSON_THROW_ON_ERROR);

        if (
            !isset($data['credential']['response']['attestationObject'], $data['credential']['response']['clientDataJSON'])
            || !is_string($data['credential']['response']['attestationObject'])
            || !is_string($data['credential']['response']['clientDataJSON'])
        ) {
            return new WP_REST_Response(['message' => __('Invalid attestation response data', 'really-simple-ssl')], 400);
        }


        $credential = $this->credentialRepository->userHasCredential($data['credential']['id']);

        if ($credential !== null) {
            return new WP_REST_Response(['message' => __('User already registered', 'really-simple-ssl')], 200);
        }

        try {
            $creationOptions = $this->get_public_key_credential_options_from_user($user->ID, 'creation');
            $serverRequest = $this->create_server_request();

            $attestationResponse = $this->server->loadAndCheckAttestationResponse(
                json_encode($data['credential'], JSON_THROW_ON_ERROR),
                $creationOptions,
                $serverRequest
            );
            $this->credentialRepository->saveCredentialSource(
                $attestationResponse,
                $user->ID,
                $parameters->auth_device_id
            );

            delete_user_meta($parameters->user_id, 'webauthn_creation_options');
        } catch (Exception $e) {
            return $this->handle_passkey_exception($e, 'registration');
        }
		 Rsssl_Two_Factor_Passkey::set_user_status($user->ID, 'active');
		 self::set_active_provider($user->ID, 'passkey');

		// User has been successfully registered, so we update the user meta so no further registration is needed.
	    update_user_meta($user->ID, 'rsssl_passkey_configured', 'configured');

        $this->authenticate_user($user->ID);
        return new WP_REST_Response([
            'message' => __('Registration successful', 'really-simple-ssl'),
            'status' => 'success',
            'userHandle' => Base64Url::encode($attestationResponse->getUserHandle()),
            'redirect_to' => $parameters->redirect_to ?? admin_url(),
        ], 200);
    }

    /**
     * Generates a challenge assertion for a given WordPress REST API request.
     *
     * @param WP_REST_Request $request The REST API request.
     *
     * @return WP_REST_Response Returns a response object containing the challenge assertion.
     *                          If the user is found and has valid credentials, the response
     *                          will include the generated challenge assertion. If the user
     *                          is not found or does not have valid credentials, an error
     *                          response will be returned.
     */
    public function challenge_assertion(WP_REST_Request $request): WP_REST_Response
    {
        // Extract user ID from the request using the helper method
        $user_id = $this->extract_user_id_from_request($request);

        if (!$user_id) {
            return new WP_REST_Response(['message' => __('User not found or invalid credentials', 'really-simple-ssl')], 404);
        }

        $user = $this->get_user_by_identifier($user_id);

        if (!$user) {
            return new WP_REST_Response(['message' => __('User not found', 'really-simple-ssl')], 404);
        }

        // Generate the request options using the helper method
        $requestOptions = $this->generate_request_options($user);

        return new WP_REST_Response($requestOptions->jsonSerialize(), 200);
    }

    /**
     * Verifies the assertion response for a given REST API request.
     *
     * @param WP_REST_Request $request The REST API request.
     *
     * @throws JsonException
     */
    public function verify_assertion(WP_REST_Request $request): WP_REST_Response
    {
        $data = json_decode($request->get_body(), true, 512, JSON_THROW_ON_ERROR);

        // Validate the assertion response data
        if (
            !isset($data['credential']['response']['authenticatorData'], $data['credential']['response']['clientDataJSON'], $data['credential']['response']['signature'])
            || !is_string($data['credential']['response']['authenticatorData'])
            || !is_string($data['credential']['response']['clientDataJSON'])
            || !is_string($data['credential']['response']['signature'])
        ) {
            return new WP_REST_Response(['message' => __('Invalid assertion response data', 'really-simple-ssl')], 400);
        }

        // Extract user ID from the request
        $user_id = $this->extract_user_id_from_assertion($data);

        if (!$user_id) {
            return new WP_REST_Response(['message' => __('User identification failed', 'really-simple-ssl')], 400);
        }

        $user = $this->get_user_by_identifier($user_id);

        if (!$user) {
            return new WP_REST_Response(['message' => __('User not found', 'really-simple-ssl')], 404);
        }

        try {
            // Retrieve the stored request options
            $requestOptions = $this->get_public_key_credential_options_from_user($user->ID, 'request');

            // Get the server request
            $serverRequest = $this->create_server_request();

            // Find the user's credential by credential ID
            $userEntity = $this->credentialRepository->findOneByCredentialId($data['credential']['id']);

            // Load and check the assertion response
            $assertionResponse = $this->server->loadAndCheckAssertionResponse(
                json_encode($data['credential'], JSON_THROW_ON_ERROR),
                $requestOptions,
                $userEntity,
                $serverRequest
            );

            // Verify that the user handle matches
            if ($assertionResponse->getUserHandle() !== Base64Url::decode($data['credential']['response']['userHandle'] ?? '')) {
                throw new RuntimeException('User handle does not match');
            }

            // If onboarding parameter is true, set the user's two-factor provider to passkey
            $parameters = new Rsssl_Request_Parameters($request);

            // Update the last used timestamp
            $this->credentialRepository->update(
                $assertionResponse->getPublicKeyCredentialId(),
                ['updated_at' => current_time('mysql')]
            );

            // Validate user login and prepare redirect URL
            $redirect_url = $parameters->redirect_to ?? admin_url();
            $this->authenticate_user($user->ID);

            return new WP_REST_Response([
                'message' => __('Assertion verified successfully', 'really-simple-ssl'),
                'status' => 'success',
                'redirect_to' => $redirect_url,
            ], 200);

        } catch (Exception $e) {
            return $this->handle_passkey_exception($e);
        }
    }

    /**
     * Fetches the user passkey data.
     *
     * @param $request
     *
     * @return void
     */
    public static function get_user_passkey_data($request): void
    {
        $user_id = (new Rsssl_Request_Parameters($request))->user_id;
        if (!$user_id) {
            wp_send_json_error(['message' => __('An error occurred while processing the request.', 'really-simple-ssl')], 403);
        }
        $resource = Rsssl_Public_Credential_Resource::get_instance();
        if (!$resource) {
            wp_send_json_error(['message' => __('An error occurred while processing the request.', 'really-simple-ssl')], 404);
        }
        $data = $resource->findAllForUserId($user_id);

        wp_send_json_success(['rows' => $data]);
    }

	/**
	 * Deletes a user's credential.
	 *
	 * For non-administrators, the user_id + login_nonce combination is validated
	 * by credentials_permission_check() and this method enforces that the credential
	 * being deleted belongs to the target user. Administrators who are logged in
	 * can delete credentials for any user, as long as a valid user_id and
	 * matching credential entry_id are provided.
	 *
	 * @param $request
	 *
	 * @return void
	 */
	public static function delete_credential($request): void
	{
		$parameters = new Rsssl_Request_Parameters($request);
		$entry_id = (int) $parameters->entry_id;
		$user_id = (int) $parameters->user_id;

		if (!$entry_id) {
			wp_send_json_error(['message' => __('An error occurred while processing the request.', 'really-simple-ssl')], 400);
		}

		if (!$user_id) {
			wp_send_json_error(['message' => __('An error occurred while processing the request.', 'really-simple-ssl')], 403);
		}

		$resource = Rsssl_Public_Credential_Resource::get_instance();

		if (!$resource) {
			wp_send_json_error(['message' => __('An error occurred while processing the request.', 'really-simple-ssl')], 404);
		}

		// Fetch all credentials for the target user
		$credentials = $resource->findAllForUserId($user_id);

		if (!is_array($credentials) || count($credentials) === 0) {
			wp_send_json_error(['message' => __('An error occurred while processing the request.', 'really-simple-ssl')], 404);
		}

		// Ensure that the credential being deleted belongs to the target user
		$owned_credential_ids = array_map(static function ($credential) {
			return (int) $credential->id;
		}, $credentials);

		if (!in_array($entry_id, $owned_credential_ids, true)) {
			wp_send_json_error(['message' => __('An error occurred while processing the request.', 'really-simple-ssl')], 403);
		}

		// If there is only one credential, we should not allow the user to delete it
		if (count($credentials) === 1) {
			wp_send_json_error(['message' => __('You cannot delete your last credential', 'really-simple-ssl')], 400);
		}

		if ($resource->delete($entry_id)) {
			wp_send_json_success(['message' => __('Credential deleted successfully', 'really-simple-ssl')]);
		}
		wp_send_json_error(['message' => __('Failed to delete credential', 'really-simple-ssl')], 400);
	}

    public function get_user_by_username(string $username)
    {
        return get_user_by('login', $username) ?? false;
    }

    /**
     * @throws Exception
     */
    public function register_api_routes(): void
    {
        $routes = [
            [
                'route' => 'webauthn_register_callback',
                'callback' => array($this, 'start_registration'),
                'permission_callback' => array($this, 'permission_check'),
                'args' => $this->build_args(array(
                    'user_id',
                    'login_nonce',
                    'provider'
                ), array('redirect_to'))
            ],
            [
                'route' => 'webauthn_complete_registration',
                'callback' => array($this, 'complete_registration'),
                'permission_callback' => array($this, 'permission_check'),
                'args' => $this->build_args(array('user_id', 'login_nonce'), array('redirect_to'))
            ],
            [
                'route' => 'webauthn_verify_assertion',
                'callback' => array($this, 'verify_assertion'),
                'permission_callback' => array($this, 'assertion_permission_check'),
                'args' => []
            ],
            [
                'route' => 'webauthn_challenge_assertion',
                'callback' => array($this, 'challenge_assertion'),
                'permission_callback' => array($this, 'challenge_permission_check'),
                'args' => []
            ],
            [
                'route' => 'webauthn_get_all_credentials',
                'callback' => array($this, 'get_user_passkey_data'),
                'permission_callback' => array($this, 'credentials_permission_check'),
                'args' => $this->build_args(array('user_id'), array('login_nonce'))
            ],
            [
	            'route' => 'webauthn_delete_credential',
	            'callback' => array($this, 'delete_credential'),
	            'permission_callback' => array($this, 'credentials_permission_check'),
	            'args' => $this->build_args(array('user_id', 'entry_id'), array('login_nonce'))
            ]
        ];
        foreach ($routes as $route) {
            $this->route(
                $this->namespace,
                self::METHOD,
                $route['route'],
                $route['callback'],
                $route['permission_callback'],
                $route['args']
            );
        }
    }

    /**
     * Checks if the user can be extracted from the request.
     *
     *
     * @return bool
     */
    public function challenge_permission_check(WP_REST_Request $request): bool
    {
        $user_id = $this->extract_user_id_from_request($request);

        return $user_id !== false;
    }

    /**
     * Checks is the post data is valid for assertion.
     *
     *
     * @return bool
     * @throws JsonException
     */
    public function assertion_permission_check(WP_REST_Request $request): bool
    {
        $data = json_decode($request->get_body(), true, 512, JSON_THROW_ON_ERROR);

        // Check if 'credential' is present in the request body
        if (!isset($data['credential'])) {
            return false;
        }

        // Validate necessary fields within 'credential'
        if (!isset($data['credential']['response']['authenticatorData'], $data['credential']['response']['clientDataJSON'], $data['credential']['response']['signature'])) {
            return false;
        }

        // Extract userHandle or username
        $userHandle = isset($data['credential']['response']['userHandle']) ? Base64Url::decode($data['credential']['response']['userHandle']) : null;
        $username = $data['username'] ?? null;

        if ($userHandle) {
            $user_id = $userHandle;
            $user = get_user_by('ID', $user_id);
            if (!$user) {
                return false;
            }
        } elseif ($username) {
            $user = $this->get_user_by_username($username);
            return $user instanceof WP_User;
        } else {
            return false;
        }

        return true;
    }

    private function get_user_by_identifier($identifier, $type = 'id')
    {
        switch ($type) {
            case 'id':
                return get_user_by('id', $identifier);
            case 'username':
                return get_user_by('login', $identifier);
            case 'user_handle':
                $user_id = Base64Url::decode($identifier);

                return get_user_by('id', $user_id);
            case 'unique_browser_id':
                $users = get_users([
                    'meta_key' => 'webauthn_unique_browser_id',
                    'meta_value' => $identifier,
                    'number' => 1,
                    'fields' => 'ID',
                ]);

                return !empty($users) ? get_user_by('id', $users[0]) : false;
            default:
                return false;
        }
    }

    /**
     * Extracts the user ID from the request.
     *
     *
     * @return false|int
     */
    private function extract_user_id_from_request(WP_REST_Request $request)
    {
        $parameters = new Rsssl_Request_Parameters($request);
        $user_login = $parameters->user_login;
        $user_handle = $parameters->user_handle;

        if (!empty($user_login)) {
            $user = $this->get_user_by_identifier($user_login, 'username');

            return $user->ID ?? false;
        }

        if (!empty($user_handle)) {
            $user = $this->get_user_by_identifier($user_handle, 'user_handle');

            return $user->ID ?? false;
        }

        return false;
    }

    /**
     * Retrieves the public key credential options from the user meta.
     *
     *
     * @return PublicKeyCredentialRequestOptions|PublicKeyCredentialCreationOptions
     * @throws Exception
     */
    private function get_public_key_credential_options_from_user(int $user_id, string $type): PublicKeyCredentialOptions
    {
        $meta_key = $type === 'creation' ? 'webauthn_creation_options' : 'webauthn_request_options';
        $options = get_user_meta($user_id, $meta_key, true);

        if (!$options) {
            throw new RuntimeException("No $type options found for user");
        }

        return $type === 'creation'
            ? PublicKeyCredentialCreationOptions::createFromArray($options)
            : PublicKeyCredentialRequestOptions::createFromArray($options);
    }

    /**
     * Handles exceptions from passkey (WebAuthn) operations.
     *
     * Logs the actual error message for debugging when WP_DEBUG is enabled.
     * Returns a user-friendly message based on the error type and context.
     *
     * @param Exception $e The exception to handle.
     * @param string $context The operation context: 'registration' or 'login'.
     *
     * @return WP_REST_Response
     */
    private function handle_passkey_exception(Exception $e, string $context = 'login'): WP_REST_Response
    {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('Really Simple Security Passkey Error: ' . $e->getMessage() . ' | File: ' . $e->getFile() . ':' . $e->getLine());
        }

        return new WP_REST_Response([
            'message' => $this->get_passkey_error_message($e->getMessage(), $context),
        ], 400);
    }

    /**
     * Returns a user-friendly error message for passkey operations.
     *
     * For errors we recognize and understand, we show a helpful message.
     * For security-related or unknown errors, we show a generic message.
     *
     * @param string $exception_message The original exception message.
     * @param string $context           The operation context: 'registration' or 'login'.
     *
     * @return string
     */
    private function get_passkey_error_message(string $exception_message, string $context): string
    {
        if ($exception_message === 'Invalid challenge.') {
            return __('Your session may have expired. Please refresh the page and try again.', 'really-simple-ssl');
        }

        if ($context === 'registration') {
            return __('Passkey registration failed. Please try again.', 'really-simple-ssl');
        }

        if ($context === 'login' && in_array($exception_message, ['The credential ID is invalid.', 'The credential ID is not allowed.'], true)) {
            return __('Your passkey is not registered on this site. Please log in with another method to register your passkey.', 'really-simple-ssl');
        }

        return __('Passkey authentication failed. Please try again.', 'really-simple-ssl');
    }

    private function generate_request_options($user): PublicKeyCredentialRequestOptions
    {
        $userEntity = $this->credentialRepository->create_public_key_credential_user_entity($user, $user->ID);
        $storedCredentials = $this->credentialRepository->findAllForUserEntity($userEntity);

        $allowedCredentials = array_map(
            static fn($credential) => new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $credential->getPublicKeyCredentialId()
            ),
            $storedCredentials
        );

        $requestOptions = $this->server->generatePublicKeyCredentialRequestOptions(null, $allowedCredentials);

        update_user_meta($user->ID, 'webauthn_request_options', $requestOptions->jsonSerialize());

        return $requestOptions;
    }

    /**
     * Extracts the user ID from the assertion data.
     *
     * @param array $data The assertion data.
     *
     * @return int|false Returns the user ID if found, false otherwise.
     */
    private function extract_user_id_from_assertion(array $data)
    {
        $userHandle = isset($data['credential']['response']['userHandle']) ? Base64Url::decode($data['credential']['response']['userHandle']) : null;
        $username = $data['username'] ?? null;

        if ($userHandle) {
            return $userHandle;
        }

        if ($username) {
            $user = $this->get_user_by_identifier($username, 'username');

            return $user->ID ?? false;
        }

        return false;
    }

    /**
     * Authenticates the user by setting auth cookies and current user.
     *
     * @param int $user_id The user ID.
     *
     * @return void
     * @noinspection UnusedFunctionResultInspection
     */
    private function authenticate_user(int $user_id): void
    {
        wp_set_auth_cookie($user_id, true);
        wp_set_current_user($user_id);
    }


	/**
	 * Allow admins, logged-in owners, or pre-auth users without configured 2FA.
	 *
	 * Logged-in administrators can manage credentials for any user. Logged-in
	 * users can manage their own credentials. During pre-authentication,
	 * login_nonce access is only valid before a provider is configured.
	 *
	 * @param WP_REST_Request $request
	 *
	 * @return bool
	 */
	public function credentials_permission_check(WP_REST_Request $request): bool
	{
		if (is_user_logged_in() && current_user_can('manage_options')) {
			return true;
		}

		$parameters = new Rsssl_Request_Parameters($request);

		try {
			$user = $this->check_login_and_get_user(
				$parameters->user_id,
				$parameters->login_nonce
			);
		} catch (Exception $e) {
			return false;
		}

		if (! $user instanceof WP_User) {
			return false;
		}

		// Owner still needs the per-request login nonce. Auth cookie alone is not enough.
		if ($this->is_logged_in_owner($user)) {
			return true;
		}

		// Pre-auth credential management is only allowed before a provider is configured.
		return ! $this->has_configured_provider($user);
	}

	/**
	 * Check if the current authenticated user owns the requested account.
	 *
	 * This marks profile management, not the pre-auth login challenge.
	 *
	 * @param WP_User $user The requested user.
	 *
	 * @return bool
	 */
	private function is_logged_in_owner(WP_User $user): bool
	{
		return is_user_logged_in() && get_current_user_id() === (int) $user->ID;
	}
}
