<?php /** @noinspection ContractViolationInspection */

/** @noinspection TransitiveDependenciesUsageInspection */
namespace RSSSL\Pro\Security\WordPress\Passkey;

require_once rsssl_path . 'pro/lib/webauthn/bootstrap.php';

use Exception;
use RSSProVendor\Base64Url\Base64Url;
use RSSProVendor\Webauthn\PublicKeyCredentialSource;
use RSSProVendor\Webauthn\PublicKeyCredentialSourceRepository;
use RSSProVendor\Webauthn\PublicKeyCredentialUserEntity;
use RSSSL\Pro\Security\WordPress\Passkey\Models\Rsssl_Webauthn;
use RuntimeException;

/**
 * Class Rsssl_Public_Credential_Resource
 * @package RSSSL\Pro\Security\WordPress\Two_Fa\Passkey
 */
final class Rsssl_Public_Credential_Resource implements PublicKeyCredentialSourceRepository {
	private Rsssl_Webauthn $model;

	/**
	 * Class constructor.
	 *
	 * Initializes the object by creating a new instance of the Rsssl_Webauthn class and assigning it to the $model property.
	 *
	 * @return void
	 */
	public function __construct() {
		$this->model = new Rsssl_Webauthn();
	}

	/**
	 * Get the instance of the Rsssl_Public_Credential_Resource class
	 *
	 * This method returns the instance of the Rsssl_Public_Credential_Resource class.
	 *
	 * @return Rsssl_Public_Credential_Resource|null The instance of the Rsssl_Public_Credential_Resource class, or null if the instance has not been created yet.
	 */
	public static function get_instance(): ?Rsssl_Public_Credential_Resource {
		static $instance = null;
		if ( null === $instance ) {
			$instance = new self();
		}

		return $instance;
	}


	/**
	 * Finds a record by credential ID.
	 *
	 * Searches for a record in the database based on the provided credential ID. If a matching record is found, it is returned as an instance of the PublicKeyCredentialSource class. If no match is found, null is returned.
	 *
	 * @param string $publicKeyCredentialId The credential ID to search for.
	 *
	 * @return PublicKeyCredentialSource|null The matching record as an instance of PublicKeyCredentialSource, or null if no match is found.
	 */
	public function findOneByCredentialId( string $publicKeyCredentialId ): ?PublicKeyCredentialSource {
		$credentialData = $this->model->get_by_credential_id( $publicKeyCredentialId );
		if ( $credentialData && $credentialData->getPublicKeyCredentialId() === $publicKeyCredentialId ) {
			return $credentialData;
		}

		return null;
	}

	/**
	 * Create a public key credential user entity
	 *
	 * This method creates and returns a public key credential user entity object
	 * using the provided user data.
	 *
	 * @param object $user The user object
	 * @param string $userId The user ID
	 *
	 * @return PublicKeyCredentialUserEntity The public key credential user entity
	 */
	public function create_public_key_credential_user_entity( object $user, string $userId ): PublicKeyCredentialUserEntity {
		return new PublicKeyCredentialUserEntity(
			$user->user_login,
			$userId,
			$user->display_name
		);
	}

	/**
	 * Saves the credential source for the given user.
	 *
	 * This method saves the PublicKeyCredentialSource object for the specified user. If the user ID is not provided, it will attempt to retrieve the current user's ID. If the user ID is invalid or the update_user_meta function does not exist, an exception will be thrown. The method then calls the save method of the Rsssl_Webauthn class to save the credential source, user ID, and authentication device ID. If the save operation fails, an exception is thrown.
	 *
	 * @param PublicKeyCredentialSource $publicKeyCredentialSource The credential source to be saved.
	 * @param mixed $user_id (optional) The ID of the user for whom the credential source is being saved. If not provided, the current user's ID will be used.
	 * @param string $authDeviceId (optional) The ID of the authentication device being used. Defaults to 'unknown'.
	 *
	 * @return void
	 */
	public function saveCredentialSource( PublicKeyCredentialSource $publicKeyCredentialSource, $user_id = null, string $authDeviceId = 'unknown' ): void {
		try {
			if ( ! $user_id ) {
				$user_id = get_current_user_id();
			}


			if ( is_null( $user_id ) ) {
				throw new RuntimeException( "Invalid user ID." );
			}

			if ( ! function_exists( 'update_user_meta' ) ) {
				throw new RuntimeException( "Function update_user_meta does not exist." );
			}

			// Check if this credential ID already exists for a different user
			$existingCredential = $this->model->findByKey( Base64Url::encode( $publicKeyCredentialSource->getPublicKeyCredentialId() ) );
			if ( $existingCredential && $existingCredential->getUserHandle() !== $publicKeyCredentialSource->getUserHandle() ) {
				throw new RuntimeException( "Credential ID already exists." );
			}

			// Save the credential source
			$result = $this->model->save( $publicKeyCredentialSource, $user_id, $authDeviceId );

			if ( ! $result ) {
				throw new RuntimeException( "Failed to save credential data." );
			}


		} catch ( Exception $e ) {
			error_log( $e->getMessage() );
		}

	}

	/**
	 * Retrieves all public key credential sources associated with a given user entity.
	 *
	 * @param PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity The user entity to retrieve the public key credential sources for.
	 *
	 * @return array An array of public key credential sources associated with the user entity.
	 */
	public function findAllForUserEntity( PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity ): array {
		$user_id     = $publicKeyCredentialUserEntity->getId();
		$credentials = $this->model->get_by_user_id( $user_id );

		$publicKeyCredentialSources = [];
		if ( isset( $credentials['user_id'] ) ) {
			unset( $credentials['user_id'] );
		}
		if ( isset( $credentials['unique_identifier'] ) ) {
			unset( $credentials['unique_identifier'] );
		}
		foreach ( $credentials as $credentialData ) {
			$publicKeyCredentialSources[] = $credentialData;
		}

		return $publicKeyCredentialSources;
	}

	/**
	 * Retrieves all data for a specific user ID.
	 *
	 * @param int $user_id The ID of the user for which to retrieve the data.
	 *
	 * @return array The list of data entries associated with the specified user ID.
	 */
	public function findAllForUserId( int $user_id ): array {
		return $this->model->get_list_user_id( $user_id );
	}

	/**
	 * Checks if the user has a credential with the given public key credential ID.
	 *
	 * @param mixed $publicKeyCredentialId The public key credential ID to check.
	 *
	 * @return PublicKeyCredentialSource|null The credential source if the user has the credential, or null otherwise.
	 */
	public function userHasCredential( $publicKeyCredentialId ): ?PublicKeyCredentialSource {
		$credentials = $this->model->findByKey( $publicKeyCredentialId );
		if ( $credentials ) {
			return new PublicKeyCredentialSource(
				$credentials['publicKeyCredentialId'],
				$credentials['Type'],
				$credentials['Transports'],
				$credentials['attestationType'],
				$credentials['trustPath'],
				$credentials['aaguid'],
				$credentials['credentialPublicKey'],
				$credentials['userHandle'],
				$credentials['counter'],
			);
		}

		return null;
	}

	/**
	 * Delete the data by the ID
	 *
	 * @param $id
	 *
	 * @return bool
	 */
	public function delete( $id ): bool {
		try {
			$this->model->delete( $id );

			return true;
		} catch ( Exception $e ) {
			error_log( $e->getMessage() );

			return false;
		}
	}

	/**
	 * @param int $user_id
	 *
	 * @return void
	 */
	public function delete_all_user_data( int $user_id ): void {
		$this->model->delete_data_by_user_id( $user_id );
	}

	/**
	 * Update the login data
	 *
	 * @param string $getPublicKeyCredentialId
	 * @param array $array
	 *
	 * @return void
	 */
	public function update( string $getPublicKeyCredentialId, array $array ): void {
		$this->model->update_login( $getPublicKeyCredentialId, $array );
	}
}
