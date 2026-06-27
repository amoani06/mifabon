<?php
namespace RSSSL\Pro\Security\WordPress\Passkey\Capability;

use RSSSL\Pro\Security\WordPress\Passkey\Rsssl_Public_Credential_Resource;
use WP_User;

class Rsssl_Passkey_Capability {
	public function is_feature_enabled(): bool {
		return (bool) rsssl_get_option('enable_passkey_login', false);
	}

	/**
	 * Check whether the user has a registered passkey.
	 */
	public function user_has_registered_passkey(WP_User $user): bool {
		if ( ! $user->exists() ) {
			return false;
		}

		return get_user_meta( $user->ID, 'rsssl_passkey_configured', true ) === 'configured'
			|| $this->has_registered_passkey_credentials( $user->ID );
	}

	/**
	 * Update the passkey status meta when stored WebAuthn credentials still exist.
	 */
	public function maybe_sync_registered_passkey_meta( WP_User $user ): void {
		if ( ! $user->exists() ) {
			return;
		}

		if ( get_user_meta( $user->ID, 'rsssl_passkey_configured', true ) === 'configured' ) {
			return;
		}

		if ( $this->has_registered_passkey_credentials( $user->ID ) ) {
			update_user_meta( $user->ID, 'rsssl_passkey_configured', 'configured' );
		}
	}

	public function is_two_fa_enabled(): bool {
		return (bool) rsssl_get_option('login_protection_enabled', false);
	}

	private function has_registered_passkey_credentials( int $user_id ): bool {
		// Stored credentials are the authoritative source when the status meta is out of sync.
		$credentials = Rsssl_Public_Credential_Resource::get_instance()->findAllForUserId( $user_id );
		return ! empty( $credentials );
	}
}
