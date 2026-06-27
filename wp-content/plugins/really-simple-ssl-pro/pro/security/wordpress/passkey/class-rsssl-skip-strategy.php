<?php

namespace RSSSL\Pro\Security\WordPress\Passkey;

use WP_User;

class Rsssl_Skip_Strategy {
	public function can_show_skip(WP_User $user, bool $is_enforced, bool $is_in_gracePeriod): bool {
		if ($is_enforced) {
			// If the user is in a grace period, we can show the skip option.
			if ( $is_in_gracePeriod ) {
				return true;
			}
			// If the user has ignored the prompt before, we can show the skip option.
			if ($this->is_ignored($user)) {
				return true;
			}
			// Otherwise, we cannot show the skip option.
			return false;
		}
		return true;
	}

	public function mark_ignored(WP_User $user): void {
		update_user_meta($user->ID, 'rsssl_passkey_configured', 'ignored');
	}

	public function is_ignored(WP_User $user): bool {
		return get_user_meta($user->ID, 'rsssl_passkey_configured', true) === 'ignored';
	}
}