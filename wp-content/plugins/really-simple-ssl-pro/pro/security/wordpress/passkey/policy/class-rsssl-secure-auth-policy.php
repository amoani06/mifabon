<?php

namespace RSSSL\Pro\Security\WordPress\Passkey\Policy;

use RSSSL\Pro\Security\WordPress\Passkey\Capability\Rsssl_Passkey_Capability;
use RSSSL\Security\WordPress\Two_Fa\Rsssl_Two_Factor_Settings;
use WP_User;

class Rsssl_Secure_Auth_Policy {
	public function is_enforced_for_user(WP_User $user): bool {
		if ( ! $user->exists() ) {
			return false;
		}

		return Rsssl_Two_Factor_Settings::is_user_forced_to_use_2fa( $user->ID );
	}

	/**
	 * Return the number of days left in the grace period.
	 * If the grace period is over, return 0.
	 * If the user has never logged in before, set user meta and return the full grace period.
	 */
	public function get_grace_period_days_left(WP_User $user): int {
		$grace_period = rsssl_get_option( 'two_fa_grace_period');
		$last_login = get_user_meta( $user->ID, 'rsssl_two_fa_last_login', true );

		if ( $last_login ) {
			$last_login = strtotime( $last_login );
			$now        = time();
			$diff       = $now - $last_login;
			$days       = floor( $diff / ( 60 * 60 * 24 ) );

			if ( (int)$days < (int)$grace_period ) {
				$end_date = gmdate( 'Y-m-d', $last_login );
				// We add the grace period to the last login date.
				$end_date = date( 'Y-m-d', strtotime( $end_date . ' + ' . $grace_period . ' days' ) );
				$today = gmdate('Y-m-d', $now);
				// If the end date is today, return 1.
				if ($end_date === $today) {
					return 1;
				}
				return $grace_period - $days;
			}
			// it is now equal or greater, so return 0.
			return 0;
		}
		// if the last login is not set, return the grace period. but also set the user meta.
		update_user_meta( $user->ID, 'rsssl_two_fa_last_login', gmdate( 'Y-m-d H:i:s' ) );
		return $grace_period;
	}

	/**
	 * If the user is in a grace period, return true.
	 * Otherwise, return false.
	 */
	public function is_grace_active_for_user(WP_User $user): bool {
		return $this->get_grace_period_days_left($user) > 0;
	}

	/**
	 * Support function to check if the user is in the grace period for today.
	 */
	public function grace_period_expires_today( WP_User $user ): bool {
		return (1 === (int) $this->get_grace_period_days_left( $user ));
	}

	/**
	 * Check if the user is locked out.
	 * A user is locked out if they are enforced and the grace period is over.
	 */
	public function is_user_locked_out( WP_User $user ): bool
	{
		if ( ( new Rsssl_Passkey_Capability() )->user_has_registered_passkey( $user ) ) {
			return false;
		}
		// If the user is enforced and the grace period is over, they are locked out.
		$enforced = $this->is_enforced_for_user( $user );
		$grace    = $this->is_grace_active_for_user( $user );
		return $enforced && ( ! $grace );
	}
}
