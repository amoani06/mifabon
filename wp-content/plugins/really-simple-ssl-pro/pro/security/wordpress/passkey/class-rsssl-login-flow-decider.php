<?php

namespace RSSSL\Pro\Security\WordPress\Passkey;

use RSSSL\Pro\Security\WordPress\Passkey\Capability\Rsssl_Passkey_Capability;
use RSSSL\Pro\Security\WordPress\Passkey\Policy\Rsssl_Secure_Auth_Policy;
use WP_User;

class Rsssl_Login_Flow_Decider {
	private Rsssl_Secure_Auth_Policy $policy;
	private Rsssl_Passkey_Capability $cap;
	private Rsssl_Skip_Strategy $skip;

	public function __construct(
		Rsssl_Secure_Auth_Policy $policy,
		Rsssl_Passkey_Capability $cap,
		Rsssl_Skip_Strategy $skip
	) {
		$this->skip   = $skip;
		$this->cap    = $cap;
		$this->policy = $policy;
	}

	/**
	 * Decide the login flow for the given user.
	 * @return array{flow:string, show_skip:bool, use_2fa_ui:bool}
	 */
	public function decide(WP_User $user): array
	{
		$enforced    = $this->policy->is_enforced_for_user($user);
		$lockedOut   = $this->policy->is_user_locked_out($user);
		$passkeyOn   = $this->cap->is_feature_enabled();
		$hasPasskey  = $this->cap->user_has_registered_passkey($user);
		$isToday     = $this->policy->grace_period_expires_today($user);
		$graceActive = $this->policy->is_grace_active_for_user($user);

		if ($enforced) {
			return $this->decideEnforced($user, $lockedOut, $passkeyOn, $hasPasskey, $isToday, $graceActive);
		}

		return $this->decideNotEnforced($user, $passkeyOn, $isToday, $graceActive);
	}

	/**
	 * Build the decision array.
	 */
	private function buildDecision(
		string $flow,
		bool $showSkip,
		?bool $isForced,
		bool $isToday,
		$graceActive,
		int $gracePeriod = 0
	): array
	{
		$decision = [
			'flow'         => $flow,
			'show_skip'    => $showSkip,
			'is_today'     => $isToday,
			'grace_period' => $gracePeriod,
		];

		if ($isForced !== null) {
			$decision['is_forced'] = $isForced;
		}

		return $decision;
	}

	/**
	 * Enforced login policy path.
	 */
	private function decideEnforced(
		WP_User $user,
		bool $lockedOut,
		bool $passkeyOn,
		bool $hasPasskey,
		bool $isToday,
		$graceActive
	): array {
		if ($lockedOut) {
			return [ 'flow' => Rsssl_Login_Flow::LOCKED_OUT ];
		}

		$showSkip = $this->skip->can_show_skip($user, true, $graceActive);
		$daysLeft = $this->policy->get_grace_period_days_left($user);
		// Passkey standalone enforced
		if ($passkeyOn) {
			if ($hasPasskey) {
				return $this->buildDecision(
					Rsssl_Login_Flow::PASSKEY_REQUIRED,
					$showSkip,
					true,
					$isToday,
					$graceActive,
					$daysLeft
				);
			}
			// Enforce enrollment
			return $this->buildDecision(
				Rsssl_Login_Flow::FORCE_PASSKEY_ENROLLMENT,
				$showSkip,
				true,
				$isToday,
				$graceActive,
				$daysLeft
			);
		}

		return $this->buildDecision(
			Rsssl_Login_Flow::PASSKEY_OPTIONAL,
			$showSkip,
			false,
			false,
			false,
			0
		);
	}

	/**
	 * None-enforced path.
	 */
	private function decideNotEnforced(
		WP_User $user,
		bool $passkeyOn,
		bool $isToday,
		$graceActive
	): array {
		$showSkip = $this->skip->can_show_skip($user, false, false);

		if ($passkeyOn) {
			return $this->buildDecision(
				Rsssl_Login_Flow::PASSKEY_OPTIONAL,
				$showSkip,
				null,
				$isToday,
				$graceActive
			);
		}
		return [
			'flow'         => Rsssl_Login_Flow::PASSKEY_OPTIONAL,
			'show_skip'    => $showSkip,
			'is_today'     => false,
			'grace_period' => 0,
		];
	}
}