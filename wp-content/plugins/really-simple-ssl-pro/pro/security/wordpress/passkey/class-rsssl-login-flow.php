<?php

namespace RSSSL\Pro\Security\WordPress\Passkey;

final class Rsssl_Login_Flow {
	public const PASSKEY_REQUIRED          = 'passkey_required';
	public const PASSKEY_OPTIONAL          = 'passkey_optional';
	public const FORCE_PASSKEY_ENROLLMENT  = 'force_passkey_enrollment';
	public const TWO_FA_REQUIRED           = 'two_fa_required';
	public const TWO_FA_OPTIONAL           = 'two_fa_optional';
	public const LOCKED_OUT                = 'locked_out'; // reserve
}