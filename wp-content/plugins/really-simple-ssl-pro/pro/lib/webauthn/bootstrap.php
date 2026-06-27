<?php

if ( ! defined( 'RSSSL_PRO_WEBAUTHN_LIB_LOADED' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';

	// Composer deduplicates autoload_files globally via $__composer_autoload_files.
	// When another plugin has already loaded the same packages, our prefixed file-based
	// functions (notably RSSProVendor\Safe\*) can be skipped unless we require them here.
	$autoload_files = require __DIR__ . '/vendor/composer/autoload_files.php';
	foreach ( $autoload_files as $autoload_file ) {
		require_once $autoload_file;
	}

	define( 'RSSSL_PRO_WEBAUTHN_LIB_LOADED', true );
}
