<?php

if ( ( defined( "RSSSL_DISABLE_REGION_BLOCK" ) && RSSSL_DISABLE_REGION_BLOCK ) || (defined( 'RSSSL_SAFE_MODE' ) && RSSSL_SAFE_MODE)  || ! file_exists( $plugin_dir ) ) {
	return;
}

/**
 * Checks if the current request is from a Google crawler
 *
 * @param string $ip_address The IP address to check
 * @param string $user_agent The user agent string
 * @param string $country_code The country code where the IP is located
 * @return bool Whether the IP belongs to a Google crawler
 */
function rsssl_is_google_crawler(string $ip_address, string $user_agent, string $country_code, string $plugin_dir, string $uploads_dir): bool {
	// Initialize IP fetcher
	$ip_fetcher = new \RSSSL\Pro\Security\WordPress\Limitlogin\Rsssl_IP_Fetcher();

	// Only check Google crawlers from the US
	if ($country_code !== 'US') {
		return false;
	}

	// Check if the user agent contains Google-related strings
	if (empty($user_agent) ||
	    (stripos($user_agent, 'googlebot') === false &&
	     stripos($user_agent, 'google') === false)) {
		return false;
	}

	// Validate IP
	if (!$ip_fetcher->is_valid_ip($ip_address)) {
		return false;
	}

	// Define path to IP data file
	$ip_data_file = $uploads_dir . '/really-simple-ssl/google-ip-data/google_crawler_ips.json';

	// Check if file exists
	if (!file_exists($ip_data_file)) {
		return true; // Allow possible Google crawlers if we can't verify
	}

	// Load Google IP ranges from file
	$google_ips_json = file_get_contents($ip_data_file);
	$google_ips = json_decode($google_ips_json, true);

	// Check if file data is valid
	if (empty($google_ips) || empty($google_ips['cidr'])) {
		return true; // Allow possible Google crawlers if we can't verify
	}

	// Simply use the IP fetcher to check if the IP is in any of the ranges
	return $ip_fetcher->is_ip_address_in_range($google_ips['cidr'], $ip_address);
}

/**
 * Blocks or allows access based on the country of the visitor's IP address.
 *
 * @param  array  $countries_blocked  An array of country codes representing the countries to block.
 * @param  array  $white_list  An array of IP addresses to whitelist, allowing access regardless of country.
 * @param  string  $geo_database_file  The path to the IP-to-country database file.
 *
 * @return bool Whether access should be blocked (true) or allowed (false) based on the visitor's country.
 */
function rsssl_block_countries( array $blocked_countries, array $white_list, string $geo_database_file, string $plugin_dir, string $country_detection_file, $ip_fetcher_file, $uploads_dir ): bool {
	// Skip when running via WP-CLI
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		return false;
	}

	// Skip when running via server cron (CLI)
	if ( PHP_SAPI === 'cli' ) {
		return false;
	}

	// Skip country blocking if the WordPress Cron is running.
	if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
		return false;
	}

	require_once $country_detection_file;
	require_once $ip_fetcher_file;

	$ip_fetcher = new RSSSL\Pro\Security\WordPress\Limitlogin\Rsssl_IP_Fetcher();
	$ip_address = $ip_fetcher->get_ip_address()[0] ?? false;

	// If there is no IP address, we can't determine the country.
	if ( empty( $ip_address ) ) {
		error_log("No ip address found, skipping country block.");
		return false;
	}

	$country_code = RSSSL\Pro\Security\WordPress\Limitlogin\Rsssl_Country_Detection::get_country_by_ip_headers( $geo_database_file, $ip_address );

	$is_blocked = in_array( $country_code, $blocked_countries, true );

	$is_whitelisted = $ip_fetcher->is_ip_address_in_range( $white_list, $ip_address );

	// Check if this is a Google crawler (only if IP is from a blocked country and not already whitelisted)
	$is_google_crawler = false;

	if ($is_blocked && !$is_whitelisted) {
		$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$is_google_crawler = rsssl_is_google_crawler($ip_address, $user_agent, $country_code, $plugin_dir, $uploads_dir);
	}

	// Block only if the country is blocked AND the IP is not whitelisted AND not a Google crawler
	return $is_blocked && !$is_whitelisted && !$is_google_crawler;
}

if ( isset( $blocked_countries, $white_list, $geo_database_file, $plugin_dir, $country_detection_file, $ip_fetcher_file, $uploads_dir ) &&
     rsssl_block_countries( $blocked_countries, $white_list, $geo_database_file, $plugin_dir, $country_detection_file, $ip_fetcher_file, $uploads_dir ) ) {
	$dir       = dirname( __DIR__, 3 );
	$block_url = "$dir/assets/templates/403-page.php";
	http_response_code( 403 );
	require_once $block_url;
	exit;
}

// Skip when running via WP-CLI
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	return false;
}

// Skip when running via server cron (CLI)
if ( PHP_SAPI === 'cli' ) {
	return false;
}

// Skip when running WordPress cron
if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
	return false;
}