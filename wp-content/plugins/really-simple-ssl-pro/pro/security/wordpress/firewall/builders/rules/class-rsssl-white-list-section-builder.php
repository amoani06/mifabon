<?php
/**
 * class-rsssl-white-list-section-builder.php
 *
 * Builds the “White List” section for the firewall rules,
 * outputting PHP code to define a list of whitelisted IP addresses.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

/**
 * Interface for building sections of firewall rules.
 */
use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;
use RSSSL\Pro\Security\WordPress\Limitlogin\Rsssl_IP_Fetcher;

/**
 * Builds the “White List” section.
 */
class Rsssl_White_List_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {
	public function build(): string {
	    $ips = $this->get_white_list();
	    $ip_fetcher = new Rsssl_IP_Fetcher();

	    // Extract, validate, and filter IP addresses
	    $list = array_filter(
	        array_map(
	            static function($i) use ( $ip_fetcher ) {
	                $ip = $i['ip_address'] ?? null;
	                if ( $ip === null ) {
	                    return null;
	                }

	                if ( ! $ip_fetcher->is_valid_ip( $ip ) && ! $ip_fetcher->isCIDR( $ip ) ) {
	                    return null;
	                }
	                return $ip;
	            },
	            $ips
	        )
	    );
	    // Export the array as PHP code
	    $arrayCode = var_export($list, true);

	    return <<<PHP
			\$white_list = $arrayCode;
			PHP;
	}

	/**
	 * Retrieves the white list of trusted IP addresses.
	 */
	private function get_white_list(): array {
		global $wpdb;
		$table_name   = $wpdb->base_prefix . 'rsssl_geo_block';
		$query_string = $wpdb->prepare(
			"SELECT ip_address FROM $table_name WHERE data_type = %s",
			'trusted'
		);
		// phpcs:ignore
		return  $wpdb->get_results( $query_string, ARRAY_A );
	}

	/**
	 * Returns the marker for this section builder.
	 */
	public function getMarker(): string {
		return 'White List Section';
	}
}