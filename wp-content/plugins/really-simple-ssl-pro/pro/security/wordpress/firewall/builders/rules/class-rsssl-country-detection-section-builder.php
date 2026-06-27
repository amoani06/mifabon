<?php
/**
 * class-rsssl-country-detection-section-builder.php
 *
 * Builds the “Country Detection” section for the firewall rule,
 * outputting PHP code to include the country detection handler when WP_DEBUG is enabled.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */

namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;
use RSSSL\Pro\Security\WordPress\Rsssl_Geo_Block;

/**
 * Class Rsssl_Country_Detection_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_Country_Detection_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {
    /**
     * Builds the Country Detection section of the firewall rules.
     */
    public function build(): string
    {
        if ( ! defined('rsssl_path')) {
            return '';
        }

        $file = rsssl_path . 'pro/security/wordpress/limitlogin/class-rsssl-country-detection.php';

        $geoBlockFile = rsssl_path . 'pro/security/wordpress/firewall/block-region.php';
        $uploadsDir   = wp_upload_dir()['basedir'];

        $countryCodes = $this->getBlockedCountryCodes();

        if (empty($countryCodes)) {
            return '';
        }

        $csv = implode(',', $countryCodes);

        return <<<PHP
		\$blocked_countries = explode(",", "$csv");
		\$country_detection_file = "$file";
		\$uploads_dir = "$uploadsDir";
		if ( ! file_exists( \$country_detection_file ) ) {
			return;
		}

		if ( ( ! defined( 'WP_CLI' ) || ! WP_CLI ) &&
			 ( ! defined( 'DOING_CRON' ) || ! DOING_CRON ) &&
			 PHP_SAPI !== 'cli' &&
			 file_exists("$geoBlockFile") ) {
			require_once "$geoBlockFile";
		}
		PHP;
    }

	/**
	 * Retrieves the ISO2 codes for blocked countries.
	 */
	private function getBlockedCountryCodes(): array
	{
		$settings = $this->get_blocked_countries_list();
		$codes = array_column( $settings, 'iso2_code' );
		$geo_block = Rsssl_Geo_Block::get_instance();

		return array_filter( $codes, static function( $code ) use ( $geo_block ) {
			return is_string( $code ) && $geo_block->is_valid_country_code( $code );
		});
	}

	private function get_blocked_countries_list() {
		global $wpdb;
		$table_name   = $wpdb->base_prefix . 'rsssl_geo_block';
		$query_string = $wpdb->prepare(
			"SELECT iso2_code FROM $table_name WHERE data_type = %s AND ip_address is NULL",
			'country'
		);

		return $wpdb->get_results( $query_string );

	}

	/**
	 * Returns the marker for this section builder.
	 */
	public function getMarker(): string
	{
		return 'Country Detection Section';
	}
}