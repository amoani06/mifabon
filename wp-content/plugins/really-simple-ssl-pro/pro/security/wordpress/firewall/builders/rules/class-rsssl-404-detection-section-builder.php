<?php
/**
 * class-rsssl-404-detection-section-builder.php
 *
 * Builds the “404 Detection” section for the firewall rule,
 * outputting PHP code to include the 404 detection handler if it exists.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */

namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;

/**
 * Class Rsssl_404_Detection_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_404_Detection_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {
	public function build(): string
	{
	    if (! defined( 'rsssl_path' )) {
	        return '';
	    }

	    $handler_file_404 = rsssl_path . 'pro/security/wordpress/firewall/404-detection.php';

		// Do not load 404 detection file during WP-CLI, server cron, or WP Cron jobs.
		// There's no IP address when running via cron/CLI, which causes issues
	    return <<<PHP
		if ( ( ! defined( 'WP_CLI' ) || ! WP_CLI ) &&
		     ( ! defined( 'DOING_CRON' ) || ! DOING_CRON ) &&
		     PHP_SAPI !== 'cli' &&
		     file_exists( "$handler_file_404" ) ) {
		    require_once "$handler_file_404";
		}
		PHP;
	}

	public function getMarker(): string {
		return '404 Detection Section';
	}
}