<?php
/**
 * class-rsssl-debug-section-builder.php
 *
 * Builds the “Debug” section for the firewall rules,
 * outputting PHP ini_set and error_reporting calls when WP_DEBUG is enabled.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */

namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;

/**
 * Class Rsssl_Debug_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_Debug_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {

    /**
     * Builds the Debug section of the firewall rules.
     */
    public function build(): string
    {
        return <<<PHP
		ini_set("display_errors", 1);
		ini_set("display_startup_errors", 1);
		error_reporting(E_ALL);
		PHP;
    }

	/**
	 * Returns the marker for this section builder.
	 */
	public function getMarker(): string
	{
		return 'Debug Section';
	}
}