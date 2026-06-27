<?php
/**
 * class-rsssl-plugin-validation-section-builder.php
 *
 * Builds the “Plugin Validation” section for the firewall rule,
 * outputting PHP code to validate and include the plugin directory.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */

namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;

/**
 * Class Rsssl_Plugin_Validation_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_Plugin_Validation_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {
    /**
     * Builds the Plugin Validation section.
     *
     * @return string PHP code for plugin validation, or empty if disabled.
     */
    public function build(): string
    {
        return $this->buildPluginValidationSection();
    }

    /**
     * Builds the plugin validation section.
     *
     * @return string PHP code for plugin validation, or empty if not configured.
     */
    private function buildPluginValidationSection(): string
    {
        if (! defined( 'rsssl_plugin' )) {
            return '';
        }

        $pluginDir = dirname( rsssl_plugin );
        if ( empty( $pluginDir ) ) {
            return '';
        }

        return <<<PHP
		\$plugin_dir = __DIR__ . "/plugins/$pluginDir";
		if (! file_exists(\$plugin_dir)) {
		    return;
		}
		PHP;
    }

	/**
	 * Returns the marker for this section builder.
	 *
	 * @return string Marker for the Plugin Validation section.
	 */
	public function getMarker(): string
	{
		return 'Plugin Validation Section';
	}
}
