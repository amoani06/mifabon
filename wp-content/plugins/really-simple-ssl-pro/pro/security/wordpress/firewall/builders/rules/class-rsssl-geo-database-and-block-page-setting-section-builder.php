<?php
/**
 * class-rsssl-geo-database-and-block-page-setting-section-builder.php
 *
 * Builds the Geo Database, Block Page, and 404 Handler sections for the firewall rules,
 * outputting PHP code blocks based on configuration.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */

namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;

/**
 * Class Rsssl_Geo_Database_And_Block_Page_Setting_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_Geo_Database_And_Block_Page_Setting_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {
    /**
     * Builds all sections for geo database, block page, and 404 handler.
     */
    public function build(): string
    {
        $sections = array_filter([
            $this->buildGeoDatabaseSection(),
            $this->buildBlockPageSection(),
           // $this->build404HandlerSection(),
        ]);

        return implode(PHP_EOL, $sections);
    }

    /**
     * Builds the Geo Database section.
     */
    private function buildGeoDatabaseSection(): string
    {
        $dbFile = is_multisite()
            ? get_site_option('rsssl_geo_ip_database_file')
            : get_option('rsssl_geo_ip_database_file');
        if (empty($dbFile)) {
            return '';
        }

        return <<<PHP
		\$geo_database_file = "$dbFile";
		if (! file_exists(\$geo_database_file)) {
		    return;
		}
		PHP;
    }

    /**
     * Builds the Block Page section.
     */
    private function buildBlockPageSection(): string
    {
        $blockPage = rsssl_get_template('403-page.php', rsssl_path . 'pro/assets/templates');
        $iconUrl = defined( 'rsssl_url' ) ? trailingslashit( rsssl_url ) . 'pro/assets/templates/security.png' : '';
        if (empty($blockPage)) {
            return '';
        }

        return <<<PHP
		\$block_page = "$blockPage";
		\$icon_url = "$iconUrl";
		if (! file_exists(\$block_page)) {
		    return;
		}
		PHP;
    }

    /**
     * Builds the 404 Handler section.
     */
    private function build404HandlerSection(): string
    {
        if (! defined('rsssl_path')) {
            return '';
        }
        $handlerFile = rsssl_path . 'pro/security/wordpress/firewall/404-detection.php';
        if (! file_exists($handlerFile)) {
            return '';
        }

        return <<<PHP
		\$handler_file_404 = "$handlerFile";
		if ( ( ! defined( 'WP_CLI' ) || ! WP_CLI ) &&
		     ( ! defined( 'DOING_CRON' ) || ! DOING_CRON ) &&
		     PHP_SAPI !== 'cli' &&
		     file_exists( "\$handler_file_404" ) ) {
		    return;
		}
		PHP;
    }

	/**
	 * Returns the marker for this section builder.
	 */
	public function getMarker(): string
	{
		return 'Geo Database and Block Page Setting Section';
	}
}
