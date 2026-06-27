<?php
/**
 * class-rsssl-ip-fetcher-section-builder.php
 *
 * Builds the “IP Fetcher” section for the firewall rule,
 * outputting PHP code to include the IP fetcher handler.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;

/**
 * Class Rsssl_Ip_Fetcher_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_Ip_Fetcher_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {

    /**
     * Builds the Variables needed for Access restrictions section.
     *
     * @return string PHP code for IP fetcher inclusion, or empty if disabled.
     */
    public function build(): string
    {
        return $this->buildIpFetcherSection();
    }

    /**
     * Builds the IP Fetcher section.
     *
     * @return string PHP code for IP fetcher inclusion, or empty if not configured.
     */
    private function buildIpFetcherSection(): string
    {
        if (! defined( 'rsssl_path' )) {
            return '';
        }

        $file = rsssl_path . 'pro/security/wordpress/limitlogin/class-rsssl-ip-fetcher.php';

        return <<<PHP
		\$ip_fetcher_file = "$file";
		if (! file_exists(\$ip_fetcher_file)) {
		    return;
		}
		PHP;
    }

	/**
	 * Returns the marker for this section builder.
	 *
	 * @return string Marker for the IP Fetcher section.
	 */
	public function getMarker(): string
	{
		return 'IP Fetcher Section';
	}
}