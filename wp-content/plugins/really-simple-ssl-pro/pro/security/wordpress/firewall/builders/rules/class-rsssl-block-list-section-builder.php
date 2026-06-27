<?php
/**
 * class-rsssl-block-list-section-builder.php
 *
 * Builds the “Block List” section for the firewall rule,
 * outputting a line of PHP that explodes blocked IP addresses.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */

namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;
use RSSSL\Pro\Security\WordPress\Firewall\Models\Rsssl_404_Block;
use RSSSL\Pro\Security\WordPress\Limitlogin\Rsssl_IP_Fetcher;

/**
 * Class Rsssl_Block_List_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_Block_List_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {

	/**
	 * Builds the “Block List” section.
	 */
	public function build(): string
	{
	    $ips = $this->getBlockedIpsList();
		// Export the array as PHP code
		$arrayCode = var_export($ips, true);

		return <<<PHP
			\$blocked_ips = $arrayCode;
			PHP;
	}

	/**
	 * Retrieve list of blocked IP addresses.
	 * Validates IP addresses to prevent code injection.
	 */
	private function getBlockedIpsList(): array
	{
		$ips = ( new Rsssl_404_Block() )->get_blocked_ips(['ip_address']);
		$ip_fetcher = new Rsssl_IP_Fetcher();

		return array_filter(
		    array_map(
		        static function($i) use ( $ip_fetcher ) {
		            $ip = $i->ip_address ?? null;
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
	}

	/**
	 * Returns the marker for this section builder.
	 */
	public function getMarker(): string
	{
		return 'Block List Section';
	}
}