<?php
/**
 * class-rsssl-user-agent-section-builder.php
 *
 * Builds the “User Agent” section for the firewall rule,
 * outputting a list of blocked user agents and including the handler file.
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */

namespace RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;
use RSSSL\Pro\Security\WordPress\Firewall\Models\Rsssl_User_Agent_Block;

/**
 * Class Rsssl_User_Agent_Section_Builder
 *
 * @package RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules
 */
class Rsssl_User_Agent_Section_Builder implements Rsssl_Rule_Section_Builder_Interface {

	/**
	 * Builds the User Agent section.
	 * @throws \JsonException
	 */
	public function build(): string
	{
		return $this->buildUserAgentSection();
	}

	/**
	 * Builds the user agent section body.
	 */
	private function buildUserAgentSection(): string
	{
		if ( ! defined( 'rsssl_path' ) ) {
			return '';
		}

		$blockedAgents = $this->getBlockedAgents();
		if ( empty( $blockedAgents ) ) {
			return '';
		}

		$userAgentDetectionFile = rsssl_path . 'pro/security/wordpress/firewall/class-rsssl-user-agent-handler.php';

		$handlerFile  = rsssl_path . 'pro/security/wordpress/firewall/user-agent.php';
		$agentsString = json_encode( array_map(
			static fn( $agent ): string => is_object( $agent ) && isset( $agent->user_agent )
				? $agent->user_agent
				: (string) $agent,
			$blockedAgents
		), JSON_THROW_ON_ERROR | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_UNESCAPED_SLASHES );

		return <<<PHP
// Needed for User Agent detection
\$userAgentDetectionFile = '$userAgentDetectionFile';

\$blocked_user_agents = $agentsString;
if ( ( ! defined( 'WP_CLI' ) || ! WP_CLI ) &&
     ( ! defined( 'DOING_CRON' ) || ! DOING_CRON ) &&
     PHP_SAPI !== 'cli' &&
     file_exists("$handlerFile") ) {
	require_once "$handlerFile";
}
PHP;
	}

	/**
	 * Retrieves the list of blocked user agents.
	 *
	 * @return string[] List of blocked user agent strings.
	 */
	private function getBlockedAgents(): array
	{
		return ( new Rsssl_User_Agent_Block() )->get_agent_list();
	}

	/**
	 * Returns the marker for this section builder.
	 *
	 * @return string Marker for the User Agent section.
	 */
	public function getMarker(): string
	{
		return 'User Agent Section';
	}

}