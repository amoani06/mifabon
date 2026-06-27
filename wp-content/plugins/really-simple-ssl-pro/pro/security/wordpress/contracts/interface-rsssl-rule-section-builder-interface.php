<?php
/**
 * Interface Rsssl_Rule_Section_Builder_Interface
 *
 * Provides a contract for constructing individual rule sections in the Really Simple SSL Pro plugin.
 *
 * Why this interface exists:
 *   - To separate the building of security rule segments from their registration and execution,
 *     enabling each feature within the firewall (e.g., user-agents, 404 blocker, country blocker and ip blocker)
 *     to define its own section logic.
 *
 * When to use:
 *   - Implement this interface when creating a new rule section for a specific firewall security feature.
 *
 * Current usage:
 *   - Section builders implementing this interface are registered via the `Rules Section Builder`
 *     and invoked during the plugin's security initialization process.
 *
 * @package Really-Simple-SSL
 */
namespace RSSSL\Pro\Security\WordPress\Contracts;

interface Rsssl_Rule_Section_Builder_Interface {
	public function build(): string;
	public function getMarker(): string;
}