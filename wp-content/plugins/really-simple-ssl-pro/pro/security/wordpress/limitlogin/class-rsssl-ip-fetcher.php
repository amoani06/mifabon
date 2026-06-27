<?php
/**
 * Class Rsssl_IP_Fetcher
 *
 * The Rsssl_IP_Fetcher class is used to retrieve a list of unique and validated IP addresses from various headers.
 *
 * @package Really_Simple_SSL
 * @company Really Simple Plugins
 * @author Really Simple Plugins
 */

namespace RSSSL\Pro\Security\WordPress\Limitlogin;

use const FILTER_FLAG_NO_PRIV_RANGE;
use const FILTER_FLAG_NO_RES_RANGE;
use const FILTER_VALIDATE_IP;

/**
 * The list of headers to check for IP addresses.
 *
 * @var array
 */
if ( ! class_exists( 'Rsssl_IP_Fetcher' ) ) {
	class Rsssl_IP_Fetcher {
		const IPV4_MAX_MASK = 32;
		const IPV6_MAX_MASK = 128;

		/**
		 * The list of headers to check for IP addresses.
		 *
		 * @var array
		 */
		private $headers
			= array(
				'HTTP_CF_CONNECTING_IP',
				'HTTP_TRUE_CLIENT_IP',
				'HTTP_X_CLUSTER_CLIENT_IP',
				'HTTP_CLIENT_IP',
				'HTTP_X_FORWARDED',
				'HTTP_X_REAL_IP',
				'HTTP_FORWARDED_FOR',
				'HTTP_FORWARDED',
				'HTTP_X_FORWARDED_FOR',
				'REMOTE_ADDR',
			);

		/**
		 * The list of CloudFlare networks.
		 *
		 * TODO: Discuss with the team and implement the method and how to get the ip addresses and not using a static list.
		 *
		 * @var array
		 */
		private $cloudflare_networks = array();

		/**
		 * The list of Securi networks.
		 *
		 *  TODO: Discuss with the team and implement the method and how to get the ip addresses and not using a static list.
		 *
		 * @var array
		 * @source https://docs.sucuri.net/website-firewall/sucuri-firewall-troubleshooting-guide/
		 */
		private $securi_networks
			= array(
				'192.88.134.0/23',
				'185.93.228.0/22',
				'66.248.200.0/22',
				'208.109.0.0/22',
				'2a02:fe80::/29',
			);

		/**
		 * Retrieves the IP address of the client.
		 *
		 * This method first checks for specific headers in the $_SERVER variable
		 * to prioritize certain IP addresses. If any of the prioritized headers
		 * contain a valid IP address, that address is returned.
		 *
		 * If none of the prioritized headers have a valid IP address, the method
		 * falls back to checking other headers specified in the $headers property.
		 * The headers are checked in the order they are added to the $headers property.
		 *
		 * Each header value is checked for multiple IP addresses separated by commas.
		 * Each IP address is validated and added to the list of validated IP addresses,
		 * ensuring no duplicate IP addresses are included.
		 *
		 * @return array An array of validated IP addresses, or an empty array if
		 *               no valid IP addresses were found.
		 */
		public function get_ip_address(): array {
			// Prioritize certain headers.
			$prioritized_headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );

			foreach ( $prioritized_headers as $header ) {
				//phpcs:ignore
				if ( isset( $_SERVER[ $header ] ) && $this->is_valid_ip( $_SERVER[ $header ] ) ) {
					//phpcs:ignore
					return array( $_SERVER[ $header ] );
				}
			}

			// If none of the prioritized headers have been found, we run the code again to check all headers.
			$validated_ips = array();
			foreach ( $this->headers as $header ) {
				if ( isset( $_SERVER[ $header ] ) ) {
					// phpcs:ignore
					$ips = explode( ',', str_replace( ' ', '', $_SERVER[ $header ] ) );
					foreach ( $ips as $ip ) {
						$ip = trim( $ip );
						if ( $this->is_valid_ip( $ip ) && ! in_array( $ip, $validated_ips, true ) ) {
							$validated_ips[] = $ip;
						}
					}
				}
			}

			return $validated_ips;
		}

		/**
		 * Validates an IP address.
		 * Checks if the IP address is valid.
		 *
		 * @param string $ip The IP address to validate.
		 *
		 * @return bool
		 */
		public function is_valid_ip( string $ip ): bool {
			return filter_var( $ip, FILTER_VALIDATE_IP );
		}

		/**
		 * Groups IP-addresses based on their format: CIDR, IPv4 and IPv6.
		 *
		 * @param array $ips The list of grouped ip-addresses.
		 *
		 * @return array An array og grouped IP-addresses set by the keys 'cidr', 'ipv4' and 'ipv6'.
		 */
		public function group_ips_by_type( array $ips ): array {
			// let's filter out the IP addresses that are in CIDR format
			$cidr_ips = [];
			$ipv4_ips = [];
			$ipv6_ips = [];

			foreach ( $ips as $ip ) {
				// Check for CIDR-formatted IPv4 addresses.
				if ( $this->isCIDR( $ip ) ) {
					$cidr_ips[] = $ip;
				} // Validate plain IPv4 addresses.
				else if ( $this->determine_ipv4_or_v6( $ip ) === 'IPv4' ) {
					$ipv4_ips[] = $ip;
				} // Validate IPv6 addresses.
				else if ( $this->determine_ipv4_or_v6( $ip ) === 'IPv6' ) {
					$ipv6_ips[] = $ip;
				}
			}

			return [
				'cidr' => $cidr_ips,
				'ipv4' => $ipv4_ips,
				'ipv6' => $ipv6_ips,
			];
		}

		/**
		 * Checks if an IP address is in CIDR format.
		 *
		 * @param string $ip
		 *
		 * @return bool
		 */
		public function isCIDR( string $ip ): bool {
			// Check if the IP contains a slash
			if ( strpos( $ip, '/' ) === false ) {
				return false;
			}

			// Split the string into address and mask parts.
			list( $address, $mask ) = explode( '/', $ip, 2 );

			// Validate that the address is a valid IP.
			if ( ! filter_var( $address, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			// Determine whether it's IPv4 or IPv6 and validate the mask range.
			if ( $this->determine_ipv4_or_v6( $address ) === 'IPv4' ) {
				return is_numeric( $mask ) && $mask >= 0 && $mask <= self::IPV4_MAX_MASK;
			}

			if ( $this->determine_ipv4_or_v6( $address ) === 'IPv6' ) {
				return is_numeric( $mask ) && $mask >= 0 && $mask <= self::IPV6_MAX_MASK;
			}

			return false;
		}


		/**
		 *  Determines if an IP address is IPv4 or IPv6.
		 */
		public function determine_ipv4_or_v6( string $ip ): string {
			// Check if the IP address is IPv4 or IPv6.
			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return 'IPv4';
			}

			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
				return 'IPv6';
			}

			// If the IP address is neither IPv4 nor IPv6, return false.
			return 'Unknown';
		}


		/**
		 * Checks if an IP address is in a given list of IP addresses or CIDR ranges.
		 *
		 * @return bool Returns true if the IP address is in the list, false otherwise.
		 */
		public function is_ip_address_in_range( array $ips, $ip ): bool {
			// Check if the IP address is in the list of IP addresses.
			$grouped_ips = $this->group_ips_by_type( $ips );

			// What type of IP address is it?
			$ip_type = $this->determine_ipv4_or_v6( $ip );

			// Validating if the cidr is set and is an array.
			if ( !isset( $grouped_ips['cidr'] ) || !is_array( $grouped_ips['cidr'] ) ) {
				$grouped_ips['cidr'] = [];
			}
			// Let's check if the IP address is in the list of cidr addresses.
			$matches = array_filter( $grouped_ips['cidr'], function ( $cidr ) use ( $ip, $ip_type ) {
				return $this->is_ip_in_cidr( $ip, $cidr, $ip_type );
			} );
			// If we have any matches, we can return true.
			if ( count( $matches ) > 0 ) {
				return true;
			}


			// Check if the IP address is in the list of IPv4 addresses.
			if ( ( $ip_type === 'IPv4' ) && in_array( $ip, $grouped_ips['ipv4'], true ) ) {
				return true;
			}

			// Check if the IP address is in the list of IPv6 addresses.
			if ( ( $ip_type === 'IPv6' ) && in_array( $ip, $grouped_ips['ipv6'], true ) ) {
				return true;
			}

			return false;
		}

		/**
		 * Checks if an IP address is in a given CIDR range.
		 *
		 * @return bool Returns true if the IP address is in the CIDR range, false otherwise.
		 */
		public function is_ip_in_cidr( string $ip, string $cidr, string $ip_type ): bool {
			// Validate the IP address.
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			// Split the CIDR into subnet and mask.
			[ $subnet, $mask ] = explode( '/', $cidr );
			$mask = (int) $mask;
			// Prevent negative or out-of-range masks.
			if ( ( $ip_type === 'IPv4' && ( $mask < 0 || $mask > self::IPV4_MAX_MASK ) ) ||
			     ( $ip_type === 'IPv6' && ( $mask < 0 || $mask > self::IPV6_MAX_MASK ) ) ) {
				return false;
			}

			// Prevent negative or out-of-range masks.
			if ( ( $ip_type === 'IPv4' && ( $mask < 0 || $mask > self::IPV4_MAX_MASK ) ) ||
			     ( $ip_type === 'IPv6' && ( $mask < 0 || $mask > self::IPV6_MAX_MASK ) ) ) {
				return false;
			}

			if ( $ip_type === 'IPv4' ) {
				// For IPv4, use ip2long.
				return ( ip2long( $ip ) & ~( ( 1 << ( 32 - $mask ) ) - 1 ) ) === ip2long( $subnet );
			}

			if ( $ip_type === 'IPv6' ) {
				// Convert addresses to binary.
				$ipBin     = inet_pton( $ip );
				$subnetBin = inet_pton( $subnet );
				if ( $ipBin === false || $subnetBin === false || strlen( $ipBin ) !== strlen( $subnetBin ) ) {
					return false;
				}
				// Calculate the number of full bytes and remaining bits to compare.
				$bytes = intdiv( $mask, 8 );
				$bits  = $mask % 8;
				// Compare full bytes.
				if ( strncmp( $ipBin, $subnetBin, $bytes ) !== 0 ) {
					return false;
				}
				// Compare remaining bits if necessary.
				if ( $bits > 0 ) {
					$maskBin = chr( 0xFF << ( 8 - $bits ) & 0xFF );
					if ( ( ord( $ipBin[ $bytes ] ) & ord( $maskBin ) ) !== ( ord( $subnetBin[ $bytes ] ) & ord( $maskBin ) ) ) {
						return false;
					}
				}

				return true;
			}

			return false;
		}


		// Helper function to match IP address with CIDR.

		/**
		 * Performs a CIDR match to check if an IP address falls within a given subnet.
		 *
		 * @param string $ip The IP address to check.
		 * @param string $cidr The CIDR notation representing the subnet to match against.
		 *
		 * @return bool Returns true if the IP address matches the subnet, false otherwise.
		 */
		public function cidr_match( string $ip, string $cidr ): bool {
			[ $subnet, $mask ] = explode( '/', $cidr );

			return ( ip2long( $ip ) & ~( ( 1 << ( 32 - $mask ) ) - 1 ) ) === ip2long( $subnet );
		}

		/**
		 * Fetches the IP address of the client making the request.
		 *
		 * This method takes into account various proxy or firewall configurations
		 * that might be present in the client's network environment. It does so
		 * by examining various HTTP headers that might contain the true IP address
		 * of the client.
		 *
		 * The following order of precedence is observed:
		 *
		 *   1. CloudFlare headers - Checks if 'HTTP_CF_CONNECTING_IP' is present.
		 *   2. Securi Firewall headers - Checks if 'HTTP_X_FORWARDED_FOR' is present
		 *      and the IP is not part of private or reserved IP ranges.
		 *   3. Local Proxy servers - Checks if 'HTTP_X_REAL_IP' is present
		 *      and the IP is not part of private or reserved IP ranges.
		 *      If not found, checks 'HTTP_X_FORWARDED_FOR',
		 *      and ensures the IP is not the same as the server IP.
		 *   4. Fallback - Uses the 'REMOTE_ADDR' header as is.
		 *
		 * All IP addresses are validated to ensure they are a valid format before
		 * they are returned. If no valid IP address is found in any of the
		 * checked headers, an empty string is returned.
		 *
		 * NOTE: This method is not yet implemented in the codebase. and needs to be discussed with the team.
		 * TODO: Discuss with the team and implement the method.
		 *
		 * @return string Returns the IP address of the client. If no valid IP
		 *                address is found, an empty string is returned.
		 */
		public function fetch_ip(): string {
			// CloudFlare service check.
			$this->update_network_lists();
			// phpcs:ignore
			if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && filter_var( $_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP ) ) {
				// phpcs:ignore
				foreach ( $this->cloudflare_networks as $network ) {
					// phpcs:ignore
					if ( $this->cidr_match( $_SERVER['REMOTE_ADDR'], $network ) ) {
						// phpcs:ignore
						return $this->is_valid_ip( $_SERVER['HTTP_CF_CONNECTING_IP'] );
					}
				}
			}

			// Securi Firewall check.
			// phpcs:ignore
			if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && filter_var( $_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				foreach ( $this->securi_networks as $network ) {
					// phpcs:ignore
					if ( $this->cidr_match( $_SERVER['REMOTE_ADDR'], $network ) ) {
						// phpcs:ignore
						return $this->is_valid_ip( $_SERVER['HTTP_X_FORWARDED_FOR'] );
					}
				}
			}

			// local reverse proxy server check.
			// phpcs:ignore
			if ( ! filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				//phpcs:ignore
				if ( isset( $_SERVER['HTTP_X_REAL_IP'] ) && filter_var( $_SERVER['HTTP_X_REAL_IP'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
					//phpcs:ignore
					return $this->is_valid_ip( $_SERVER['HTTP_X_REAL_IP'] );
				}

				if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
					//phpcs:ignore
					$server_ip = $_SERVER['SERVER_ADDR'] ?? '';
					//phpcs:ignore
					$ip = trim( current( explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
					//phpcs:ignore
					if ( $ip !== $server_ip && filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
						return $ip;
					}
				}
			}

			//phpcs:ignore
			return $this->is_valid_ip( $_SERVER['REMOTE_ADDR'] );
		}

		/**
		 * Fetches and updates the list of cloudflare and securi networks.
		 *
		 * @return void
		 */
		public function update_network_lists(): void {
			$opts    = array(
				'http' =>
					array(
						'method'        => 'GET',
						'ignore_errors' => 1,
					),
			);
			$context = stream_context_create( $opts );

			// Fetch the list of CloudFlare and Securi networks.
			// phpcs:ignore
			$cloudflare_ipv4 = file_get_contents( 'https://www.cloudflare.com/ips-v4', false, $context );
			//phpcs:ignore
			$cloudflare_ipv6 = file_get_contents( 'https://www.cloudflare.com/ips-v6', false, $context );

			if ( false === $cloudflare_ipv4 || false === $cloudflare_ipv6 ) {
				// TODO: Discuss how to handle errors.
				return;
			}

			$cloudflare_ips = array_merge(
				explode( "\n", trim( $cloudflare_ipv4 ) ),
				explode( "\n", trim( $cloudflare_ipv6 ) )
			);

			// Securi IPs do not have an API like Cloudflare, so we need to fetch it from the database.
			// TODO: Discuss with the team and implement the method.
			// $securi_ips = array(); // Replace with the method to fetch Securi's IP list.

			$this->cloudflare_networks = $cloudflare_ips;

			// phpcs:ignore
			// $this->securi_networks = $securi_ips;
		}
	}
}
