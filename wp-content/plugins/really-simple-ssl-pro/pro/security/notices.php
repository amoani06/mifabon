<?php
defined( 'ABSPATH' ) or die();

function rsssl_premium_security_notices( $notices ) {
	global $wpdb;
	if ( $wpdb->base_prefix === 'wp_' && get_option('rsssl_db_prefix_rename_failed') ) {
		$notices['rename_db_failed'] = array(
			'condition' => [ 'wp_option_rsssl_db_prefix_rename_failed' ],
			'callback' => '_true_',
			'score' => 5,
			'output' => array(
				'true' => array(
					'msg'  => __( 'You have enabled the "Rename and randomize your database prefix" option, but the attempt to do this has failed. The option has been disabled.', "really-simple-ssl" ),
					'icon' => 'warning',
					'dismissible' => true,
				),
			),
			'show_with_options' => [
				'rename_db_prefix',
			],
		);
	}

	$notices['admin_registration_failed'] = array(
		'callback' => '_true_',
		'condition'  => array(
			'option_block_admin_creation',
			'NOT option_block_admin_creation_confirm',
		),
		'score' => 5,
		'output' => array(
			'true' => array(
				'highlight_field_id' => 'block_admin_creation',
				'msg' => __("Block admin creation was disabled, because the registration of admin users has failed.", "really-simple-ssl"),
				'icon' => 'warning',
				'dismissible' => false,
				'url' => 'knowledge-base/admin-registration-failed',
			),
		),
	);

	$notices['enable_two_fa'] = array(
		'callback' => 'option_login_protection_enabled',
		'score'    => 5,
		'output'   => array(
			'false' => array(
				'highlight_field_id' => 'login_protection_enabled',
				'msg'                => __( 'We recommend to enable Two-Factor Authentication at least for administrators.', 'really-simple-ssl' ),
				'icon'               => 'open',
				'admin_notice'       => false,
				'dismissible'        => true,
				'plusone'            => false,
			),
			'true'  => array(
				'msg'  => __( 'Two-Factor Authentication enabled for administrators.', 'really-simple-ssl' ),
				'icon' => 'success',
			),
		),
	);

	$notices['enable_lla'] = array(
		'callback' => 'option_enable_limited_login_attempts',
		'score'    => 5,
		'output'   => array(
			'false' => array(
				'highlight_field_id' => 'enable_limited_login_attempts',
				'msg'                => __( 'Enable Limit Login Attempts to protect the login form against brute-force attacks.', 'really-simple-ssl' ),
				'icon'               => 'open',
				'admin_notice'       => false,
				'dismissible'        => true,
				'plusone'            => false,
			),
			'true'  => array(
				'msg'  => __( 'Limit Login Attempts enabled.', 'really-simple-ssl' ),
				'icon' => 'success',
			),
		),
	);

	$notices['enable_firewall'] = array(
		'callback' => 'option_enable_firewall',
		'score'    => 5,
		'output'   => array(
			'false' => array(
				'highlight_field_id' => 'enable_firewall',
				'msg'                => __( 'Secure your site with the performant Firewall.', 'really-simple-ssl' ),
				'icon'               => 'open',
				'admin_notice'       => false,
				'dismissible'        => true,
				'plusone'            => false,
			),
			'true'  => array(
				'msg'  => __( 'Performant Firewall enabled.', 'really-simple-ssl' ),
				'icon' => 'success',
			),
		),
	);

	$notices['permalink_changed_to_plain_with_custom_login_url'] = array(
		'callback'  => 'wp_option_rsssl_permalink_changed_to_plain',
		'score'     => 5,
		'output'    => array(
			'true' => array(
				'msg'          => esc_html__( 'Warning: We noticed that you changed your permalinks settings to Plain. It is not possible to configure a custom login URL with plain permalinks. The Custom Login URL setting is automatically disabled.', 'really-simple-ssl' ) . '<br><br>' .
				                  esc_html__( 'Please change your permalink settings back to a different value if you wish to re-activate a custom login URL.', 'really-simple-ssl' ) . '<br><br>' .
					'<a href="' . esc_url( admin_url( 'options-permalink.php' ) ) . '" class="button button-primary">' . __( 'Permalink settings', 'really-simple-ssl' ) . '</a>',
				'icon'         => 'warning',
				'dismissible'  => true,
				'admin_notice' => true,
				'logo'         => true,
				'plusone'      => false,
			),
		),
	);

	return $notices;
}
add_filter( 'rsssl_notices', 'rsssl_premium_security_notices' );
