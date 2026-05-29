<?php

/**
 * Popup Builder.
 *
 * @since 3.9.0
 */

use \Elementor\Controls_Manager;


// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// \Elementor\Core\Base\Document

class Sina_Popup_Builder extends \Elementor\Modules\Library\Documents\Page{
	public function get_name() {
		return 'sina_popup';
	}

	public static function get_type() {
		return 'sina_popup';
	}

	public static function get_title() {
		return esc_html__( 'Sina Popup', 'sina-ext' );
	}

	public function get_css_wrapper_selector() {
		return '#sina-ext-popup-'.$this->get_main_id();
	}

	public function get_container_attributes() {
		$attributes = parent::get_container_attributes();
		$attributes['id'] = 'sina-ext-popup-' . $this->get_main_id();
		return $attributes;
	}

	protected function register_controls() {
		// Start Popup Settings
		// =====================
			$this->start_controls_section(
				'popup_settings',
				[
					'label' => esc_html__( 'Popup Settings', 'sina-ext' ),
					'tab' => Controls_Manager::TAB_SETTINGS,
				]
			);

				$this->add_control(
					'popup_trigger',
					[
						'label'   => esc_html__( 'Open Trigger', 'sina-ext' ),
						'type'    => Controls_Manager::SELECT,
						'options' => [
							'load' => esc_html__( 'After Page Load', 'sina-ext' ),
							'date' => esc_html__( 'After Specific Date', 'sina-ext' ),
							'scroll' => esc_html__( 'Page Scroll', 'sina-ext' ),
							'scroll-element' => esc_html__( 'Scroll to Element', 'sina-ext' ),
							'inactivity'  => esc_html__( 'User Inactivity', 'sina-ext' ),
							'exit-intent' => esc_html__( 'User Exit Intent', 'sina-ext' ),
							'custom' => esc_html__( 'Custom Element', 'sina-ext' ),
						],
						'default' => 'load',
					]
				);
				$this->add_control(
					'popup_load_delay',
					[
						'label' => esc_html__( 'Delay Page Load (Seconds)', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'min' => 0,
						'default' => 1,
						'condition' => [
							'popup_trigger' => 'load',
						]
					]
				);
				$this->add_control(
					'popup_date',
					[
						'label' => esc_html__( 'Select Date', 'sina-ext' ),
						'label_block' => false,
						'type' => Controls_Manager::DATE_TIME,
						'default' => date( 'Y-m-d H:i', strtotime( '+1 day' ) + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) ),
						'condition' => [
							'popup_trigger' => 'date',
						],
					]
				);
				$this->add_control(
					'popup_scroll_distance',
					[
						'label' => esc_html__( 'Scroll Distance (In %)', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'min' => 1,
						'max' => 100,
						'default' => 10,
						'condition' => [
							'popup_trigger' => 'scroll',
						]
					]
				);
				$this->add_control(
					'popup_scroll_element',
					[
						'label' => esc_html__( 'Element Selector', 'sina-ext' ),
						'type' => Controls_Manager::TEXT,
						'description' => esc_html__( 'Enter CSS Selector. Like: .sina-extension, #sina-extension', 'sina-ext' ),
						'dynamic' => [
							'active' => true,
						],
						'condition' => [
							'popup_trigger' => 'scroll-element',
						]
					]
				);
				$this->add_control(
					'popup_inactivity_time',
					[
						'label' => esc_html__( 'Inactivity Time (seconds)', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'min' => 1,
						'default' => 20,
						'condition' => [
							'popup_trigger' => 'inactivity',
						]
					]
				);
				$this->add_control(
					'popup_custom_trigger',
					[
						'label' => esc_html__( 'Element Selector', 'sina-ext' ),
						'type' => Controls_Manager::TEXT,
						'description' => esc_html__( 'Enter CSS Selector. Like: .sina-extension, #sina-extension. If clicks the selector element(s) the Popup will show.', 'sina-ext' ),
						'dynamic' => [
							'active' => true,
						],
						'condition' => [
							'popup_trigger' => 'custom',
						]
					]
				);
				$this->add_control(
					'popup_show_again',
					[
						'label'   => esc_html__( 'Show Again', 'sina-ext' ),
						'type'    => Controls_Manager::SELECT,
						'description' => esc_html__( 'When to show the Popup again to a visitor after it is closed.', 'sina-ext' ),
						'options' => [
							'1' => esc_html__( 'No Delay', 'sina-ext' ),
							'seconds' => esc_html__( 'Seconds', 'sina-ext' ),
							'minutes' => esc_html__( 'Minutes', 'sina-ext' ),
							'hours' => esc_html__( 'Hours', 'sina-ext' ),
							'days' => esc_html__( 'Days', 'sina-ext' ),
							'months' => esc_html__( 'Months', 'sina-ext' ),
						],
						'default' => '1',
					]
				);
				$this->add_control(
					'popup_show_seconds',
					[
						'label' => esc_html__( 'After Seconds', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'min' => 1,
						'default' => 30,
						'condition' => [
							'popup_show_again' => 'seconds',
						]
					]
				);
				$this->add_control(
					'popup_show_minutes',
					[
						'label' => esc_html__( 'After Minutes', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'min' => 1,
						'default' => 15,
						'condition' => [
							'popup_show_again' => 'minutes',
						]
					]
				);
				$this->add_control(
					'popup_show_hours',
					[
						'label' => esc_html__( 'After Hours', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'min' => 1,
						'default' => 6,
						'condition' => [
							'popup_show_again' => 'hours',
						]
					]
				);
				$this->add_control(
					'popup_show_days',
					[
						'label' => esc_html__( 'After Days', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'min' => 1,
						'default' => 15,
						'condition' => [
							'popup_show_again' => 'days',
						]
					]
				);
				$this->add_control(
					'popup_show_months',
					[
						'label' => esc_html__( 'After Months', 'sina-ext' ),
						'type' => Controls_Manager::NUMBER,
						'description' => esc_html__( '30 Days counts 1 Month.', 'sina-ext' ),
						'min' => 1,
						'default' => 1,
						'condition' => [
							'popup_show_again' => 'months',
						]
					]
				);

			$this->end_controls_section();
		// End Popup Settings
		// ===================


		// Start Close Settings
		// =====================
			$this->start_controls_section(
				'close_button',
				[
					'label' => esc_html__( 'Close Trigger', 'sina-ext' ),
					'tab' => Controls_Manager::TAB_SETTINGS,
				]
			);

				$this->add_control(
					'close_esc',
					[
						'label' => esc_html__( 'Close to press ESC', 'sina-ext' ),
						'type' => Controls_Manager::SWITCHER,
						'default' => 'yes',
					]
				);
				$this->add_control(
					'close_element',
					[
						'label' => esc_html__( 'Close Element', 'sina-ext' ),
						'type' => Controls_Manager::SELECT,
						'options' => [
							'default' => esc_html__( 'Click Close Button', 'sina-ext' ),
							'overlay' => esc_html__( 'Click Outside', 'sina-ext' ),
							'default-overlay' => esc_html__( 'Close Button or Click Outside', 'sina-ext' ),
							'custom' => esc_html__( 'Custom', 'sina-ext' ),
						],
						'default' => 'default',
						'selectors_dictionary' => [
							'overlay' => 'display: none;',
							'custom' => 'display: none;',
						],
						'selectors' => [
							'{{WRAPPER}} .sina-ext-popup-close-btn' => '{{VALUE}}',
						],
					]
				);
				$this->add_control(
					'close_element_selector',
					[
						'label' => esc_html__( 'Element Selector', 'sina-ext' ),
						'type' => Controls_Manager::TEXT,
						'description' => esc_html__( 'Enter CSS Selector. Like: .sina-extension, #sina-extension. If clicks the selector element(s) the Popup will close.'),
						'condition' => [
							'close_element' => 'custom',
						]
					]
				);

			$this->end_controls_section();
		// End Close Settings
		// ===================


		Sina_Common_Data::popup_style( $this );


		// Start Close Button Style
		// =========================
			$selector = '{{WRAPPER}} .sina-ext-popup-close-btn';
			$this->start_controls_section(
				'close_btn_style',
				[
					'label' => esc_html__( 'Close Button', 'sina-ext' ),
					'tab' => Controls_Manager::TAB_STYLE,
					'condition' => [
						'close_element' => ['default', 'default-overlay'],
					]
				]
			);

				$this->add_control(
					'close_btn_hr_align',
					[
						'label' => esc_html__( 'Horizontal Align', 'sina-ext' ),
						'type' => Controls_Manager::CHOOSE,
						'options' => [
							'left' => [
								'title' => esc_html__( 'Left', 'sina-ext' ),
								'icon' => 'eicon-h-align-left',
							],
							'right' => [
								'title' => esc_html__( 'Right', 'sina-ext' ),
								'icon' => 'eicon-h-align-right',
							],
						],
						'toggle' => false,
						'default' => 'right',
					]
				);
				$this->add_control(
					'close_btn_vr_align',
					[
						'label' => esc_html__( 'Vertical Align', 'sina-ext' ),
						'type' => Controls_Manager::CHOOSE,
						'options' => [
							'top' => [
								'title' => esc_html__( 'Top', 'sina-ext' ),
								'icon' => 'eicon-v-align-top',
							],
							'bottom' => [
								'title' => esc_html__( 'Bottom', 'sina-ext' ),
								'icon' => 'eicon-v-align-bottom',
							],
						],
						'toggle' => false,
						'default' => 'top',
					]
				);
				$this->add_responsive_control(
					'close_btn_hr_spacing',
					[
						'label' => esc_html__( 'Horizontal Spacing', 'sina-ext' ),
						'type' => Controls_Manager::SLIDER,
						'default' => [
							'size' => '5',
						],
						'selectors' => [
							$selector => 'right: inherit !important;{{close_btn_hr_align.VALUE || right}}: {{SIZE}}{{UNIT}};',
						],
					]
				);
				$this->add_responsive_control(
					'close_btn_vr_spacing',
					[
						'label' => esc_html__( 'Vertical Spacing', 'sina-ext' ),
						'type' => Controls_Manager::SLIDER,
						'default' => [
							'size' => '5',
						],
						'selectors' => [
							$selector => 'top: inherit !important;{{close_btn_vr_align.VALUE || top}}: {{SIZE}}{{UNIT}};',
						],
					]
				);
				Sina_Common_Data::icon_style( $this, $selector.' i', 'close_btn' );

			$this->end_controls_section();
		// End Close Button Style
		// =======================
	}
}