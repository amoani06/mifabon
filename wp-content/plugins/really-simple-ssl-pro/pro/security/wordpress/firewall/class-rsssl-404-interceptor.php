<?php
/**
 *
 */

namespace RSSSL\Pro\Security\WordPress\Firewall;

use Exception;
use RSSSL\Pro\Security\WordPress\Captcha\Rsssl_Captcha;
use RSSSL\Pro\Security\WordPress\Firewall\Models\Rsssl_404_Block;
use RSSSL\Pro\Security\WordPress\Limitlogin\Rsssl_IP_Fetcher;
use RSSSL\Pro\Security\WordPress\Rsssl_Geo_Block;


/**
 * The number of attempts.
 *
 * @var int $attempts The number of attempts
 */
class Rsssl_404_Interceptor
{

    /**
     * The number of attempts.
     *
     * @var int $attempts The number of attempts
     */
    private $attempts = 2;

    /**
     * The time span in seconds.
     *
     * @var int $time_span The time span in seconds.
     */
    private $time_span = 10; // 2 minutes

    /**
     * The duration in minutes.
     * @var int
     */
    private $duration = 30;// 30 minutes

    /**
     * The instance of the Model class.
     *
     * @var Rsssl_404_Block $model The instance of the Model class.
     */
    private $model;

    /**
     * The IP address of the user.
     *
     * @var string $ip_address The IP address of the user.
     */
    private $ip_address;

	/** @var Rsssl_Geo_Block */
	private Rsssl_Geo_Block $geoBlock;

    /**
     * Class constructor.
     * Creates a new instance of the class and initializes its properties.
     *
     * @return void
     */
    public function __construct()
    {
        if (false === rsssl_get_option('enable_firewall') || 'disabled' === rsssl_get_option('404_blocking_threshold')) {
            return;
        }

	    $this->geoBlock = Rsssl_Geo_Block::get_instance();

        $this->model = new Rsssl_404_Block();
        $ip_addresses = (new Rsssl_IP_Fetcher())->get_ip_address();
        $this->ip_address = !empty($ip_addresses) ? $ip_addresses[0] : '';

	    // we add the action to delete the non-blocked 404 entries to the cron.
	    add_action(
		    'rsssl_five_minutes_cron',
		    array($this, 'cleanup_404_entries')
	    );

	    // Skip when running via WP-CLI
	    if ( defined( 'WP_CLI' ) && WP_CLI ) {
		    return;
	    }

	    // Skip when running via server cron (CLI)
	    if ( PHP_SAPI === 'cli' ) {
		    return;
	    }

	    // Skip when running WordPress cron
	    if (defined('DOING_CRON') && DOING_CRON) {
		    return;
	    }

        switch (rsssl_get_option('404_blocking_threshold')) {
            case 'lax':
                $this->attempts = 10;
                $this->time_span = 2;
                break;
            case 'normal':
                $this->attempts = 10;
                $this->time_span = 5;
                break;
            case 'strict':
                $this->attempts = 10;
                $this->time_span = 10;
                break;
            default:
                $this->attempts = 2;
                $this->time_span = 10;
                break;
        }

        $this->duration = 60 * (int)rsssl_get_option('404_blocking_lockout_duration');
        if ($this->duration < 1) {
            $this->duration = 60 * 30;
        }

        add_action('template_redirect', array($this, 'intercept_404'));

        add_action(
            'rsssl_next_page_load_event',
            array($this, 'handle_next_page_load_event')
        );

        add_action('rsssl_after_save_field', array($this, 'set_defaults'), 10, 4);


    }

    /**
     * @param $field_id
     * @param $field_value
     * @param $prev_value
     * @param $field_type
     *
     * @return void
     *
     * Maybe allow the user to re-verify their e-mail address after the notifications e-mail address has changed
     */
    public function set_defaults($field_id, $field_value, $prev_value, $field_type): void
    {
        if (rsssl_get_option('404_blocking_lockout_duration', 30) < 1) {
            rsssl_update_option('404_blocking_lockout_duration', 30);
        }
    }

    /**
     * Intercepts the 404 pages and checks if the threshold is reached for the visitor's IP address.
     *
     * @return void
     * @throws Exception When the captcha cannot be loaded.
     */
    public function intercept_404(): void
    {
	    // Skip when running via WP-CLI
	    if ( defined( 'WP_CLI' ) && WP_CLI ) {
		    return;
	    }

	    // Skip when running via server cron (CLI)
	    if ( PHP_SAPI === 'cli' ) {
		    return;
	    }

	    // Skip when running WordPress cron
	    if (defined('DOING_CRON') && DOING_CRON) {
		    return;
	    }

        if ( !is_404() ) {
            return;
        }

        // if user is logged in and can manage RSS, do not block
        if (is_user_logged_in()) {
            return;
        }

        // if the ip is in the allow list we return.
        $white_list = Rsssl_Geo_Block::get_white_list();
        if (in_array($this->ip_address, explode(',', $white_list), true)) {
            return;
        }

        if ((!empty($_POST) && (bool)rsssl_get_option('404_blocking_captcha_trigger')) || $this->captcha_was_triggered()) {
            if (!$this->validate_captcha()) {
                $this->update_headers();
                // Removing the $_POST array in case they do a refresh.
                $_POST = array();

                // Showing the 404 page without Captcha.
                $this->load_captcha(false);
                exit;
            }
        }

        // We get the ip address of the visitor.
        $ip_address = $this->ip_address;

        // If the Captcha is set we redirect to a not-a-bot page.

        // now we only get the values from the collection of objects and make it an array.
        $blocked_ips = $this->clean_up_list($this->model->get_all(array('ip_address')));

        if ($this->check_threshold($ip_address, $blocked_ips)) {
            if ($this->model->get_captcha($ip_address) === 1) {
                $this->model->set_captcha($ip_address);
                $this->load_captcha();
                exit;
            }
            // if the ip is not blocked we do the block and update the advanced_headers.
            if (!$this->model->is_blocked($ip_address)) {
                $this->model->block_ip($ip_address);
                $this->update_headers();
            } else {
                $this->load_captcha(false);
                exit;
            }
        }
    }

    /**
     * Updates the headers of the class.
     * Makes a call to the Rsssl_To_Many404::handle_event() method,
     * and schedules the cron job for the next page load if the rsssl_firewall_manager class does not exist.
     *
     * @return void
     */
    public function update_headers(): void
    {

        // Add define so rsssl_admin_logged_in() returns true, required to update blocklist rule in advanced-headers.php
        if (!defined('RSSSL_LEARNING_MODE')) {
            define('RSSSL_LEARNING_MODE', true);
        }

		$this->geoBlock->generate_firewall_rules();
    }

    /**
     * Check if the threshold is reached for the given IP address.
     *
     * @param string $ip_address The IP address to check.
     * @param array $blocked_ips The list of blocked IP addresses.
     *
     * @return bool Returns true if the threshold is reached, false otherwise.
     */
    private function check_threshold(string $ip_address, array $blocked_ips): bool
    {
        // Check if the threshold is reached
        // if the ip is not in the list we add it.
        if (!in_array($ip_address, $blocked_ips, true)) {
            // We just add the ip address to the list.
            $this->model->add($ip_address);

            return false;
        }

        // So here we know it already exists in the list so we up the count.
        $current = $this->model->up_count($ip_address);
        // if the $current is null we return false.
        if (is_null($current) || empty((array)$current)) {
            return false;
        }
        if ((int)$current->blocked === 1) {
            return true;
        }


        if ($this->within_timeframe($current->create_date, $this->time_span)) {
            // If the count is almost blocked we set captcha to true.
            if ((int)$current->attempt_count === $this->attempts && (bool)rsssl_get_option('404_blocking_captcha_trigger')) {
                $this->model->set_captcha($ip_address);
            }

            // if the count within the time span is smaller than the count attempts we return false.
            return (int)$current->attempt_count === $this->attempts;
        }
        // We delete the entry.
        $this->model->delete_by_ip($ip_address);

        return false;
    }

    /**
     * Clean up the list by returning only the non-null ip addresses.
     *
     * @param array $data The list of objects.
     *
     * @return array The list of non-null ip addresses
     */
    private function clean_up_list(array $data): array
    {
        return array_values(
            array_filter(
                array_map(
                    static function ($item) {
                        // If the object is not null we return the ip address.
                        return $item->ip_address ?? null;
                    },
                    $data
                )
            )
        );
    }

    /**
     * Determines if the given create date falls within the specified time span.
     *
     * @param int $create_date The timestamp of the initial attempt.
     * @param int $time_span The duration in seconds that defines the time span.
     *
     * @return bool Returns true if the create date falls within the time span, false otherwise.
     */
    private function within_timeframe(int $create_date, int $time_span): bool
    {
        $now = time();
        $seconds = $now - $create_date;

        return $seconds < $time_span;
    }

    /**
     * Deletes the non-blocked 404 entries.
     *
     * Deletes the 404 entries from the model that are not blocked.
     *
     * @return void
     * @throws Exception When the firewall manager class does not exist.
     */
    public function cleanup_404_entries(): void
    {
        $this->model->delete_temporarily_blocked_entries();
        $this->model->cleanup_watchlist();
	    $this->geoBlock->generate_firewall_rules();
    }

    /**
     * Load captcha page.
     *
     * @param bool $captcha Whether to display captcha or not.
     *
     * @return void
     * @throws Exception
     */
    public function load_captcha(bool $captcha = true): void
    {

        $apology = __('We\'re sorry!', 'really-simple-ssl');
        $message = __('Please verify that you are human', 'really-simple-ssl');
        if (!$captcha) {
            $message = __('Your access to this site has been temporarily denied', 'really-simple-ssl');
        }
        $error_code = __('Error code: 404', 'really-simple-ssl');
        $auto_submit = true;
        $icon_url = defined( 'rsssl_url' ) ? trailingslashit( rsssl_url ) . 'pro/assets/templates/security.png' : '';
        $captcha_template = '';

        if ( $captcha ) {
            $ip_addresses = ( new Rsssl_IP_Fetcher() )->get_ip_address();
            $ip_address = $ip_addresses[0] ?? '';
            $this->model->set_captcha( $ip_address );
            $captcha_template = Rsssl_Captcha::get_markup( true, 'rsssl-captcha-form' );
        }

        // ... generate your page content here
        rsssl_load_template(
            '403-page.php',
            compact('apology', 'message', 'error_code', 'captcha', 'captcha_template', 'auto_submit', 'icon_url'),
            rsssl_path . 'pro/assets/templates'
        );

        exit;
    }

    /**
     * Validate the captcha for 404 request.
     *
     */
    public function validate_captcha(): bool
    {
        // Initialize the CAPTCHA object.
        $captcha = new Rsssl_Captcha();

        // Retrieve the CAPTCHA response sent by the user.
        $captcha_response = $captcha->captcha_provider->get_response_value();

        // Validate the CAPTCHA response.
        if (!$captcha->captcha_provider->validate($captcha_response)) {
            // The CAPTCHA response is invalid. Block the ip.
            $this->model->block_ip($this->ip_address);

            return false;
        }

        //We remove the temporary block.
        $this->model->delete_by_ip($this->ip_address);

        return true;
    }

    /**
     * Checks if captcha was triggered.
     *
     * @return bool Returns true if the captcha was triggered, false otherwise.
     */
    private function captcha_was_triggered(): bool
    {
        $current = $this->model->get($this->ip_address);

        if (!$current) {
            return false;
        }

        return (int)$current->captcha === 3;
    }
}

$interceptor = new Rsssl_404_Interceptor();
