<?php
/**
 * Onboarding template for passkey.
 *
 * @package Rsssl
 */

if (!defined('ABSPATH')) {
    exit;
}

?>
<form id="two_fa_onboarding_form" class="login-form">
    <h3><?php esc_html_e('Register your Passkey', 'really-simple-ssl'); ?></h3>
    <p class="rsssl_into_two_factor"><?php esc_html_e("You're almost there! To complete your setup, you need to register a passkey. This will allow you to log in securely without a password.", 'really-simple-ssl'); ?></p>
    <?php
    if ( $is_forced && $grace_period ) {
        ?>
        <br/>
        <p>
            <?php
            if ( ! $is_today ) {
                echo sprintf( esc_html__(
                        'Please make sure to configure your passkey, access to your account will be denied if no method is configured within the next %s days.',
                        'really-simple-ssl'
                ), $grace_period );
            } else {
                echo esc_html__( 'Please make sure to configure your passkey, access to your account will be denied if no method is configured today.', 'really-simple-ssl' );
            }

            ?>
        </p>
        <?php
    }
    ?>
    <p>
    <div id="passkey-integration"></div>
    <div id="rsssl-passkey-error" class="error" style="display:none;"></div>
    <div class="rsssl_step_three_onboarding" style="display: block;">
        <button id="register-passkey-button" class="button button-primary passkey-registration-button"><?php esc_html_e('Register Passkey', 'really-simple-ssl'); ?></button>
    </div>
    </p>

    <p class="skip_container">
        <?php if (!$is_forced) { ?>
        <a href="#" id="do_not_ask_again">
	        <?php esc_html_e("Don't ask again", 'really-simple-ssl'); ?>
        </a>
        <?php } ?>
        <?php if ($show_skip && $is_forced) { ?>
        <a href="#" id="skip_onboarding">
            <?php
            if ( $is_today ) {
                echo esc_html__( 'Skip (Only today remaining)', 'really-simple-ssl' );
            } else {
                echo sprintf(
                        esc_html__( 'Skip (%1$d %2$s remaining)', 'really-simple-ssl' ),
                        $grace_period,
                        $grace_period > 1 ? esc_html__( 'days', 'really-simple-ssl' ) : esc_html__( 'day', 'really-simple-ssl' )
                );
            }
            ?>
        </a>
        <?php } elseif($show_skip) { ?>
        <a href="#" id="skip_onboarding">
            <?php echo esc_html__( 'Skip', 'really-simple-ssl' ) ?>
        </a>
        <?php } ?>
    </p>
</form>
