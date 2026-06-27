<?php
if ( isset( $captcha ) && true === $captcha && function_exists( 'wp_head' ) ) {
	wp_head();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>403 Forbidden</title>
	<style type="text/css">
		body {
			font-family: arial, helvetica, sans-serif;
			margin: 2em;
			background-color: #fff;
		}

		.container {
			margin: 1% auto;
			width: 550px;
		}

		.logo {
			margin-bottom: 10px;
		}

		.logo img {
			width: 45%;
			max-width: 32px;
		}

		h1 {
			font-size: 24px;
			font-weight: 525;
			margin: 0;
		}

		.subtitle {
			font-size: 18px;
			margin: 8px 0 8px 0;
			font-weight: normal;
		}

		code {
			margin: 8px 0 0 0;
			font-size: 1em;
			color: rgba(128, 128, 128, 0.59);
		}
        .button {
            border: none;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
        }
        .button-primary {
            background-color: #0073aa;
        }
	</style>
</head>
<body>

<div class="container">
	<div class="logo">
		<?php if ( ! empty( $icon_url ) ) { ?>
			<img src="<?php echo htmlspecialchars( (string) $icon_url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); ?>" alt="Logo">
		<?php } ?>
	</div>
	<h1><?php echo htmlspecialchars( (string) ( $apology ?? '' ), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); ?></h1>
	<h2 class="subtitle"><?php echo htmlspecialchars( (string) ( $message ?? '' ), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); ?></h2>
	<code><?php echo htmlspecialchars( (string) ( $error_code ?? '' ), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); ?></code>
	<?php if ( isset( $captcha ) && true === $captcha ) { ?>
		<p>
		<form method="post" id="rsssl-captcha-form">
			<?php
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Markup is generated and escaped by the captcha provider.
			echo $captcha_template;
			if ( ! isset( $auto_submit ) || ! $auto_submit ) {
				?>
				<input type="submit" class="button button-primary" value="Submit"/>
				<?php
			}
			?>
		</form>
		</p>
	<?php } ?>
</div>

<?php
if ( isset( $captcha ) && true === $captcha && function_exists( 'wp_footer' ) ) {
	wp_footer();
}
?>
</body>
</html>
