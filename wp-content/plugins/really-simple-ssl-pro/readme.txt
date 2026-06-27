=== Really Simple Security ===
Contributors: RogierLankhorst, markwolters, hesseldejong, vicocotea, marcelsanting, janwoostendorp, wimbraam
Donate link: https://www.paypal.me/reallysimplessl
Tags: security, https, 2fa, vulnerabilities, two factor
Requires at least: 6.6
License: GPL2
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 9.6.0

Easily improve site security with WordPress Hardening, Two-Factor Authentication (2FA), Login Protection, Vulnerability Detection and SSL certificate.

== Description ==

= Really simple, Effective and Performant WordPress Security =

Really Simple Security is the most lightweight and easy-to-use security plugin for WordPress. It secures your WordPress website with SSL certificate generation, including proper 301 https redirection and SSL enforcement, scanning for possible vulnerabilities, Login Protection and implementing essential WordPress hardening features.

We believe that security should have the absolute minimum effect on website performance, user experience and maintainability. Therefore, Really Simple Security is:

* **Lightweight:** Every security feature is developed with a modular approach and with performance in mind. Disabled features won't load any redundant code.
* **Easy-to-use:** 1-minute configuration with short onboarding setup.

= Security Features =

= Easy SSL Migration =

Migrates your website to HTTPS and enforces SSL in just one click.

* 301 redirect via PHP or .htaccess
* Secure cookies
* Let's Encrypt: Install an SSL Certificate if your hosting provider supports manual installation.
* Server Health Check: Your server configuration is every bit as important for your website security.

= WordPress Hardening =

Tweak your configuration and keep WordPress fortified and safe by tackling potential weaknesses.

* Prevent code execution in the uploads folder
* Prevent login feedback and disable user enumeration
* Disable XML-RPC
* Disable directory browsing
* Username restrictions (block 'admin' and public names)
* and much more..

= Vulnerability Detection =

Get notified when plugins, themes or WP core contain vulnerabilities and need appropriate action.

= Login Protection =

Allow or enforce Two-Factor Authentication (2FA) for specific user roles. Users receive a two-factor code via Email.

= Improve Security with Really Simple Security Pro =

[Protect your site with all essential security features by upgrading to Really Simple Security Pro.](https://really-simple-ssl.com/)

= Advanced SSL enforcement =

* Mixed Content Scan & Fixer. Detect files that are requested over HTTP and fix them to HTTPS, both Front- and Back-end.
* Enable HTTP Strict Transport Security and configure your site for the HSTS Preload list.

= Firewall =

Really Simple Security Pro includes a performant and efficient WordPress firewall, to stop bots, crawlers and bad actors with IP and username blocks.

* 404 blocking - Blocks crawlers as they trigger unusual numbers of 404 errors.
* Region blocking - Only allow/block access to your site from specific regions.
* Automated and customisable Firewall rules.
* IP blocklist and allowlist.

= Security Headers =

Security headers protect your site visitors against the risk of clickjacking, cross-site-forgery attacks, stealing login credentials and malware.

* Independent of your Server Configuration, works on Apache, LiteSpeed, NGINX, etc.
* Protect your website visitors with X-XSS Protection, X-Content-Type-Options, X-Frame-Options, a Referrer Policy and CORS headers.
* Automatically generate your WordPress-tailored Content Security Policy.

= Vulnerability Measures =

When a vulnerability is detected in a plugin, theme or WordPress core you will get notified accordingly. With Vulnerability Measures, you can configure simple but effective measures to make sure that a critical vulnerability won't remain unattended.

* Force update: An update process will be tried multiple times until it can be assumed development of a theme or plugin is abandoned. You will be notified during these steps.
* Quarantine: When a plugin or theme can't be updated to solve a vulnerability, Really Simple Security can quarantine the plugin.

= Advanced Site Hardening =

* Choose a custom login URL
* Automated File Permissions check and fixer
* Rename and randomize your database prefix
* Change the debug.log file location to a non-public folder
* Disable application passwords
* Control admin creation
* Disable HTTP methods, reducing HTTP requests

= Login Protection =

Secure your website's login process and user accounts with powerful security measures.

* Two-Step verification (Email login)
* 2FA (two factor authentication) with TOTP
* Passwordless login with passkey login
* Enforce strong passwords and frequent password change
* Limit Login Attempts

With Limit Login Attempts you can configure a threshold to temporarily or permanently block IP addresses or (non-existing) usernames. You can also throw a CAPTCHA after a failed login (hCaptcha or Google reCaptcha)

= Access Control =

* Restrict access to your site for specific regions.
* Add specific IP addresses or IP ranges to the Blocklist or Allowlist.


= Useful Links =

* [Documentation](https://really-simple-ssl.com/knowledge-base-overview/)
* [Security Definitions](https://really-simple-ssl.com/definitions/)
* [Translate Really Simple Security](https://translate.wordpress.org/projects/wp-plugins/really-simple-ssl)
* [Issues & pull requests](https://github.com/Really-Simple-Plugins/really-simple-ssl/issues)
* [Feature requests](https://github.com/Really-Simple-Plugins/really-simple-ssl/labels/feature%20request)

= Love Really Simple Security? =

If you want to support the continuing development of this plugin, please consider buying [Really Simple Security Pro](https://www.really-simple-ssl.com/pro/), which includes some excellent security features and premium support.

= About Really Simple Plugins =

Our mission is to make complex WordPress requirements really easy. Really Simple Security is developed by [Really Simple Plugins](https://www.really-simple-plugins.com).

For generating SSL certificates, Really Simple Security uses the [le acme2 PHP](https://github.com/fbett/le-acme2-php/) Let's Encrypt client library, thanks to 'fbett' for providing it. Vulnerability Detection uses WP Vulnerability, an open-source initiative by Javier Casares. Want to join as a collaborator? We're on [GitHub](https://github.com/really-simple-plugins/really-simple-ssl) as well!

== Installation ==
To install this plugin:

1. Make a backup! See [our recommendations](https://really-simple-ssl.com/knowledge-base/backing-up-your-site/).
2. Download the plugin.
3. Upload the plugin to the /wp-content/plugins/ directory.
4. Go to "Plugins" in your WordPress admin, then click "Activate".
5. You will now see the Really Simple Security onboarding process, to quickly help you through the configuration process.

== Frequently Asked Questions ==
= Knowledge Base =
For more detailed explanations and documentation on all Really Simple Security features, please search the [Knowledge Base](https://www.really-simple-ssl.com/knowledge-base/)

= What happened with Really Simple SSL? =

All features that made Really Simple SSL the most powerful and easy-to-use SSL generation and redirect plugin are still part of Really Simple Security. The plugin is developed with a modular approach: if you don't want to use the full set of security features, the unused code will not be loaded and won't have any effect on your site's performance.

= Why Really Simple Security? =

In our experience, security solutions for WordPress are often hard to configure, trigger many false positives and have a significant impact on site performance. We have been receiving requests from our users to simplify WordPress security for years, so that has become our mission!

= I want to share my feedback or contribute to Really Simple Security =
You couldn't make us happier! Really Simple Security is GPL licensed and co-created by the WordPress community. All feedback is highly appreciated and has always helped us to better understand users' needs. For code contributions or suggestions, we're on [GitHub](https://github.com/really-simple-plugins/really-simple-ssl). For suggestions, please [open a support ticket](https://wordpress.org/support/plugin/really-simple-ssl/) You can also express your appreciation by [leaving a review](https://wordpress.org/support/plugin/really-simple-ssl/reviews/).

= What are Mixed Content issues? =

Most mixed content issues are caused by URLs in CSS or JS files. For detailed instructions on how to find mixed content read this [article](https://really-simple-ssl.com/knowledge-base/how-to-track-down-mixed-content-or-insecure-content/).

= Generating a Let's Encrypt SSL Certificate =

We added the possibility to generate a Free SSL Certificate with Let's Encrypt in our Really Simple Security Wizard. We have an updated list available for all possible integrations [here](https://really-simple-ssl.com/install-ssl-certificate/). Please leave feedback about another integration, incorrect information, or you need help.

= How do I fix a redirect loop? =

If you are experiencing redirect loops on your site, try these [instructions](https://really-simple-ssl.com/knowledge-base/my-website-is-in-a-redirect-loop/). This can sometimes happen during the migration to HTTPS or due to conflicting redirect rules.

= Is the plugin multisite compatible? =

Yes. There is a dedicated network settings page where you can control settings for your entire network, at once.

= How do I enforce strong passwords? =

Under Login Protection, you can configure minimum strength settings and require users to change their passwords after a defined interval. Disabling weak password usage is a best practice.

= How can I change my login URL? =

You can set a custom login URL under Advanced Site Hardening, which helps prevent brute force login attacks and bots targeting wp-login.php.

= Does this plugin redirect HTTP to HTTPS? =

Yes. The plugin enforces HTTPS and handles all necessary redirects, optionally using .htaccess or PHP.

= Can I use Really Simple Security besides WordFence? =

Really Simple Security and WordFence greatly overlap in term of functionality. If you like to use specific features from both plugins, we strongly recommend not to enable similar features twice. The benefit of Really Simple Security is that disabled features don't load any code, so won't have an impact on site performance.

== Changelog ==
= 9.6.0 - 2026-06-09 =
* Fixed: 2FA grace period reminder emails could be sent unexpectedly.
* Fixed: Content Security Policy now follows the setting toggle correctly.
* Fixed: PHP 8.4 deprecation warning.
* Fixed: DNS verification issue in the Let's Encrypt wizard.
* Changed: Vulnerability details now load only for the plugin or theme being activated.
* Changed: Improved rule writing with file locking to avoid race conditions.
* Changed: Uninstall cleanup now removes plugin options and transients more reliably.
* Changed: Added a login page notice for invalid login sessions.
* Changed: Improved 2FA user lookup performance on multisite.
* Changed: Improved license check reliability.
* Changed: Improved DirectAdmin Let's Encrypt certificate generation.
* Changed: Improved several interface texts.
* Changed: Event logs now support larger log tables.
* Changed: Added RSSSL_INFO_LOG for extra debugging details.
* Changed: Added more prerequisite checks before features can be enabled.

= 9.5.11 - 2026-05-05 =
* Fixed: fatal error that could occur when a plugin uses admin_enqueue_scripts incorrectly.
* Fixed: a bug where the wrong settings value could be saved.

= 9.5.10.1 - 2026-04-29 =
* Fixed: Undefined variable during cron.
* Changed: Updated 2FA login flow to address inconsistent verification behavior.

= 9.5.10 - 2026-04-14 =
* Fixed: An issue that could cause a crash when activating alongside the Perfmatters plugin.
* Fixed: Some styling (CSS) issues to improve compatibility with WordPress 7.0.
* Changed: Removed an unused AJAX callback.
* Changed: Tested up to WordPress 7.0.

= 9.5.9 - 2026-03-24 =
* Fixed: A fatal error that could occur when activating Pro in a multisite environment.
* Fixed: An issue where logging in with a username and password on multisite did not trigger a passkey prompt when using a standalone passkey.
* Fixed: Improved and future-proofed the plugin updater.
* Changed: Updated the event log cleanup cron hook.
* Changed: Reworked vulnerability detection and measures logic.

= 9.5.8.1 - 2026-03-03 =
* Fixed: An issue where TOTP codes starting with a 0 were not properly recognized.
* Fixed: Prevent using "Do Not Ask Again" for user roles where 2FA is required.
* Changed: Various improvements to authentication flow.

= 9.5.8 - 2026-02-24 =
* Fixed: Resolved an issue where “Prevent login feedback” could show a ghost username on the login retry screen.
* Fixed: Prevented “Failed to send buffer of zlib output compression” notices when using the Mixed Content Fixer with zlib.output_compression enabled.

= 9.5.7 - 2026-02-03 =
* Fixed: scenario where users were stuck after an expired 2FA grace period due to missing authentication methods.
* Fixed: Support for `wss://` URLs in CSP `connect-src`.
* Fixed: MemberPress login compatibility with Limit Login Attempts.
* Changed: event logging by generating messages dynamically instead of storing translated text.
* Changed: Email 2FA user experience by making Enter submit the verification code instead of resending it.
* Changed: Simplified service bootstrapping by removing the Provider layer and registering all services directly in the App container.

= 9.5.6 - 2026-01-13 =
* Fixed: compromised password check compatibility with Thrive Architect
* Fixed: fatal error on multisite subsite profile pages with passkeys enabled
* Fixed: user role demotion issue on multisite
* Fixed: passkey settings appearing twice on profile page
* Fixed: 2FA users list not displaying all users
* Fixed: Cloudflare cache not clearing after SSL activation
* Fixed: passkey strings not translatable
* Fixed: uploads .htaccess using incorrect Apache syntax for some versions
* Changed: deferred header detection on activation to prevent timeouts
* Changed: improved deactivation process
* Changed: more robust firewall code generation

= 9.5.5 - 2025-12-09 =
* Fixed: JavaScript error when using custom roles with 2FA
* Fixed: fatal error caused by hosts class being instantiated twice
* Fixed: Limit Login Attempts now blocks both username and email address
* Fixed: fatal error when upgrading from older plugin versions
* Fixed: security headers set outside the plugin now correctly appear disabled
* Fixed: text domain loaded too early warning when logging in with blocked username
* Fixed: reinstated reset_2fa [id] WP-CLI command
* Fixed: WP-CLI activate_ssl command now works correctly on first attempt
* Changed: removed two unused files from the plugin
* Changed: improved feedback when logging in with a passkey
* Changed: updated readme to align with standards

= 9.5.4.1 - 2025-11-19 =
* Fixed: an edge case where authentication validation could behave unexpectedly

= 9.5.4 - 2025-11-18 =
* Fixed: 2FA login error when user has no assigned roles
* Fixed: fatal error when wp-config.php path is empty
* Changed: added file locking to .htaccess and wp-config.php to prevent race conditions
* Changed: login lockout period no longer extends when trying to log in while blocked
* Changed: password login now triggers passkey prompt when passkeys are enabled
* Changed: clarified .htaccess directory indexing comment
* Changed: replaced site_url() with home_url() in the 404 resource check on the homepage
* Changed: security functions now skip cron jobs and CLI environments
* Changed: Let's Encrypt wizard final step now shows only SSL activation button
* Changed: added a license.txt file

= 9.5.3.1 =
* Fixed: Added a fix for WP_CLI commands

= 9.5.3 =
* Fixed: blocking a username now blocks both lower- and uppercase variants
* Fixed: readme now displays correctly in WordPress updates screen
* Fixed: added a fallback for when an empty get_user_totp_key was empty
* Fixed: removed an unused translation that could cause a textdomain loaded to early warning
* Fixed: prevent an error when an IP address is undefined
* Fixed: empty sections are now correctly cleared from the firewall
* Fixed: deactivation modal now always displays
* Changed: added a notice when using a custom login URL with plain permalinks
* Changed: added a check if WPFC_SERVE_ONLY_VIA_CACHE is already defined before defining it
* Changed: updated the mixed content notice text
* Changed: refactored the onboarding code

= 9.5.2.3 =
* Fixed: the 2FA reset fix now correctly calls the 2FA reset service

= 9.5.2.2 =
* Fixed: 2FA TypeError when updating from older versions

= 9.5.2 =
* Fixed: all users will now appear in the 2FA list
* Fixed: advanced-headers.php and firewall paths update correctly during migration
* Fixed: PHP 8.4 deprecation notices
* Fixed: tasks will now always display on multisite
* Fixed: skip/don't ask again is now hidden for users who already configured passkeys
* Changed: activate_ssl CLI command supports --force to skip confirmation

= 9.5.1 =
* Fixed: activating the Pro and Multisite plugin at the same time will no longer throw a fatal error
* Fixed: added a check for the getmyuid function to prevent errors in case this function was missing
* Fixed: Right-To-Left CSS now works correctly when SCRIPT_DEBUG is enabled
* Changed: passkeys can now be used as a stand-alone feature
* Changed: standardized REST namespaces to really-simple-security

= 9.5.0.3 =
* Fixed: Prevent empty content to be written into htaccess

= 9.5.0.2 =
* Fixed: .htaccess protected from empty overwrites, auto-creation requires filter opt-in

= 9.5.0.1 =
* Fixed: removed unnecessary call to install() in firewall constructor
* Fixed: header_length_ok() now uses options instead of transients for caching
* Fixed: user agent and 404 detection are now excluded on cron requests
* Fixed: added a check to prevent a typeError in generating htaccess rules

= 9.5.0 =
* Fixed: replaced accidental Dutch word in 2FA datatable with correct English translation.
* Fixed: resolved PHP 8.4 deprecation warnings while maintaining compatibility with PHP 7.4–8.4.
* Fixed: whitelisted LiteSpeed Cache crawler in .htaccess to prevent redirect issues.
* Fixed: corrected 2FA grace period email logic to avoid sending reminders to users with active 2FA.
* Fixed: updated hosting provider name from "XXL Hosting" to "Superspace".
* Changed: reworked .htaccess handling with insert_with_markers and improved WP Rocket integration.
* Changed: moved firewall rules to separate firewall.php with dedicated rule classes.
* Changed: SBOM added to plugin.
* Changed: improved text consistency and updated geopolitical terminology

= 9.4.3 =
* Fixed: handled a case where the user ID could be empty in 2FA.
* Fixed: learn more button in vulnerability e-mail link now links to the correct page.
* Fixed: rsssl_user_can_manage undefined error when downloading system status
* Changed: improved compatibility with plain permalinks.
* Changed: handling of user agents in the firewall.
* Changed: auto cleanup 404 watchlist via cron job.
* Changed: updated links in the plugin.
* Changed: made various improvements to CSP learning mode.

= 9.4.2.1 =
* Fixed: changed a constant from uppercase to lowercase.

= 9.4.2 =
* Fixed: Adjusted .htaccess redirect requirements for subfolder configurations
* Fixed: re-send e-mail button on the 2FA page will now show a message when the e-mail is sent.
* Fixed: restored SCSS files.
* Fixed: fixed an issue where the plugin kept redirecting to its settings page after activation.
* Changed: limit login attempts will now also trigger on password reset pages.
* Changed: updated the way other plugins are installed via the onboarding and dashboard page.
* Changed: added notice with an option to force verify e-mail address.
* Changed: updated minimum WordPress version to 6.6.

= 9.4.1 =
 * Fixed: Fixed the feedback when an email is resend during Two-Factor Authentication setup.
 * Fixed: Fixed the Single Sign on link to support custom login urls.
 * Fixed: Fixed an issue where the composer autoloader was loaded twice.

= 9.4.0 =
 * Fixed: Validate CIDR ranges before bit-shifting in IP fetcher.
 * Fixed: Auto-allow Googlebot IPs in Firewall when blocking the United States.
 * Fixed: Adjust plugin initialization timing to prevent a textdomain warning.
 * Added: Passkey support for Two-Factor Authentication.
 * Added: Include SimplyBook in "onboarding" and "other plugins" sections.
 * Changed: More detailed feedback when using CLI commands.
 * Changed: On activation, detect `EXTENDIFY_PARTNER_ID` constant and run `wp rsssl activate_recommended_features`.
 * Changed: Standardize RSS onboarding hoster list to brand names.
 * Changed: "Disable user enumeration" now returns 401 Unauthorized (instead of 404 Not Found) for non-authenticated requests to the /wp/v2/users/ endpoint.

= 9.3.6 =
* Fixed: moved WooCommerce event listener to wp_loaded
* Fixed: 2FA methods can now be set on profile page
* Fixed: Show correct Project-ID-Version in translation files

= 9.3.4 =
* Fixed: Fixed an issue where TOTP codes were not properly validated.
* Fixed: login limits now skip WordPress Cron for better plugin compatibility
* Fixed: Eventlog no longer logs temp blocks for non-blocked IPs
* Fixed: Fixed an issue where Limit Login Attempts, temporary blocks were not correctly cleared.
* Changed: Added a better handling for Ip subnets cidr in Firewall.

= 9.3.3 =
* Fixed: Fixed a rare case where the autoloader could cause a Fatal Error due to loading twice
* Changed: Added multiple WP-CLI commands to better align with recent plugin features
* Changed: Added multiple improvements to File Permissions Check
* Changed: Added support for custom/multiple roles in Two Factor Authentication
* Removed: File Change Detection

= 9.3.2.1 =
* Fixed: Properly handle unknown plugins in upgrade requests, preventing unintended behavior.

= 9.3.2 =
* Fixed: Removed default checkbox behaviour from configuration settings.
* Fixed: loop when creating password protected page with custom login URL
* Fixed: handle multiple tooltip reasons for disabled select fields
* Fixed: Preventing double lines to occur in the advanced-headers.php file
* Changed: Added filters to customize Let's Encrypt Wizard behaviour

= 9.3.1 =
* Fixed: logout error with custom login URL in some cases

= 9.3.0 =
* Fixed: Improved user role handling to prevent undefined array key in 2FA.
* Fixed: All instruction links are now correct.
* Fixed: Undefined array key "m" when showing vulnerability details.
* Fixed: Prevent errors when downgrading to free.
* Fixed: Compatibility between 2FA and JetPack "Log in using WordPress.com account" setting
* Added: Create manual CSP entries.
* Changed: generating backup codes only when totp is being configured.
* Changed: Not able to use email needed functions when email is not yet verified.
* Changed: Added better text to verify the action of resending 2fa email.
* Changed: remove email token when login succeeds.
* Changed: Updated LLA database structure for MySQL 5.7 compatibility.

= 9.2.0 =
* Fixed: In some situations, header settings were lost after temporarily deactivating the plugin.
* Fixed: In some cases the review notice was not properly dismissible.
* Fixed: Added nonce check to certificate re-check button.
* Added: file change detection for suspicious changes outside of updates
* Changed: limited the number of header test requests for CSP learning mode
* Changed: 404 blocker skips homepage to prevent accidental lockouts
* Changed: Two-Factor Authentication now works with custom login screens.
* Changed: Updated endpoint version.
* Changed: disabling file permissions check will now correctly reset the file permissions list.

= 9.1.4 =
* Fixed: 404 blocker will now write the rules to the advanced-headers.php file immediately
* Fixed: fixed the dropdown height for the custom login URL 404 page picker
* Fixed: LLA Username block did not expire
* Fixed: stop showing notice when firewall is enabled.
* Fixed: Reset 2FA attempt counter & notice after successful TOTP login
* Fixed: 2fa sanitising produced a failed login.
* Fixed: password change enforcement uses batches to prevent memory issues
* Changed: do not track 404's for logged in users
* Changed: implemented the rsssl_wpconfig_path filter in all wp-config functions
* Changed: blocking IP no longer blocks associated username after login
* Changed: Faster onboarding completion after clicking Finish button
* Changed: CSS. Shields in user interface on datatables are no longer cut off

= 9.1.3 =
* Fixed: Remove duplicate site URL.
* Fixed: ensure rsssl_sanitize_uri_value() function always returns a string, to prevent errors.
* Fixed: multisite 2FA role enforcement fix for users with multiple roles
* Fixed: Skip Onboarding button undefined page with email method
* Changed: Width Vulnerabilities -> configuration
* Changed: 2Fa lockout notice
* Changed: catch use of short init in advanced-headers file
* Changed: string improvements and translator comments
* Changed: Bitnami support for rsssl_find_wordpress_base_path()
* Changed: integrate Site health notifications with Solid Security
* Changed: Enhanced random password generation in Rename Admin User feature
* Changed: Always return string in wpconfig_path() function
* Changed: Removes configuration options for a user in edit user.

= 9.1.2 =
* Changed: improved error handling

= 9.1.1.1 - 2024-11-05 =
* Fixed: fixed a bug where the 2FA grace period was kept active after a reset

= 9.1.1 - 2024-10-30 =
* Fixed: email login button not working
* Fixed: onboarding and login button did not save the correct configuration.
* Changed: safe-mode.lock file deactivates Firewall, 2FA and LLA for debugging
* Changed: update to system status
* Changed: textual changes
* Changed: Updated instructions URLs
* Changed: Changed site health notices from critical to recommended
* Changed: dropped obsolete react library
* Changed: add a site URL to email warnings regarding suspicious admin account creation
* Changed: Additional feedback if 2FA grace period has expired
* Changed: enforced 2FA users get email reminder 3 days before grace period expires

= 9.1.0 - 2024-10-22 =
* Fixed: prevent potential errors with login feedback..
* Fixed: Catch type error when $transients is not an array.
* Fixed: Custom Login URL compatibility with password protected pages.
* Fixed: Prevent potential errors when adding IP addresses to the Firewall allowlist.
* Added: User Agent Blocking.
* Changed: add captcha URL's to default Content Security Policy rules.
* Changed: Auto-removal of Free plugin and translation files when Pro is activated.
* Changed: Resize logo in 2FA e-mails.
* Changed: Allow scanning for security headers via http://scan.really-simple-ssl.com  with one click
* Changed: Exclude MPDF library in Complianz from Permission Detection.
* Changed: Remove unnecessary rsssl_update_option calls.

= 9.0.2 =
* Fixed: issue with deactivating 2fa

= 9.0.1 - 2024-09-16 =
* Fixed: Prevent duplicate DB queries on Firewall settings page
* Fixed: Instructions URL in the Firewall settings.
* Fixed: Block a custom login URL bypass on Multisite
* Fixed: Catch situation where an entry in the MaxMind DB returns null
* Fixed: Fixed incorrect instructions URL
* Fixed: Dismiss notice when dashboard is viewed
* Changed: dropped deprecated X-Frame-Options header in favor of frame-ancestors

= 9.0.0 - 2024-09-06 =
* Fixed: Let's Encrypt returning an old certificate on auto-renewed certificates
* Fixed: Multiselect in Limit login attempts
* Security: Login url bypass on multisite
* Security: 2fa bypass fix, props Julio Potier @SecuPress
* Changed: Better UX sync between CSP and frame ancestors
* Changed: save and continue in vulnerabilities overview not working correctly

= 8.3.0.1 =
* Fixed: Issues with the decryption model

= 8.3.0 - 2024-08-12 =
* Fixed: Fixed some strings that were not translatable. This has been resolved.
* Fixed: Premium support link did not work. Now links to the correct page.
* Fixed: Links in emails were sometimes not correct. This has been fixed.
* Fixed: Fatal error on permission detection. This has been resolved.
* Added: password security scan detects weak and compromised passwords
* Changed: Disable the cron schedules on deactivation.
* Changed: custom license check header improves hosting compatibility
* Changed: Added option to disable X-powered-by header.
* Changed: New improved encryption method for some settings.

= 8.2.6.1 =
* Fixed: Multisite fix.

= 8.2.6 - 2024-07-30 =
* Fixed: reduced advanced-headers file rewrites in dashboard

= 8.2.5 - 2024-07-25 =
* Fixed: possibility to bypass hide login url with certain internal URLs.
* Fixed: setting for hide remember me missing
* Fixed: code for two modules loaded even if not enabled.
* Added: 404 blocker and firewall, auto blocking IP's that generate 404 errors
* Added: File Change detection, get notified when files are changed
* Changed: added filter to write to other file than the wp-config.php
* Changed: added option to disable Limit Login Attempts with a constant, if the admin is locked out.
* Changed: added a constant which prevents inserting the .htaccess auto prepend rule
* Changed: admin notices now branded with 'Really Simple Security'

= 8.2.4 - 2024-06-20 =
* Fixed: documentation links to website broken
* Changed: some text changes in helptexts
* Changed: x-frame options synced with frame-ancestors
* Changed: new structure to upgrade database tables
* Changed: change login url compatibility with other plugin

= 8.2.3 - 2024-06-06 =
* Fixed: Reset user for two step email authentication from the settings page
* Fixed: Not loading cookie expiration change
* Fixed: Visual Composer compatibility icw Enforce Strong Password
* Fixed: Multiple CloudFlare detected notices in onboarding
* Fixed: Checkbox position in onboarding
* Changed: dropdown in onboarding not entirely visible
* Changed: Styling of locked XML RPC overview

= 8.2.2 - 2024-05-16 =
* Fixed: WP Rocket compatibility causing an issue when advanced-headers.php does not exist

= 8.2.1 - 2024-05-16 =
* Fixed: advanced-headers.php now supports early inclusion

= 8.2.0 - 2024-05-07 =
* Fixed: upgrade from <6.0 version to >8.0 causing a fatal error
* Fixed: URL to details of detected vulnerabilities was incorrect
* Added: detection of non-recommended permissions on files
* Added: Configure region restrictions for your site
* Changed: Textual change on premium overlay
* Changed: Upgraded minimum required PHP version to 7.4
* Changed: compatibility with Bitnami
* Changed: compatibility of Limit Login Attempts with Woocommerce
* Changed: remove duplicate X-Really-Simple-SSL-Test from advanced-headers-test.php
* Changed: clear notice about .htaccess writable if do_not_edit_htaccess is enabled

= 8.1.0 =
* Fixed: show 'self' as default in Frame Ancestors
* Added: Limit Login Attempts Captcha integration
* Changed: some string corrections
* Changed: catch not existing rsssl_version_compare
* Changed: check for openSSL module existence
* Changed: set default empty array for options, for legacy upgrades
* Changed: disable custom login URL when plain permalinks are enabled
* Changed: drop renamed folder notice, not needed anymore
* Changed: enable advanced headers in onboarding
* Changed: is_object check in updater

= 8.0.1 =
* Fixed: enable 2FA during onboarding when not selected by user
* Fixed: upgrading to Pro preserves settings when clear on deactivation enabled
* Fixed: catch several array key not existing errors
* Changed: better CSP defaults

= 8.0.0 =
* Added: hide remember me checkbox
* Added: extend blocking of malicious admin creation to multisite
* Changed: drop prefetch-src from Content Security Policy
* Changed: disable two-fa when login protection is disabled

= 7.2.8 =
* Fixed: clear cron schedules on deactivation
* Changed: translations update
* Changed: info notice about automatic free and pro plugin merge

= 7.2.7 =
* Changed: added integration with FlyingPress and Fastest Cache
* Changed: fix exiting a filter, causing a compatibility issue with BuddyPress

= 7.2.6 =
* Fixed: custom 404 pages i.c.w. custom login url
* Added: Added option to limit login cookie expiration time
* Changed: text changes
* Changed: css on login error message
* Changed: header detection improved by always checking the last url in the redirect chain

= 7.2.5 =
* Fixed: IP detection header order
* Fixed: table creation on activation of LLA module

= 7.2.4 =
* Fixed: PHP warning in Password Security module
* Fixed: change login url feature not working with password protected pages
* Changed: move database table creation to Limit Login Attempts module
* Changed: prevent php error caused by debug.log file hardening feature

= 7.2.3 =
* Fixed: CSP data not showing in datatable

= 7.2.2 =
* Changed: improved check for PharData class

= 7.2.1 =
* Fixed: Config for CSP preventing Learning mode from completing
* Fixed: datatable styling
* Fixed: using deactivate_https with wp-cli did not remove htaccess rules
* Changed: add query parameter to enforce email verification &rsssl_force_verification
* Changed: css for check certificate manually button

= 7.2.0 =
* Fixed: changed link to article
* Fixed: remove flags .js file which was added twice, props @adamainsworth
* Fixed: typo in missing advanced-headers.php notice
* Changed: catch php warning when script src is empty when using hide wp version, props @chris-yau
* Changed: new save & continue feedback
* Changed: datatable styling
* Changed: new react based modal
* Changed: menu re-structured
* Changed: re-check vulnerability status after core update
* Changed: vulnerability notification emails now link to specific details

= 7.1.3 - 2023-10-11 =
* Fixed: React ErrorBoundary preventing Let's Encrypt generation to complete.

= 7.1.2 - 2023-10-06 =
* Fixed: hook change in integrations loader causing modules not to load. props @rami5342

= 7.1.1 - 2023-10-05 =
* Fixed: incorrect function usage, props @heutger

= 7.1.0 - 2023-10-04 =
* Changed: detection if advanced-headers.php file is running

= 7.0.9 - 2023-09-05 =
* Changed: typo update word
* Changed: translatability in several strings.

= 7.0.8 - 2023-08-08 =
* Fixed: handling of legacy options in php 8.1
* Fixed: count remaining tasks
* Changed: WordPress tested up to 6.3
* Changed: improve file existence check json

= 7.0.7 - 2023-07-25 =
* Fixed: handling of legacy options in php 8.1
* Fixed: prevent issues with CloudFlare when submitting support form from within the plugin
* Fixed: translations singular/plural for japanese translations @maboroshin
* Changed: modal icon placement in wizard on smaller screens
* Changed: expire cached detected headers five minutes after saving the settings

= 7.0.6 - 2023-07-04 =
* Fixed: translations not loading for chunked react components
* Changed: support custom wp-content directory in advanced-headers.php
* Changed: prevent usage of subdirectories in custom login url
* Changed: added manual vulnerability recheck parameter

= 7.0.5 =
* Fixed: reverted redirect method to fix non-www site login issues

= 7.0.4 - 2023-06-14 =
* Fixed: feedback on hardening features enable action not showing as enabled, props @rtpHarry
* Changed: notice informing about the new free vulnerability detection feature
* Changed: improved the php redirect method
* Changed: make the wp-config.php not writable notice dismissable

= 7.0.3 =
* Fixed: fix false positives on some plugins
* Changed: vulnerability notifications in site health, if notifications are enabled.

= 7.0.2 =
* Changed: improve matching precision on plugins with vulnerabilities.

= 7.0.1 =
* Fixed: REST API ajax fallback now works correctly

= 7.0.0 =
* Added: Vulnerability Detection (Beta)
* Changed: move onboarding rest api to do_action rest_route
* Changed: catch several edge situations in SSL Labs api
* Changed: SSL Labs block responsiveness
* Changed: more robust handling of wp-config.php detection

= 6.3.0 =
* Changed: added support for the new Let's Encrypt staging environment

= 6.2.5 =
* Fixed: capability mismatch in multisite. props @verkkovaraani
* Changed: add warning alert option

= 6.2.4 =
* Fixed: catch non array value from notices array, props @kenrichman
* Fixed: typo in documenation link, props @bookman53
* Changed: optionally enable notification emails in onboarding wizard
* Changed: onboarding styling

= 6.2.3 =
* Changed: Changed Back-end react to functional components
* Changed: multisite notice should link to network admin page
* Changed: detect existing CAA records to check Let's Encrypt compatibility
* Changed: tested up to wp 6.2
* Changed: UX improvement learning mode

= 6.2.2 =
* Fixed: capability mismatch for a non administrator in multisite admin, props @jg-visual

= 6.2.1 =
* Fixed: race condition when activating SSL through wp-cli, because of upgrade script
* Fixed: missing disabled state in textarea and checkboxes
* Fixed: some strings not translatable
* Fixed: Let's Encrypt renewal with add on
* Changed: permissions check re-structuring
* Changed: notice on subsite within multisite environment about wildcard updated

= 6.2.0 =
* Added: optional email notifications on advanced settings
* Changed: added tooltips
* Changed: added warnings for .htaccess redirect
* Changed: don't send user email change on renaming admin user, as the email doesn't actually change
* Changed: Use BASEPATH only for wp-load.php, so symlinked folders will load based on ABSPATH
* Changed: Improved support for environments where Rest API is blocked

= 6.1.1 =
* Fixed: WP-CLI SSL activation fix when site not visited before
* Changed: prevent 'undefined' status showing up in api calls on settings page
* Changed: notice for incompatible Let's Encrypt shell add-on versions

= 6.1.0 =
* Fixed: empty menu item visible in Let's Encrypt menu
* Changed: some UX changes
* Changed: Limit number of notices in the dashboard
* Changed: load rest api request url over https if website is loaded over https

= 6.0.14 =
* Fixed: settings page when using plain permalinks, props @mvsitecreator, props @doug2son

= 6.0.13 =
* Fixed: CSS for blue labels in progress dashboard below 1080px
* Fixed: WPCLI SSL activation not working due to capability checks, props @oolongm
* Fixed: catch invalid account error in Let's Encrypt generation, props @bugsjr
* Fixed: do not block user enumeration for gutenberg
* Changed: improve method of dropping empty menu items in settings dashboard
* Changed: dynamic links in auto installer
* Changed: Let's Encrypt Auto installer not working correctly, props @mirkolofio
* Changed: change rest_api method to core wp apiFetch()
* Changed: scroll highlighted setting into view after clicking "fix" on a task
* Changed: HTTP method tests run in batches to prevent CURL timeouts
* Changed: clean up code-execution.php file after test, props @spinhead
* Changed: notification when DISABLE_FILE_EDITING is set to false
* Changed: drop some unnecessary translations
* Changed: WP version test uses options for better persistence

= 6.0.12 =
* Fixed: multisite admin username test uses correct database prefix
* Changed: allow submenu in back-end react application
* Changed: Skip value update when no change has been made
* Changed: no redirect on dismiss of admin notice, props @gangesh, @rtpHarry, @dumel
* Changed: remove obsolete warning
* Changed: qtranslate support on settings page

= 6.0.11 =
* Fixed: login check works when HTTP_X_WP_NONCE unavailable
* Fixed: admin notices now dismiss immediately

= 6.0.10 =
* Fixed: Apache 2.4 compatibility for upload directory code blocking
* Fixed: Varnish cache compatibility for REST API requests
* Fixed: manage_security capability added for upgraded users
* Fixed: allow for custom rest api prefixes, props @coderevolution
* Fixed: Let's Encrypt DNS verification save and action issues
* Fixed: REST API error handling prevents blank settings page
* Changed: Simplify user enumeration test
* Changed: catch unexpected response in SSL Labs object
* Changed: z-index on on boarding modal on smaller screen sizes, props @rtpHarry
* Changed: hide username field if no admin username is present, props @rtpHarry

= 6.0.9 =
* Fixed: incorrectly disabled email field in Let's Encrypt wizard, props @cburgess
* Changed: on rename admin user, catch existing username, and strange characters
* Changed: catch openBaseDir restriction in cpanel detection function, props @alofnur
* Changed: removed 6.0 update notices from subsites

= 6.0.8 =
* Changed: Lets Encrypt wizard CSS styling
* Changed: re-add link to article about Let's Encrypt so users can easily find the URL
* Changed: let user choose a new username when selecting "rename admin user"

= 6.0.7 =
* Fixed: restricted .htaccess rewrite to prevent plugin conflicts

= 6.0.6 =
* Fixed: drop upgrade of .htaccess file in upgrade script

= 6.0.5 =
* Fixed: .htaccess race condition with simultaneous updates

= 6.0.4 =
* Fixed: .htaccess redirect compatibility with upload code blocking
* Fixed: deactivation now fully removes wp-config.php changes

= 6.0.3 =
* Fixed: Rest Optimizer no longer deactivates other plugins

= 6.0.2 =
* Fixed: do not show WP_DEBUG_DISPLAY notice if WP_DEBUG is false, props @janv01
* Fixed: empty cron schedule, props @gilvansilvabr
* Fixed: auto installer used function not defined yet
* Fixed: rest api optimizer causing an error in some cases @giorgos93
* Changed: several typo's and string improvements

= 6.0.1 =
* Fixed: translations not loading for scripts

= 6.0.0 =
* Added: Server Health Check - powered by SSLLabs
* Added: WordPress Hardening Features
* Changed: User Interface
* Changed: Tested up to WordPress 6.1.0
