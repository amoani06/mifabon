/**
 * SureRank UTM URL builder
 *
 * Appends the standard SureRank UTM tracking parameters to a surerank.com URL.
 * If the URL already contains any UTM parameter it is returned unchanged.
 * Asset URLs (wp-content/uploads) are also returned unchanged.
 *
 * Standard UTM set:
 *   utm_source   = surerank_plugin
 *   utm_medium   = wordpress_plugin
 *   utm_campaign = <surface> (or core_plugin fallback)
 *   utm_content  = <context>   (e.g. 'learn_more', 'documentation')
 *
 * @since x.x.x
 */

/**
 * Build a surerank.com URL with standard UTM tracking parameters.
 *
 * @param {string} url      Base surerank.com URL (must be a valid absolute URL).
 * @param {string} campaign UTM campaign value — surface identifier using
 *                          lowercase letters, digits, and underscores
 *                          (e.g. 'admin_dashboard', 'onboarding').
 * @param {string} content  UTM content value — CTA / context identifier using
 *                          lowercase letters, digits, and underscores
 *                          (e.g. 'learn_more', 'documentation').
 * @return {string} URL with UTM parameters appended, or the original URL if
 *                  it already contains UTM parameters or is an asset URL.
 */
export const getSurerankUtmUrl = ( url, campaign, content ) => {
	// Guard: require all parameters.
	if ( ! url || ! campaign || ! content ) {
		return url || '';
	}

	// Normalize to https.
	const normalizedUrl = url.replace( /^http:\/\//i, 'https://' );

	// Leave asset URLs untouched.
	if ( normalizedUrl.includes( '/wp-content/uploads' ) ) {
		return normalizedUrl;
	}

	let urlObj;
	try {
		urlObj = new URL( normalizedUrl );
	} catch ( error ) {
		// Return original URL if it cannot be parsed (e.g. relative or malformed).
		return normalizedUrl;
	}

	// Leave URLs that already carry any UTM parameter untouched.
	if (
		urlObj.searchParams.has( 'utm_source' ) ||
		urlObj.searchParams.has( 'utm_medium' )
	) {
		return normalizedUrl;
	}

	urlObj.searchParams.set( 'utm_source', 'surerank_plugin' );
	urlObj.searchParams.set( 'utm_medium', 'wordpress_plugin' );
	urlObj.searchParams.set( 'utm_campaign', campaign || 'core_plugin' );
	urlObj.searchParams.set( 'utm_content', content );

	return urlObj.toString();
};
