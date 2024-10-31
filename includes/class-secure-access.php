<?php
/**
 * Shared functionality of Secure Access used by public and admin
 * console hooks.
 *
 * @link https://github.com/bobbywalters/secure-access
 * @package SecureAccess
 * @since 1.0.1
 */

/**
 * The SecureAccess class provides shared functionality across public
 * and administration screens. The plugin bootstrap file sets a global
 * reference to `$secure_access` pointing to an instance of this class.
 *
 * @package SecureAccess
 * @author Bobby Walters
 */
class SecureAccess {
	/**
	 * Registers most of the hooks back into WordPress.
	 *
	 * @see add_action()
	 * @see add_filter()
	 */
	function __construct() {
		add_action( 'init', array( &$this, 'init' ) );
		add_action( 'login_form_login', array( &$this, 'login_form_login' ) );
		add_action( 'login_head', array( &$this, 'login_head' ), 99 );

		add_filter( 'do_parse_request', array( &$this, 'do_parse_request' ), 1, 3 );
		add_filter( 'logout_url', array( &$this, 'logout_url' ), 99, 2 );
	}

	/**
	 * A filter for "do_parse_request" that actually triggers the logic
	 * for secure access.
	 *
	 * This fitler performs the security check and may cause a redirect
	 * if the user has not logged in yet. The secure access check will
	 * not be performed if the current page is one of the log in screens.
	 *
	 * @param bool         $bool             Whether or not to parse
	 * the request. Default `true`.
	 * @param WP           $wp               Current WordPress
	 * environment instance.
	 * @param array|string $extra_query_vars Extra query variables.
	 * @return bool `true` if the request should be parsed.
	 * @global string $pagenow The current PHP page being displayed.
	 * Will always end with ".php" and will never be empty.
	 * @see auth_redirect()
	 * @see is_user_logged_in()
	 */
	function do_parse_request( $bool, $wp, $extra_query_vars ) {
		global $pagenow;
		switch ( $pagenow ) {
			case 'wp-login.php':
			case 'wp-signup.php':
				return $bool;
		}

		if ( ! is_user_logged_in() ) {
			auth_redirect();
		}

		return $bool;
	}

	/**
	 * An action for "init" that loads the secure access text domain for
	 * internationalization (i18n) support.
	 *
	 * The directory containing the gettext files is "languages" at the
	 * base of the plugin directory by default.
	 *
	 * @see load_plugin_textdomain()
	 */
	function init() {
		load_plugin_textdomain( 'secure-access', false, 'secure-access/languages' );
	}

	/**
	 * An action for "login_form_login" that will register two (2)
	 * filters for proper handling of the log in screen messages.
	 *
	 * @uses SecureAccess::login_message()
	 * @uses SecureAccess::wp_login_errors()
	 * @see add_filter()
	 */
	function login_form_login() {
		add_filter( 'login_message', array( &$this, 'login_message' ) );
		add_filter( 'wp_login_errors', array( &$this, 'wp_login_errors' ), 99, 2 );
	}

	/**
	 * An action for "login_head" to echo out some CSS rules that secure
	 * the site a little bit better.
	 */
	function login_head() {
		echo '<style type="text/css">#login>h1:first-child,#backtoblog{display:none}</style>';
	}

	/**
	 * A filter for "login_message" that will add the secure access
	 * message only if the supplied $message is empty.
	 *
	 * The secure access message will only be added if no other error or
	 * regular status message is set.
	 *
	 * @param string $message A message possibly coming from another
	 * plugin that will be displayed on the log in screen.
	 * @return string The login message to display.
	 * @see SecureAccess::wp_login_errors()
	 */
	function login_message( $message ) {
		if ( $message ) {
			remove_filter( 'wp_login_errors', array( &$this, 'wp_login_errors' ), 99 );
		}

		return $message;
	}

	/**
	 * A filter for "logout_url" that removes the "redirect_to" request
	 * parameter to get a proper logged out message.
	 *
	 * If this filter wasn't in place, the redirect would immediately
	 * happen after logging out but since the site is secured the user
	 * would be prompted to log in anyway. This cuts down on the traffic
	 * and keeps the messages back to the user correct.
	 *
	 * @param string $logout_url The URL to log out of the site.
	 * @param string $redirect   The URL that the user would have been
	 * redirected to.
	 * @return string A safe logout URL.
	 */
	function logout_url( $logout_url, $redirect ) {
		// It seems $logout_url will be escaped for HTML at this point.
		if ( $redirect ) {
			$logout_url = str_replace(
				array( 'redirect_to=' . urlencode( $redirect ), '?&amp;', '&amp;&amp;' ),
				array( '', '?', '&amp;' ),
			$logout_url);
		}

		return $logout_url;
	}

	/**
	 * A filter for "wp_login_errors" that adds the secure access log
	 * in message if no other message is queued up for display.
	 *
	 * This filter is conditionally registered for the login screen and
	 * the login action. Registration, verify e-mail, etc screens will
	 * never add the secure access message.
	 *
	 * @param WP_Error $errors      A collection of error codes and
	 * messages that will be displayed back to the user. There may not
	 * be errors added to the object but the object itself will never
	 * be `null`.
	 * @param string   $redirect_to A URL that the user will be
	 * redirected to.
	 * @return WP_Error An appropriate set of (error) messages to
	 * display on the login screen.
	 * @global string $error A single error message that plugins may use
	 * instead of the errors object to pass a message along to the user.
	 */
	function wp_login_errors( $errors, $redirect_to ) {
		global $error;

		if ( ! $error && ! $errors->get_error_code() ) {
			$errors->add(
				'secureaccess',
				esc_html__( 'Please log in to view this site.', 'secure-access' ),
				'message'
			);
		}

		return $errors;
	}
}
