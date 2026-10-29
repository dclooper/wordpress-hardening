<?php
/**
 * Plugin Name: WordPress Hardening
 * Plugin URI: https://github.com/dclooper/wordpress-hardening
 * Description: Security hardening toggles: hide WP version, block user enumeration, mask login errors, disable file editor, security headers, login rate limiting, IP blocklist and XML-RPC blocking.
 * Version: 1.0.0
 * Requires at least: 5.5
 * Requires PHP: 7.0
 * Author: Looper Global
 * Author URI: https://looper.global
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WP_Hardening {

	const OPTION = 'wph_settings';

	/** Cloudflare IPv4 ranges, used to trust the CF-Connecting-IP header only from Cloudflare. */
	private static $cf_ranges = array(
		'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
		'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
		'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
		'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
	);

	public static function features() {
		return array(
			'hide_version'     => array( 'Hide your WordPress version', 'Removes the WordPress version from your site\'s HTML, feeds and asset URLs so attackers can\'t target version-specific exploits.' ),
			'block_user_enum'  => array( 'Block user enumeration', 'Stops bots from listing your usernames through author pages, the REST API and your sitemap. Author archives redirect to your homepage for logged-out visitors.' ),
			'mask_login'       => array( 'Mask login error messages', 'Shows a single generic message on failed logins so attackers can\'t tell whether a username exists.' ),
			'disable_editor'   => array( 'Disable the theme and plugin file editor', 'Removes the built-in code editor from wp-admin so a compromised account can\'t inject PHP into your site.' ),
			'security_headers' => array( 'Add security headers', 'Sends hardening HTTP headers such as X-Frame-Options and X-Content-Type-Options to protect against clickjacking and content sniffing.' ),
			'rate_limit'       => array( 'Rate-limit login attempts', 'Locks out an IP address after too many failed logins in a short time to slow down brute-force attacks.' ),
			'block_ips'        => array( 'Block IP addresses', 'Turns away the IP addresses and ranges you list below before they reach WordPress.' ),
			'disable_xmlrpc'   => array( 'Disable XML-RPC', 'Closes the XML-RPC endpoint that attackers abuse to amplify brute-force attempts and pingback DDoS. Leave this off if your site relies on the WordPress mobile app or Jetpack.' ),
		);
	}

	public static function defaults() {
		$d = array();
		foreach ( array_keys( self::features() ) as $key ) {
			$d[ $key ] = 1;
		}
		$d['block_ips']       = 0;
		$d['max_attempts']    = 5;
		$d['lockout_minutes'] = 15;
		$d['ip_list']         = '';
		return $d;
	}

	public static function settings() {
		$saved = get_option( self::OPTION, array() );
		return wp_parse_args( is_array( $saved ) ? $saved : array(), self::defaults() );
	}

	public static function on( $key ) {
		$s = self::settings();
		return ! empty( $s[ $key ] );
	}

	public static function init() {
		if ( is_admin() ) {
			add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
			add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( __CLASS__, 'action_links' ) );
		}

		if ( self::on( 'block_ips' ) ) {
			self::maybe_block_ip();
		}
		if ( self::on( 'disable_xmlrpc' ) ) {
			self::disable_xmlrpc();
		}
		if ( self::on( 'disable_editor' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
		if ( self::on( 'hide_version' ) ) {
			self::hide_version();
		}
		if ( self::on( 'block_user_enum' ) ) {
			self::block_user_enum();
		}
		if ( self::on( 'mask_login' ) ) {
			add_filter( 'login_errors', array( __CLASS__, 'mask_login_errors' ) );
		}
		if ( self::on( 'security_headers' ) ) {
			add_action( 'send_headers', array( __CLASS__, 'send_security_headers' ) );
		}
		if ( self::on( 'rate_limit' ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'check_lockout' ), 30 );
			add_action( 'wp_login_failed', array( __CLASS__, 'record_failure' ) );
			add_action( 'wp_login', array( __CLASS__, 'clear_failures' ) );
		}
	}

	/* ---------- Client IP ---------- */

	private static function ip_in_cidr( $ip, $cidr ) {
		if ( false === strpos( $cidr, '/' ) ) {
			return $ip === $cidr;
		}
		list( $subnet, $bits ) = explode( '/', $cidr, 2 );
		$ip_l  = ip2long( $ip );
		$sub_l = ip2long( $subnet );
		$bits  = (int) $bits;
		if ( false === $ip_l || false === $sub_l || $bits < 0 || $bits > 32 ) {
			return false;
		}
		$mask = 0 === $bits ? 0 : ( -1 << ( 32 - $bits ) );
		return ( $ip_l & $mask ) === ( $sub_l & $mask );
	}

	public static function client_ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && filter_var( $remote, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			foreach ( self::$cf_ranges as $range ) {
				if ( self::ip_in_cidr( $remote, $range ) ) {
					$cf_ip = trim( (string) $_SERVER['HTTP_CF_CONNECTING_IP'] );
					return filter_var( $cf_ip, FILTER_VALIDATE_IP ) ? $cf_ip : $remote;
				}
			}
		}
		return $remote;
	}

	/* ---------- Block IP addresses ---------- */

	private static function parse_ip_list( $text ) {
		$out = array();
		foreach ( preg_split( '/[\s,]+/', (string) $text ) as $entry ) {
			$entry = trim( $entry );
			if ( '' === $entry ) {
				continue;
			}
			$base = explode( '/', $entry, 2 );
			if ( filter_var( $base[0], FILTER_VALIDATE_IP ) ) {
				$out[] = $entry;
			}
		}
		return array_values( array_unique( $out ) );
	}

	private static function maybe_block_ip() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}
		$s  = self::settings();
		$ip = self::client_ip();
		if ( '' === $ip ) {
			return;
		}
		foreach ( self::parse_ip_list( $s['ip_list'] ) as $entry ) {
			if ( self::ip_in_cidr( $ip, $entry ) ) {
				status_header( 403 );
				nocache_headers();
				exit( 'Forbidden' );
			}
		}
	}

	/* ---------- XML-RPC ---------- */

	private static function disable_xmlrpc() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			exit( 'XML-RPC is disabled on this site.' );
		}
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', '__return_empty_array' );
		add_filter( 'pings_open', '__return_false', 9999 );
		remove_action( 'wp_head', 'rsd_link' );
		add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
	}

	public static function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/* ---------- Hide version ---------- */

	private static function hide_version() {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
		add_filter( 'style_loader_src', array( __CLASS__, 'strip_version' ), 9999 );
		add_filter( 'script_loader_src', array( __CLASS__, 'strip_version' ), 9999 );
	}

	public static function strip_version( $src ) {
		if ( $src && false !== strpos( $src, 'ver=' . get_bloginfo( 'version' ) ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/* ---------- User enumeration ---------- */

	private static function block_user_enum() {
		add_action( 'template_redirect', array( __CLASS__, 'redirect_author_pages' ), 1 );
		add_filter( 'rest_endpoints', array( __CLASS__, 'hide_user_endpoints' ) );
		add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'remove_user_sitemap' ), 10, 2 );
		add_filter( 'oembed_response_data', array( __CLASS__, 'strip_oembed_author' ) );
	}

	public static function redirect_author_pages() {
		if ( is_user_logged_in() ) {
			return;
		}
		if ( isset( $_GET['author'] ) || is_author() ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	public static function hide_user_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	public static function remove_user_sitemap( $provider, $name ) {
		return ( 'users' === $name ) ? false : $provider;
	}

	public static function strip_oembed_author( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	/* ---------- Login errors ---------- */

	public static function mask_login_errors( $error ) {
		if ( false !== strpos( (string) $error, 'Too many failed login attempts' ) ) {
			return $error;
		}
		return '<strong>Error:</strong> Invalid login details.';
	}

	/* ---------- Security headers ---------- */

	public static function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
	}

	/* ---------- Login rate limiting ---------- */

	private static function attempts_key() {
		return 'wph_login_' . md5( self::client_ip() );
	}

	public static function check_lockout( $user ) {
		$s        = self::settings();
		$attempts = (int) get_transient( self::attempts_key() );
		if ( $attempts >= max( 1, (int) $s['max_attempts'] ) ) {
			return new WP_Error( 'wph_locked', '<strong>Error:</strong> Too many failed login attempts. Please try again later.' );
		}
		return $user;
	}

	public static function record_failure() {
		$s        = self::settings();
		$key      = self::attempts_key();
		$attempts = (int) get_transient( $key );
		set_transient( $key, $attempts + 1, max( 1, (int) $s['lockout_minutes'] ) * MINUTE_IN_SECONDS );
	}

	public static function clear_failures() {
		delete_transient( self::attempts_key() );
	}

	/* ---------- Admin ---------- */

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=wordpress-hardening' ) ) . '">Settings</a>' );
		return $links;
	}

	public static function admin_menu() {
		add_options_page( 'WordPress Hardening', 'Hardening', 'manage_options', 'wordpress-hardening', array( __CLASS__, 'render_page' ) );
	}

	public static function register_settings() {
		register_setting( 'wph_group', self::OPTION, array( 'sanitize_callback' => array( __CLASS__, 'sanitize' ) ) );
	}

	public static function sanitize( $input ) {
		$input = is_array( $input ) ? $input : array();
		$clean = array();
		foreach ( array_keys( self::features() ) as $key ) {
			$clean[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
		}
		$clean['max_attempts']    = min( 50, max( 1, isset( $input['max_attempts'] ) ? (int) $input['max_attempts'] : 5 ) );
		$clean['lockout_minutes'] = min( 1440, max( 1, isset( $input['lockout_minutes'] ) ? (int) $input['lockout_minutes'] : 15 ) );
		$list                     = self::parse_ip_list( isset( $input['ip_list'] ) ? $input['ip_list'] : '' );

		// Never let an admin lock themselves out.
		$me = self::client_ip();
		foreach ( $list as $i => $entry ) {
			if ( $me && self::ip_in_cidr( $me, $entry ) ) {
				unset( $list[ $i ] );
				add_settings_error( self::OPTION, 'wph_self', 'Removed ' . esc_html( $entry ) . ' from the block list because it matches your own IP address.' );
			}
		}
		$clean['ip_list'] = implode( "\n", $list );
		return $clean;
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s = self::settings();
		?>
		<div class="wrap wph">
			<h1>WordPress Hardening</h1>
			<?php settings_errors( self::OPTION ); ?>
			<form method="post" action="options.php">
				<?php settings_fields( 'wph_group' ); ?>
				<div class="wph-card">
					<?php foreach ( self::features() as $key => $f ) : ?>
						<div class="wph-row">
							<div class="wph-text">
								<strong><?php echo esc_html( $f[0] ); ?></strong>
								<p><?php echo esc_html( $f[1] ); ?></p>
								<?php if ( 'rate_limit' === $key ) : ?>
									<p class="wph-extra">
										Lock out after
										<input type="number" min="1" max="50" name="<?php echo esc_attr( self::OPTION ); ?>[max_attempts]" value="<?php echo esc_attr( $s['max_attempts'] ); ?>" class="small-text">
										failed logins for
										<input type="number" min="1" max="1440" name="<?php echo esc_attr( self::OPTION ); ?>[lockout_minutes]" value="<?php echo esc_attr( $s['lockout_minutes'] ); ?>" class="small-text">
										minutes.
									</p>
								<?php elseif ( 'block_ips' === $key ) : ?>
									<p class="wph-extra">One IP or IPv4 range per line (e.g. <code>203.0.113.7</code> or <code>203.0.113.0/24</code>). Your IP: <code><?php echo esc_html( self::client_ip() ); ?></code></p>
									<textarea name="<?php echo esc_attr( self::OPTION ); ?>[ip_list]" rows="5" class="large-text code"><?php echo esc_textarea( $s['ip_list'] ); ?></textarea>
								<?php endif; ?>
							</div>
							<label class="wph-switch">
								<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( ! empty( $s[ $key ] ) ); ?>>
								<span class="wph-slider"></span>
							</label>
						</div>
					<?php endforeach; ?>
				</div>
				<?php submit_button( 'Save changes' ); ?>
			</form>
		</div>
		<style>
			.wph-card{background:#fff;border:1px solid #dcdcde;border-radius:8px;max-width:960px;padding:0 20px}
			.wph-row{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;padding:16px 0;border-bottom:1px solid #f0f0f1}
			.wph-row:last-child{border-bottom:0}
			.wph-text strong{font-size:14px}
			.wph-text p{margin:4px 0 0;color:#50575e}
			.wph-extra{margin-top:8px!important}
			.wph-switch{position:relative;display:inline-block;width:40px;height:22px;flex:0 0 auto;margin-top:2px}
			.wph-switch input{opacity:0;width:0;height:0}
			.wph-slider{position:absolute;inset:0;background:#c3c4c7;border-radius:22px;cursor:pointer;transition:.2s}
			.wph-slider:before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
			.wph-switch input:checked + .wph-slider{background:#4f46e5}
			.wph-switch input:checked + .wph-slider:before{transform:translateX(18px)}
			.wph-switch input:focus-visible + .wph-slider{outline:2px solid #2271b1;outline-offset:2px}
		</style>
		<?php
	}
}

WP_Hardening::init();
