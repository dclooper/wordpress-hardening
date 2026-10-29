# WordPress Hardening

A lightweight WordPress plugin that adds common security hardening options, each with its own on/off switch under **Settings → Hardening**.

## Features

| Option | What it does |
| --- | --- |
| Hide your WordPress version | Removes the version from the page source, feeds and asset URLs. |
| Block user enumeration | Blocks username discovery through author pages, `?author=` URLs, the REST API users endpoint, the users sitemap and oEmbed data. Author archives redirect to the homepage for logged-out visitors. |
| Mask login error messages | Shows one generic message on failed logins, so attackers can't tell whether a username exists. |
| Disable the theme and plugin file editor | Removes the built-in code editor from wp-admin. |
| Add security headers | Sends `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`. |
| Rate-limit login attempts | Locks out an IP after a set number of failed logins. Attempts and lockout time are configurable (default: 5 attempts, 15 minutes). |
| Block IP addresses | Blocks the IPs and IPv4 ranges (CIDR) you list. Your own IP is never saved to the list. |
| Disable XML-RPC | Returns 403 for `xmlrpc.php`, disables pingbacks and removes the `X-Pingback` header. |

All options are enabled by default except **Block IP addresses**.

## Cloudflare

When a site is behind Cloudflare, the plugin uses the visitor IP from the `CF-Connecting-IP` header, but only for requests that come from Cloudflare's IP ranges. This keeps login rate limiting and IP blocking accurate without trusting a header anyone could fake.

## Requirements

- WordPress 5.5 or later
- PHP 7.0 or later (tested up to PHP 8.3)

## Installation

1. Download `wordpress-hardening.php` into `wp-content/plugins/wordpress-hardening/`.
2. Activate **WordPress Hardening** under **Plugins**.
3. Go to **Settings → Hardening** to choose which options to use.

## Notes

- Leave **Disable XML-RPC** off if a site uses Jetpack or the WordPress mobile app.
- Login lockouts apply to everyone, including administrators. If you lock yourself out, wait for the lockout to expire.
- To remove the plugin, deactivate and delete it. Settings are stored in the `wph_settings` option.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
