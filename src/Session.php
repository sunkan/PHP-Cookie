<?php
declare(strict_types=1);

/**
 * PHP-Cookie (https://github.com/delight-im/PHP-Cookie)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */
namespace ParagonIE\Cookie;

use Delight\Http\ResponseHeader;

/**
 * Session management with improved cookie handling
 *
 * You can start a session using the static method `Session::start(...)` which
 * is compatible to PHP's built-in `session_start()` function.
 *
 * Note that sessions must always be started before the HTTP headers are sent
 * to the client, i.e. before the actual output starts.
 */
final class Session
{
    /**
     * Starts or resumes a session in a way compatible to PHP's built-in `session_start()` function
     *
     * @param string $sameSiteRestriction Indicates that the cookie should not
     *                                    be sent along with cross-site
     *                                    requests (either `Lax`, `Strict`, or
     *                                    en empty string.)
     */
    public static function start(
        string $sameSiteRestriction = Cookie::SAME_SITE_RESTRICTION_STRICT
    ) {
        // run PHP's built-in equivalent
        \session_start();

        // intercept the cookie header (if any) and rewrite it
        self::rewriteCookieHeader($sameSiteRestriction);
    }

    /**
     * Returns the ID of the current session
     *
     * @return string the session ID or an empty string
     */
    public static function id(): string
    {
        return \session_id();
    }

    /**
     * Re-generates the session ID in a way compatible to PHP's built-in
     * `session_regenerate_id()` function.
     *
     * @param bool $deleteOldSession      Whether to delete the old session or
     *                                    not.
     * @param string $sameSiteRestriction Indicates that the cookie should not
     *                                    be sent along with cross-site
     *                                    requests (either `Lax`, `Strict`, or
     *                                    en empty string.)
     */
    public static function regenerate(
        bool $deleteOldSession = false,
        string $sameSiteRestriction = Cookie::SAME_SITE_RESTRICTION_STRICT
    ) {
        // run PHP's built-in equivalent
        \session_regenerate_id($deleteOldSession);

        // intercept the cookie header (if any) and rewrite it
        self::rewriteCookieHeader($sameSiteRestriction);
    }

    /**
     * Checks whether a value for the specified key exists in the session
     *
     * @param string $key The key to check
     * @return bool       Whether there is a value for the specified key or not
     */
    public static function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    /**
     * Returns the requested value from the session or, if not found, the
     * specified default value
     *
     * @param string $key         The key to retrieve the value for.
     * @param mixed $defaultValue The default value to return if the
     *                            requested value cannot be found.
     * @return mixed              The requested value or the default
     *                            value.
     */
    public static function get(string $key, $defaultValue = null)
    {
        if (isset($_SESSION[$key])) {
            return $_SESSION[$key];
        }
        return $defaultValue;
    }

    /**
     * Returns the requested value and removes it from the session
     *
     * This is identical to calling `get` first and then `remove` for the same
     * key.
     *
     * @param string $key         The key to retrieve and remove the value for.
     * @param mixed $defaultValue The default value to return if the requested
     *                            value cannot be found.
     * @return mixed              The requested value or the default value
     */
    public static function take(string $key, $defaultValue = null)
    {
        if (isset($_SESSION[$key])) {
            $value = $_SESSION[$key];

            unset($_SESSION[$key]);

            return $value;
        }
        return $defaultValue;
    }

    /**
     * Sets the value for the specified key to the given value
     *
     * Any data that already exists for the specified key will be overwritten
     *
     * @param string $key the key to set the value for
     * @param mixed $value the value to set
     */
    public static function set(string $key, $value)
    {
        $_SESSION[$key] = $value;
    }

    /**
     * Removes the value for the specified key from the session
     *
     * @param string $key the key to remove the value for
     */
    public static function delete(string $key)
    {
        unset($_SESSION[$key]);
    }

    /**
     * Intercepts and rewrites the session cookie header
     *
     * @param string $sameSiteRestriction Indicates that the cookie should not
     *                                    be sent along with cross-site
     *                                    requests (either `Lax`, `Strict`, or
     *                                    en empty string.)
     */
    private static function rewriteCookieHeader(
        $sameSiteRestriction = Cookie::SAME_SITE_RESTRICTION_STRICT
    ) {
        // get and remove the original cookie header set by PHP
        $originalCookieHeader = ResponseHeader::take('Set-Cookie', session_name().'=');

        // if a cookie header has been found
        if (isset($originalCookieHeader)) {
            // parse it into a cookie instance
            $parsedCookie = Cookie::parse($originalCookieHeader);

            // if the cookie has successfully been parsed
            if (isset($parsedCookie)) {
                // apply the supplied same-site restriction
                $parsedCookie->setSameSiteRestriction($sameSiteRestriction);
                // save the cookie
                $parsedCookie->save();
            }
        }
    }
}
