<?php
declare(strict_types=1);
/**
 * PHP-Cookie (https://github.com/delight-im/PHP-Cookie)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 *
 * Forked by Paragon Initiative Enterprises.
 */

namespace ParagonIE\Cookie;

/**
 * Modern cookie management for PHP
 *
 * Cookies are a mechanism for storing data in the client's web browser and
 * identifying returning clients on subsequent visits.
 *
 * All cookies that have successfully been set will automatically be included
 * in the global `$_COOKIE` array with future requests.
 *
 * You can set a new cookie using the static method `Cookie::setcookie(...)`
 * which is compatible to PHP's built-in `setcookie(...)` function.
 *
 * Alternatively, you can construct an instance of this class, set properties
 * individually, and finally call `save()`.
 *
 * Note that cookies must always be set before the HTTP headers are sent to the
 * client, i.e. before the actual output starts.
 */
final class Cookie
{
    const SAME_SITE_RESTRICTION_LAX = 'Lax';
    const SAME_SITE_RESTRICTION_STRICT = 'Strict';

    /**
     * @var string The name of the cookie which is also the key for future
     *             accesses via `$_COOKIE[...]`
     */
    private $name;

    /**
     * @var mixed The value of the cookie that will be stored on the
     *            client's machine
     */
    private $value;

    /**
     * @var int The Unix timestamp indicating the time that the cookie will
     *          expire, i.e. usually `time() + $seconds`
     */
    private $expiryTime;

    /**
     * @var string The path on the server that the cookie will be valid for
     *             (including all sub-directories), e.g. an empty string for
     *             the current directory or `/` for the root directory
     */
    private $path;

    /**
     * @var string The domain that the cookie will be valid for (including all
     *             subdomains)
     */
    private $domain;

    /**
     * @var bool Indicates that the cookie should be accessible through the
     *           HTTP protocol only and not through scripting languages
     */
    private $httpOnly;

    /**
     * @var bool Indicates that the cookie should be sent back by the client
     * over secure HTTPS connections only
     */
    private $secureOnly;

    /**
     * @var string Indicates that the cookie should not be sent along with
     *             cross-site requests (either `null`, `Lax` or `Strict`)
     */
    private $sameSiteRestriction;

    /**
     * Prepares a new cookie
     *
     * @param string $name The name of the cookie which is also the key for
     *                     future accesses via `$_COOKIE[...]`.
     * @param string $domain The domain that the cookie will be valid for (including all subdomains)
     */
    public function __construct(string $name, string $domain = null)
    {
        $this->name = $name;
        $this->value = null;
        $this->expiryTime = 0;
        $this->path = '/';
        $this->setDomain(self::normalizeDomain($domain ?? $_SERVER['HTTP_HOST']));        
        $this->httpOnly = true;
        $this->secureOnly = false;
        $this->sameSiteRestriction = self::SAME_SITE_RESTRICTION_STRICT;
    }

    /**
     * Sets the value for the cookie
     *
     * @param mixed $value The value of the cookie that will be stored on the
     *                     client's machine.
     * @return self        This instance for chaining
     */
    public function setValue($value): self
    {
        $this->value = $value;

        return $this;
    }

    /**
     * Sets the expiry time for the cookie
     *
     * @param int $expiryTime The Unix timestamp indicating the time that the
     *                        cookie will expire, i.e. usually
     *                        `time() + $seconds`.
     * @return self           This instance for chaining
     */
    public function setExpiryTime(int $expiryTime)
    {
        $this->expiryTime = $expiryTime;

        return $this;
    }

    /**
     * Sets the expiry time for the cookie based on the specified maximum age
     *
     * @param int $maxAge The maximum age for the cookie in seconds.
     * @return self       This instance for chaining
     */
    public function setMaxAge(int $maxAge)
    {
        $this->expiryTime = time() + $maxAge;

        return $this;
    }

    /**
     * Sets the path for the cookie
     *
     * @param string $path The path on the server that the cookie will be valid
     *                     for (including all sub-directories), e.g. an empty
     *                     string for the current directory or `/` for the root
     *                     directory.
     * @return self        This instance for chaining
     */
    public function setPath(string $path): self
    {
        $this->path = $path;

        return $this;
    }

    /**
     * Sets the domain for the cookie
     *
     * @param string $domain The domain that the cookie will be valid for (including all subdomains)
     * @param bool $keepWww  whether a leading `www` subdomain must be preserved or not
     * @return self          This instance for chaining
     */
    public function setDomain(string $domain, bool $keepWww = false): self
    {
        $this->domain = self::normalizeDomain($domain, $keepWww);

        return $this;
    }

    /**
     * Sets whether the cookie should be accessible through HTTP only
     *
     * @param bool $httpOnly Indicates that the cookie should be accessible
     *                       through the HTTP protocol only and not through
     *                       scripting languages.
     * @return self          This instance for chaining
     */
    public function setHttpOnly(bool $httpOnly): self
    {
        $this->httpOnly = $httpOnly;

        return $this;
    }

    /**
     * Sets whether the cookie should be sent over HTTPS only
     *
     * @param bool $secureOnly Indicates that the cookie should be sent back by
     *                         the client over secure HTTPS connections only.
     * @return self            This instance for chaining
     */
    public function setSecureOnly(bool $secureOnly): self
    {
        $this->secureOnly = $secureOnly;

        return $this;
    }

    /**
     * Sets the same-site restriction for the cookie
     *
     * @param string $sameSiteRestriction Indicates that the cookie should not
     *                                    be sent along with cross-site
     *                                    requests (either `Lax`, `Strict`, or
     *                                    an empty string).
     * @return self                       This instance for chaining
     */
    public function setSameSiteRestriction(string $sameSiteRestriction): self
    {
        $this->sameSiteRestriction = $sameSiteRestriction;

        return $this;
    }

    /**
     * Saves the cookie
     *
     * @return bool Whether the cookie header has successfully been sent (and
     *              will *probably* cause the client to set the cookie)
     */
    public function save(): bool
    {
        return self::addHttpHeader((string) $this);
    }

    /**
     * Deletes the cookie
     *
     * @return bool Whether the cookie header has successfully been sent (and
     *              will *probably* cause the client to delete the cookie)
     */
    public function delete(): bool
    {
        // create a temporary copy of this cookie so that it isn't corrupted
        $copiedCookie = clone $this;

        // set the copied cookie's value to an empty string which internally
        // sets the required options for a deletion
        $copiedCookie->setValue('');

        // save the copied "deletion" cookie
        return $copiedCookie->save();
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return self::buildCookieHeader(
            $this->name,
            $this->value,
            $this->expiryTime,
            $this->path,
            $this->domain,
            $this->secureOnly,
            $this->httpOnly,
            $this->sameSiteRestriction
        );
    }

    /**
     * Sets a new cookie in a way compatible to PHP's `setcookie(...)` function
     *
     * @param string $name                The name of the cookie which is also
     *                                    the key for future accesses via
     *                                    `$_COOKIE[...]`.
     * @param mixed $value                The value of the cookie that will be
     *                                    stored on the client's machine.
     * @param int $expiryTime             The Unix timestamp indicating the
     *                                    time that the cookie will expire,
     *                                    i.e. usually `time() + $seconds`.
     * @param string $path                The path on the server that the cookie
     *                                    will be valid for (including all sub-
     *                                    directories), e.g. an empty string for
     *                                    the current directory or `/` for the
     *                                    root directory.
     * @param string $domain              The domain that the cookie will be
     *                                    valid for (including all subdomains).
     * @param bool $secureOnly            Indicates that the cookie should be
     *                                    sent back by the client over secure
     *                                    HTTPS connections only.
     * @param bool $httpOnly              Indicates that the cookie should be
     *                                    accessible through the HTTP protocol
     *                                    only and not through scripting
     *                                    languages.
     * @param string $sameSiteRestriction Indicates that the cookie should not
     *                                    be sent along with cross-site
     *                                    requests (either `Lax`, `Strict`, or
     *                                    an empty string).
     * @return bool                       Whether the cookie header has successfully
     *                                    been sent (and will *probably* cause
     *                                    the client to set the cookie).
     */
    public static function setcookie(
        string $name,
        $value = null,
        int $expiryTime = 0,
        string $path = '',
        string $domain = '',
        bool $secureOnly = true,
        bool $httpOnly = true,
        string $sameSiteRestriction = self::SAME_SITE_RESTRICTION_STRICT
    ): bool {
        $cookieHeader = self::buildCookieHeader(
            $name,
            $value,
            $expiryTime,
            $path,
            $domain,
            $secureOnly,
            $httpOnly,
            $sameSiteRestriction
        );

        return self::addHttpHeader($cookieHeader);
    }

    /**
     * Builds the HTTP header that can be used to set a cookie with the
     * specified options.
     *
     * @param string $name                The name of the cookie which is also
     *                                    the key for future accesses via
     *                                    `$_COOKIE[...]`.
     * @param mixed $value                The value of the cookie that will be
     *                                    stored on the client's machine.
     * @param int $expiryTime             The Unix timestamp indicating the
     *                                    time that the cookie will expire,
     *                                    i.e. usually `time() + $seconds`.
     * @param string $path                The path on the server that the cookie
     *                                    will be valid for (including all sub-
     *                                    directories), e.g. an empty string for
     *                                    the current directory or `/` for the
     *                                    root directory.
     * @param string $domain              The domain that the cookie will be
     *                                    valid for (including all subdomains).
     * @param bool $secureOnly            Indicates that the cookie should be
     *                                    sent back by the client over secure
     *                                    HTTPS connections only.
     * @param bool $httpOnly              Indicates that the cookie should be
     *                                    accessible through the HTTP protocol
     *                                    only and not through scripting
     *                                    languages.
     * @param string $sameSiteRestriction Indicates that the cookie should not
     *                                    be sent along with cross-site
     *                                    requests (either `Lax`, `Strict`, or
     *                                    an empty string).
     * @return string the HTTP header
     * @throws \Exception
     */
    public static function buildCookieHeader(
        string $name,
        $value = null,
        int $expiryTime = 0,
        string $path = '',
        string $domain = '',
        bool $secureOnly = true,
        bool $httpOnly = true,
        string $sameSiteRestriction = self::SAME_SITE_RESTRICTION_STRICT
    ): string {
        if (!self::isNameValid($name)) {
            throw new \Exception('Invalid cookie name');
        }

        if (!self::isExpiryTimeValid($expiryTime)) {
            throw new \Exception('Invalid expiration time');
        }

        $forceShowExpiry = false;

        if (empty($value)) {
            $value = 'deleted';
            $expiryTime = 0;
            $forceShowExpiry = true;
        }

        $maxAgeStr = self::formatMaxAge(
            $expiryTime,
            $forceShowExpiry
        );
        $expiryTimeStr = self::formatExpiryTime(
            $expiryTime,
            $forceShowExpiry
        );

        $headerStr = 'Set-Cookie: ' . $name . '=' . urlencode($value);

        if (!empty($expiryTimeStr)) {
            $headerStr .= '; expires=' . $expiryTimeStr;
        }

        if (!empty($maxAgeStr)) {
            $headerStr .= '; Max-Age=' . $maxAgeStr;
        }

        if (!empty($path) || $path === 0) {
            $headerStr .= '; path=' . $path;
        }

        if (!empty($domain) || $domain === 0) {
            $headerStr .= '; domain=' . $domain;
        }

        if ($secureOnly) {
            $headerStr .= '; secure';
        }

        if ($httpOnly) {
            $headerStr .= '; httponly';
        }

        if ($sameSiteRestriction === self::SAME_SITE_RESTRICTION_LAX) {
            $headerStr .= '; SameSite=Lax';
        }
        elseif ($sameSiteRestriction === self::SAME_SITE_RESTRICTION_STRICT) {
            $headerStr .= '; SameSite=Strict';
        }

        return $headerStr;
    }

    /**
     * Parses the given cookie header and returns an equivalent cookie instance
     *
     * @param string $cookieHeader the cookie header to parse
     * @return self
     * @throws \Exception
     */
    public static function parse(string $cookieHeader): self
    {
        if (empty($cookieHeader)) {
            throw new \Exception('Not a valid Set-Cookie header.');
        }

        if (\preg_match('/^Set-Cookie: (.*?)=(.*?)(?:; (.*?))?$/i', $cookieHeader, $matches)) {
            if (\count($matches) >= 4) {
                $attributes = \explode('; ', $matches[3]);

                $cookie = new self($matches[1]);
                $cookie->setPath('');
                $cookie->setHttpOnly(false);
                $cookie->setValue($matches[2]);

                foreach ($attributes as $attribute) {
                    if (\strcasecmp($attribute, 'HttpOnly') === 0) {
                        $cookie->setHttpOnly(true);
                    } elseif (\strcasecmp($attribute, 'Secure') === 0) {
                        $cookie->setSecureOnly(true);
                    } elseif (\stripos($attribute, 'Expires=') === 0) {
                        $cookie->setExpiryTime((int) strtotime(substr($attribute, 8)));
                    } elseif (\stripos($attribute, 'Domain=') === 0) {
                        $cookie->setDomain(substr($attribute, 7), true);
                    } elseif (\stripos($attribute, 'Path=') === 0) {
                        $cookie->setPath(substr($attribute, 5));
                    }
                }
                return $cookie;
            }
        }
        throw new \Exception('Not a valid Set-Cookie header.');
    }

    /**
     * Is a cookie name valid?
     *
     * @param $name
     * @return bool
     */
    private static function isNameValid(string $name): bool
    {
        if ($name !== '') {
            if (!\preg_match('/[=,; \\t\\r\\n\\013\\014]/', $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param $expiryTime
     * @return bool
     */
    private static function isExpiryTimeValid($expiryTime): bool
    {
        return \is_numeric($expiryTime);
    }

    /**
     * @param $expiryTime
     * @return int
     */
    private static function calculateMaxAge(int $expiryTime): int
    {
        if ($expiryTime === 0) {
            return 0;
        }
        return $expiryTime - time();
    }

    /**
     * Format expiry time.
     *
     * @param $expiryTime
     * @param bool $forceShow
     * @return string
     */
    private static function formatExpiryTime(
        int $expiryTime,
        bool $forceShow = false
    ): string {
        if ($expiryTime > 0 || $forceShow) {
            if ($forceShow) {
                $expiryTime = 1;
            }

            $date = \gmdate('D, d-M-Y H:i:s T', $expiryTime);
            if ($date !== false) {
                return $date;
            }
        }
        return '';
    }

    /**
     * Format maximum cookie age.
     *
     * @param int $expiryTime
     * @param bool $forceShow
     * @return string
     */
    private static function formatMaxAge(
        int $expiryTime,
        bool $forceShow = false
    ): string {
        if ($expiryTime > 0 || $forceShow) {
            return (string) self::calculateMaxAge($expiryTime);
        }
        return '';
    }

    /**
     * Normalize a domain name.
     *
     * @param string $domain
     * @param bool $keepWww
     * @return string
     */
    private static function normalizeDomain(
        string $domain = '',
        bool $keepWww = false
    ): string {
        // if the cookie should be valid for the current host only
        if ($domain === '') {
            // no need for further normalization
            return '';
        }

        // if the provided domain is actually an IP address
        if (\filter_var($domain, FILTER_VALIDATE_IP) !== false) {
            // let the cookie be valid for the current host
            return '';
        }

        // for local hostnames (which either have no dot at all or a leading dot only)
        if (\strpos($domain, '.') === false || \strrpos($domain, '.') === 0) {
            // let the cookie be valid for the current host while ensuring
            // maximum compatibility
            return '';
        }

        // unless the domain already starts with a dot
        if ($domain[0] !== '.') {
            // prepend a dot for maximum compatibility (e.g. with RFC 2109)
            $domain = '.' . $domain;
        }

        // if a leading `www` subdomain may be dropped
        if (!$keepWww) {
            // if the domain name actually starts with a `www` subdomain
            if (\substr($domain, 0, 5) === '.www.') {
                // strip that subdomain
                $domain = \substr($domain, 4);
            }
        }

        // return the normalized domain
        return $domain;
    }

    /**
     * Send an additional HTTP header.
     *
     * @param $header
     * @return bool
     */
    private static function addHttpHeader(string $header): bool
    {
        if (!\headers_sent()) {
            if (!empty($header)) {
                \header($header, false);

                return true;
            }
        }

        return false;
    }
}
