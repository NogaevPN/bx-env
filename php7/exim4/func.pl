#!/usr/bin/env perl
#===============================================================================
#
#         FILE: func.pl
#
#        USAGE: ./func.pl
#
#  DESCRIPTION:
#
#      OPTIONS: ---
# REQUIREMENTS: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: YOUR NAME (),
# ORGANIZATION:
#      VERSION: 1.0
#      CREATED: 11/24/2017 12:52:30 PM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;
use utf8;
use MIME::Base64;
use Redis;
use LWP::UserAgent;
use HTTP::Request::Common;
use JSON::PP;

my $HTTP_CALLBACK = '/bitrix/tools/track_mail_callback.php';
my $HTTP_TIMEOUT = 30;
my $HTTP_AGENT = "Bitrix24 Email Callbacks Service";
my $TOKEN_EXPIRE_GAP = 5;
my $HTTP_SCHEME = 'http'; #change to https for prod

sub trim
{
    my $string = shift;
    $string =~ s/^\s+|\s+$//g;

    return $string
}

sub debug_log
{
    my ($message) = @_;

    # print "$message\n";
    # or save to file
    #open(my $fh, '>>', '/tmp/exim_auth.log');
    #print $fh "$message\n";
    #close $fh;
}

sub prepare_password_for_smtp
{
    my $password = shift;
    $password =~ s/\^/\^\^/g;
    $password =~ s/\^\^\^\^/\^\^\^/g;

    return $password;
}

sub get_redis_key
{
    my ($uid) = @_;

    return "oauth_access_token_$uid";
}

sub get_from_cache
{
    my $uid = shift;
    my $key = get_redis_key($uid);
    my $result = '';

    eval {
        $result = Redis->new->get($key);

        return 1; #return from eval for correct error handling if key not exist
    } or do {
        debug_log("Redis get error: $@");
    };

    return $result;
}

sub set_to_cache
{
    my ($uid, $value, $ttl) = @_;
    if ($ttl <= 0)
    {
        $ttl = 10;
    }
    my $key = get_redis_key($uid);

    eval {
        Redis->new->setex($key, $ttl, $value);
    } or do {
        debug_log("Redis set error: $@");
    };
}

sub get_callback_params
{
    my $headers = shift;

    my $id = '';
    my $sign = '';
    my $host = '';

    if ($headers =~ /\nX-Bitrix-Mail-Callback-Id:(.*?)\n/)
    {
        $id = trim($1);
    }
    if ($headers =~ /\nX-Bitrix-Mail-Callback-Sign:(.*?)\n/)
    {
        $sign = trim($1);
    }
    if ($headers =~ /\nX-Bitrix-Mail-Callback-Host:(.*?)\n/)
    {
        $host = trim($1);
    }

    return ($id, $sign, $host);
}

sub http_request
{
    my ($host, $json) = @_;

    my $ua = LWP::UserAgent->new();
    $ua->timeout($HTTP_TIMEOUT);
    $ua->agent("$HTTP_AGENT");

    my $resp = $ua->request( POST "$HTTP_SCHEME://$host$HTTP_CALLBACK", [ data => $json ] );

    if ($resp->is_redirect)
    {
        my $location = $resp->header("Location");
        $resp = $ua->request( POST "$location", [ data => $json ] );
    }
    my $msg  = $resp->decoded_content;
    my $code = $resp->code;

    return ( $code, $msg );
}

sub prepare_request_json
{
    my ($uid, $sign, $expires, $callback_id, $callback_sign, $sender) = @_;

    return encode_json {
        list => [
            {
                id => $callback_id,
                sign => $callback_sign,
                status => 'refreshToken',
                email => $sender,
                refreshUid => $uid,
                refreshExpires => $expires,
                refreshSign => $sign,
            }
        ]
    };
}

sub parse_from_json_response
{
    my $body = shift;
    my $decoded = decode_json($body);
    my $tokenData = $ { $decoded } { list } { refreshedTokens } [0];
    my $token = $ { $tokenData } { accessToken };
    my $expires = $ { $tokenData } { expires };

    return ($token, $expires);
}

sub get_from_http_api
{
    my ($uid, $sign, $expires, $headers, $sender) = @_;
    my $token = '';
    my $new_expires = '';
    my ($callback_id, $callback_sign, $callback_host) = get_callback_params($headers);
    if ($callback_id and $callback_sign and $callback_host)
    {
        my $request_json = prepare_request_json($uid, $sign, $expires, $callback_id, $callback_sign, $sender);
        my ($response_code, $response_body) = http_request($callback_host, $request_json);
        if ($response_code == 200)
        {
            ($token, $new_expires) = parse_from_json_response($response_body);
        }
        else
        {
            debug_log("Error response with code: $response_code and body: $response_body")
        }
    }

    return ($token, $new_expires);
}

sub get_refreshed_token
{
    my ($uid, $sign, $expires, $headers, $sender) = @_;

    my $cached = get_from_cache($uid);
    if (length($cached))
    {
        return $cached;
    }

    my ($token, $new_expires) = get_from_http_api($uid, $sign, $expires, $headers, $sender);
    if (length($token) and $new_expires > 0)
    {
        my $ttl = $new_expires - time() - $TOKEN_EXPIRE_GAP;
        set_to_cache($uid, $token, $ttl);

        return $token;
    }

    return '';
}

sub extract_refresh_params
{
    my $headers = shift;

    my $expires = '';
    my $uid = '';
    my $sign = '';
    if ($headers =~ /\nX-Bitrix-Mail-Oauth-Expires:(.*?)\n/)
    {
        $expires = trim($1);
    }
    if ($headers =~ /\nX-Bitrix-Mail-Oauth-Uid:(.*?)\n/)
    {
        $uid = trim($1);
    }
    if ($headers =~ /\nX-Bitrix-Mail-Oauth-Sign:(.*?)\n/)
    {
        $sign = trim($1);
    }

    return ($uid, $sign, $expires);
}

sub compose_oauth_with_password
{
    my ($login, $password) = @_;
    if ($login and $password)
    {
        $password = prepare_password_for_smtp($password);

        return "user=$login\001auth=Bearer $password\001\001";
    }

    return '';
}

sub extract_login_from_headers
{
    my $headers = shift;
    my $login = '';
    if ($headers =~ /\nX-Bitrix-Mail-SMTP-User:(.*?)\n/)
    {
        $login = decode_base64($1);
    }

    return $login;
}

sub extract_password_from_headers
{
    my $headers = shift;
    my $password = '';
    if ($headers =~ /\nX-Bitrix-Mail-SMTP-Pass:\s*(.*?)\s*\n/)
    {
        $password = decode_base64($1);
    }

    return $password;
}

sub extract_xoauth
{
     my $headers = shift;
     my $login = extract_login_from_headers($headers);
     my $password = '';
     if ($headers =~ /\nX-Bitrix-Mail-Oauth:\s*(.*?)\s*\n/)
     {
         $password = $1;
         $password = $password . join('', $headers =~ /X-Bitrix-Mail-Oauth[0-9]:\s*(.*?)\s*\n/g);
         $password = decode_base64($password);
     }

    return compose_oauth_with_password($login, $password);
}

sub extract_xoauth_with_refresh
{
    my ($headers, $sender) = @_;
    my ($refreshUid, $refreshSign, $expires) = extract_refresh_params($headers);
    my $timeThreshold = time() + $TOKEN_EXPIRE_GAP;
    if (length($expires) and $refreshUid and $refreshSign and $expires < $timeThreshold)
    {
        my $token = get_refreshed_token($refreshUid, $refreshSign, $expires, $headers, $sender);
        if (length($token))
        {
            return compose_oauth_with_password(extract_login_from_headers($headers), $token);
        }
    }

    return extract_xoauth($headers);
}

sub extract_auth
{
    my $headers = shift;
    my $login = extract_login_from_headers($headers);
    my $password = extract_password_from_headers($headers);

    if ($login and $password)
    {
        $password = prepare_password_for_smtp($password);

        return "^$login^$password";
    }

    return '';
}

sub extract_login
{
     my $headers = shift;
     my $login = extract_login_from_headers($headers);
     my $password = extract_password_from_headers($headers);
     if ($login and $password)
     {
          return "$login";
     }

     return '';
}

sub extract_password
{
    my $headers = shift;
    my $login = extract_login_from_headers($headers);
    my $password = extract_password_from_headers($headers);

    if ($login and $password)
    {
        $password = prepare_password_for_smtp($password);

        return "$password";
    }

    return '';
}


sub log_error($$)
{
     my $headers = shift;
     my $message = shift;
     if($headers =~ /\nsmtp-error-log:(.*?)\n/) {
        my $error_log = $1;
        open(OUT, ">$error_log");
        print OUT $message;
        close(OUT);
     }
     return $message;
}

