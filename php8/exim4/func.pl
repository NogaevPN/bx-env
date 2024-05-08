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

sub trim 
{ 
    my $string = shift; 
    $string =~ s/^\s+|\s+$//g; 
    return $string  
}

sub compute_headers
{
    my $headers = shift;
    $headers =~ s/\r\n/\n/g;
    
    my @rows = split(/\n/, $headers);
    my @computed_headers = ();
    my $header_started = 0;

    foreach(@rows)
    {
      my($name, $value) = split(':', $_, 2);
  
      if($name && $value) 
      {
	 push(@computed_headers, "$name:$value");
	 $header_started = 1;
      } 
      elsif ($name && $header_started && $#computed_headers) 
      {
  	 @computed_headers[$#computed_headers] = $computed_headers[$#computed_headers] . $name;
      } 
      elsif (!$name) 
      {
         $header_started = 0;
      }
   }
   
   return "\n" . join("\n", @computed_headers) . "\n";
}

#sub extract_auth($$)
#{
#    my $headers = shift;
#    $headers =~ /\nX-Bitrix-Mail-SMTP-User:(.*?)\n/;
#    my $login = trim($1);
#    my $password = '';
#    $headers =~ /\nX-Bitrix-Mail-SMTP-Pass:(.*?)\n/;
#    my $password = trim($1); 
#    if ($login and $password) {
#        return "^$login^$password"; 
#    } else {
#        return "";
#    }
#}
sub extract_auth($$)
{
     my $headers = shift;
#     $headers = compute_headers($headers);
     my $login = '';
     my $password = '';
     if ($headers =~ /\nX-Bitrix-Mail-SMTP-User:(.*?)\n/) {
             $login = $1;
             #if ($login  =~ m/^=\?(.+)\?=/) {
                     $login = decode_base64($1);
                     #}
     }
     if ($headers =~ /\nX-Bitrix-Mail-SMTP-Pass:\s*(.*?)\s*\n/) {
             $password = $1;
             #if ($password =~ m/^=\?(.+)\?=/) {
                     $password = decode_base64($1);
                     #}
     }
     if ($login and $password) {
             $password =~ s/\^/\^\^/g;
             $password =~ s/\^\^\^\^/\^\^\^/g;
             return "^$login^$password";
     } else {
             return "";
     }
}

sub extract_xoauth($$)
{
     my $headers = shift;
#     log_au("before:\n\n $headers\n");
     
#     $headers = compute_headers($headers);
     
#     log_au("after:\n\n $headers\n");
     my $login = '';
     my $password = '';
     if ($headers =~ /\nX-Bitrix-Mail-SMTP-User:(.*?)\n/) {
             $login = $1;
             $login = decode_base64($1);
     }
     if ($headers =~ /\nX-Bitrix-Mail-Oauth:\s*(.*?)\s*\n/) {
             $password = $1;
             log_au("password_before:\n\n $password\n");
             $password = $password . join('', $headers =~ /X-Bitrix-Mail-Oauth[0-9]:\s*(.*?)\s*\n/g);
             log_au("password_after:\n\n $password\n");
             $password = decode_base64($password);
     }
     if ($login and $password) {
        $password =~ s/\^/\^\^/g;
        $password =~ s/\^\^\^\^/\^\^\^/g;

        return "user=$login\001auth=Bearer $password\001\001";
     } else {
        return "";
     }
}


sub extract_login($$)
{
     my $headers = shift;
     my $login = '';
     my $password = '';
     if ($headers =~ /\nX-Bitrix-Mail-SMTP-User:(.*?)\n/) {
            $login = $1;
            $login = decode_base64($1);
     }
     if ($headers =~ /\nX-Bitrix-Mail-SMTP-Pass:\s*(.*?)\s*\n/) {
            $password = $1;
            $password = decode_base64($1);
     }
     if ($login and $password) {
             return "$login";
     } else {
             return "";
     }
}


sub extract_password($$)
{
     my $headers = shift;
     my $login = '';
     my $password = '';
     if ($headers =~ /\nX-Bitrix-Mail-SMTP-User:(.*?)\n/) {
            $login = $1;
            $login = decode_base64($1);
     }
     if ($headers =~ /\nX-Bitrix-Mail-SMTP-Pass:\s*(.*?)\s*\n/) {
            $password = $1;
            $password = decode_base64($1);
     }
     if ($login and $password) {
         $password =~ s/\^/\^\^/g;
         $password =~ s/\^\^\^\^/\^\^\^/g;
         return "$password";
     } else {
             return "";
     }
}

sub log_au {
my $string = shift;

open(my $fh, '>>', '/tmp/exim_auth.log');
print $fh "$string\n";
close $fh;
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

