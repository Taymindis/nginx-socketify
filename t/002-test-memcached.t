# vi:filetype=perl

use lib '../test-nginx/inc';
use lib '../test-nginx/lib';
use Test::Nginx::Socket 'no_plan';

our $http_config = <<'_EOC_';
    upstream memcached_upstream {
        server 127.0.0.1:11211;
    }
    geo $dlr {
      default "$";
    }
_EOC_

no_shuffle();
run_tests();


__DATA__

=== TEST 1: test memcached set key value
--- http_config eval: $::http_config
--- config
    location  = /mmc {
        set $lastdelimeter "@:|:@";

        if ( $request_method !~ ^(GET|PUT|POST)$ ) {
            return 405;
        }

        if ($arg_key = ''){
            return 405 'key needed';
        }
        socketify_strlen $request_body$lastdelimeter totalbulklength;

        socketify_send "set $arg_key 0 60000 $totalbulklength\r\n$request_body$lastdelimeter\r\n";
        socketify_done_recv_if_eol_match "STORED\r\n";

        socketify_pass 127.0.0.1:11211;
    }
--- request
POST /mmc?key=testkey
{"data":"MESSAGE1"}
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: text/plain


=== TEST 2: test memcached get key value
--- http_config eval: $::http_config
--- config
    location  = /mmc {
        set $lastdelimeter "@:|:@";

        if ( $request_method !~ ^(GET|PUT|POST)$ ) {
            return 405;
        }

        if ($arg_key = ''){
            return 405 'key needed';
        }
        socketify_send "get $arg_key\r\n";
        socketify_done_recv_if_eol_match "@:|:@\r\nEND\r\n";
        socketify_done_recv_if_start_match "END\r\n";
        socketify_substr_resp "\r\n" "@:|:@\r\nEND" 200;
        socketify_pass 127.0.0.1:11211;
    }
--- request
GET /mmc?key=testkey
--- error_code: 200
--- timeout: 10




=== TEST 3: test memcached get key which does not exist
--- http_config eval: $::http_config
--- config
    location  = /mmc {
        set $lastdelimeter "@:|:@";

        if ( $request_method !~ ^(GET|PUT|POST)$ ) {
            return 405;
        }

        if ($arg_key = ''){
            return 405 'key needed';
        }
        socketify_send "get $arg_key\r\n";
        socketify_done_recv_if_eol_match "@:|:@\r\nEND\r\n";
        socketify_done_recv_if_start_match "END\r\n";
        socketify_substr_resp "\r\n" "@:|:@\r\nEND" 200;
        socketify_pass 127.0.0.1:11211;
    }
--- request
GET /mmc?key=testkey_noexists
--- error_code: 404
--- timeout: 10

