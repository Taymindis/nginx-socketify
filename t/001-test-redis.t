# vi:filetype=perl

use lib '../test-nginx/inc';
use lib '../test-nginx/lib';
use Test::Nginx::Socket 'no_plan';

our $http_config = <<'_EOC_';
    upstream redis_upstream {
        server 127.0.0.1:6379;
    }
    geo $dlr {
      default "$";
    }
_EOC_

no_shuffle();
run_tests();


__DATA__

=== TEST 1: test redis set key value
--- http_config eval: $::http_config
--- config
    location = /redis {
	    set $lastdelimeter "@:|:@";

	    if ( $request_method !~ ^(PUT|POST)$ ) {
	        return 405;
	    }
	    if ($arg_key = ''){
     	   return 405 'key needed';
    	}

	    if ( $request_method ~ ^(PUT|POST)$ ) {
	        socketify_strlen $arg_key keylen;
	        socketify_strlen $request_body$lastdelimeter totalbulklength;
	        socketify_send "*3\r\n";
	        socketify_send "${dlr}3\r\nSET\r\n";
	        socketify_send "${dlr}$keylen\r\n$arg_key\r\n";
	        socketify_send "${dlr}$totalbulklength\r\n${request_body}${lastdelimeter}\r\n";

	        socketify_done_recv_if_eol_match "\r\n";
            socketify_substr_resp "+" "\r\n" 0 0 202;
	    }

	    socketify_pass redis_upstream;
	}
--- request
POST /redis?key=testkey
{"data":"MESSAGE1"}
--- error_code: 202
--- timeout: 10
--- response_headers
Content-Type: text/plain


=== TEST 2: test redis get key value
--- http_config eval: $::http_config
--- config
    location = /redis {
	    if ( $request_method !~ ^(GET)$ ) {
	        return 405;
	    }
	    if ($arg_key = ''){
     	   return 405 'key needed';
    	}

	    if ( $request_method ~ ^(GET)$ ) {
	         socketify_send "GET $arg_key\r\n";
	         socketify_done_recv_if_eol_match "@:|:@\r\n";
	         socketify_done_recv_if_eol_match "$-1\r\n";
	         
	         socketify_substr_resp "\r\n" "@:|:@\r\n" 200;
	         add_header content-type "application/json";
	    }
	    socketify_pass redis_upstream;
	}
--- request
GET /redis?key=testkey
--- error_code: 200
--- timeout: 10


=== TEST 3: receive by scan length
--- http_config eval: $::http_config
--- config
    location = /redis {
	    if ( $request_method !~ ^(GET)$ ) {
	        return 405;
	    }
	    if ($arg_key = ''){
     	   return 405 'key needed';
    	}

	    if ( $request_method ~ ^(GET)$ ) {
            socketify_send "GET $arg_key\r\n";
            socketify_done_recv_by_scan_len scan_aft=$;
            socketify_substr_resp "$-1" "\r\n" 0 0 404; # not found go to fallback mode 
            socketify_substr_resp "\r\n" "@:|:@\r\n" 2 0 200; # faster than regex filter, make sure data is correct

            socketify_content_type "application/json";
        }  
	    socketify_pass redis_upstream;
	}
--- request
GET /redis?key=testkey
--- error_code: 200
--- timeout: 10

