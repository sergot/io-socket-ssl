use Test;
use IO::Socket::SSL;

plan 2;

unless %*ENV<NETWORK_TESTING> {
    diag "NETWORK_TESTING was not set";
    skip-rest("NETWORK_TESTING was not set");
    exit;
}

my IO::Socket $ssl = IO::Socket::SSL.new(:host<github.com>, :port(443));
isa-ok $ssl, IO::Socket::SSL, 'new 1/1';
$ssl.close;

subtest {
    lives-ok { $ssl = IO::Socket::SSL.new(:host<google.com>, :port(443)) };
    is $ssl.print("GET / HTTP/1.1\r\nHost:www.google.com\r\nConnection:close\r\n\r\n"), 57;
    ok $ssl.get ~~ /\s3\d\d\s/|/\s2\d\d\s/;
    $ssl.close;
}, 'google: ssl';

done-testing;
