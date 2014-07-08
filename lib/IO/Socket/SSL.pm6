class IO::Socket::SSL;

use NativeCall;
use OpenSSL;

my sub client_connect(CArray[uint8], int32) returns int32 is native('./libclient') { * }
my sub get_buff(int32) returns CArray[uint8] is native('./libclient')              { * }

my sub v4-split($uri) {
    $uri.split(':', 2);
}
my sub v6-split($uri) {
    my ($host, $port) = ($uri ~~ /^'[' (.+) ']' \: (\d+)$/)[0, 1];
    $host ?? ($host, $port) !! $uri;
}

has Str $.encoding = 'utf8';
has Str $.host;
has Int $.port = 80;
has Str $.localhost;
has Int $.localport;
has Bool $.listen;
has $.family = PIO::PF_INET;
has $.proto = PIO::PROTO_TCP;
has $.type = PIO::SOCK_STREAM;
has Str $.input-line-separator is rw = "\n";
has Int $.ins = 0;

has int32 $.fd;
has OpenSSL::SSL_CTX $.ctx;
has OpenSSL::SSL $.ssl;

method new() {
    ...
}

method !initialize {
    if $.host && $.port {
        my int32 $port = $.port;
        $.fd = client_connect($.host, $port);

        if $.fd > 0 {
            # do some SSL here
            OpenSSL::SSL_library_init();
            OpenSSL::SSL_load_error_strings();
            $.ctx = OpenSSL::SSL_CTX_new( OpenSSL::SSLv23_client_method() );
            $.ssl = OpenSSL::SSL_new($.ctx);
            OpenSSL::SSL_set_connect_state($.ssl);
            OpenSSL::SSL_set_fd($.ssl, $.fd);
            OpenSSL::SSL_connect($.ssl);
        }
    }
    self;
}

method recv() {
    ...
}

method send() {
    ...
}
