class IO::Socket::SSL;

use NativeCall;
use OpenSSL;

use libclient;

sub client_connect(Str, int32) returns int32 { * }
sub client_disconnect(int32) { * }
sub server_init(int32, int32, Str) returns int32 { * }
trait_mod:<is>(&client_connect, :native(libclient::library));
trait_mod:<is>(&client_disconnect, :native(libclient::library));
trait_mod:<is>(&server_init, :native(libclient::library));

sub v4-split($uri) {
    $uri.split(':', 2);
}
sub v6-split($uri) {
    my ($host, $port) = ($uri ~~ /^'[' (.+) ']' \: (\d+)$/)[0, 1];
    $host ?? ($host, $port) !! $uri;
}

has Str $.encoding = 'utf8';
has Str $.host;
has Int $.port = 80;
has Str $.localhost;
has Int $.localport;
has Str $.certfile;
has Bool $.listen;
#has $.family = PIO::PF_INET;
#has $.proto = PIO::PROTO_TCP;
#has $.type = PIO::SOCK_STREAM;
has Str $.input-line-separator is rw = "\n";
has Int $.ins = 0;

has int32 $.fd;
has OpenSSL $.ssl;

method new(*%args is copy) {
    fail "Nothing given for new socket to connect or bind to" unless %args<host> || %args<listen>;

    if %args<host> {
        my ($host, $port) = %args<family> && %args<family> == PIO::PF_INET6()
            ?? v6-split(%args<host>)
            !! v4-split(%args<host>);
        if $port {
            %args<port> //= $port;
            %args<host> = $host;
        }
    }
    if %args<localhost> {
        my ($peer, $port) = %args<family> && %args<family> == PIO::PF_INET6()
            ?? v6-split(%args<localhost>)
            !! v4-split(%args<localhost>);
        if $port {
            %args<localport> //= $port;
            %args<localhost> = $peer;
        }
    }

    %args<listen>.=Bool if %args.exists_key('listen');

    self.bless(|%args)!initialize;
}

method !initialize {
    if $!host && $!port {
        # client stuff
        my int32 $port = $!port;
        $!fd = client_connect($!host, $port);

        if $!fd > 0 {
            # handle errors
            $!ssl = OpenSSL.new(:client);
            $!ssl.set-fd($!fd);
            $!ssl.set-connect-state;
            $!ssl.connect;
        }
        else {
            die "Failed to connect";
        }
    }
    elsif $!localhost && $!localport {
        my int32 $listen = $!listen.Int // 0;
        $!fd = server_init($!localport, $listen, $!certfile);
        if $!fd > 0 {
            $!ssl = OpenSSL.new;
            $!ssl.set-fd($!fd);
            $!ssl.set-accept-state;

            die "No certificate file given" unless $!certfile;
            $!ssl.use-certificate-file($!certfile);
            $!ssl.use-privatekey-file($!certfile);
            $!ssl.check-private-key;
        }
        else {
            die "Failed to " ~ ($!fd == -1 ?? "bind" !! "listen");
        }
    }
    self;
}

method recv(Int $n = 1048576, Bool :$bin = False) {
    $!ssl.read($n, :$bin);
}

method send(Str $s) {
    $!ssl.write($s);
}

method accept {
    $!ssl.accept;
}

method close {
    $!ssl.close;
    client_disconnect($!fd);
}
