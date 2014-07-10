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
#has $.family = PIO::PF_INET;
#has $.proto = PIO::PROTO_TCP;
#has $.type = PIO::SOCK_STREAM;
has Str $.input-line-separator is rw = "\n";
has Int $.ins = 0;

has int32 $.fd;
has OpenSSL $.ssl;

method new(*%args) {
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
        my int32 $port = $.port;
        $!fd = client_connect(str-to-carray($!host), $port);

        if $!fd > 0 {
            # handle errors
            $!ssl = OpenSSL.new(:client);
            $!ssl.set-fd($.fd);
            $!ssl.set-connect-state;
            $!ssl.connect;
        }
    }
    elsif $!localhost && $!localport {
        # server stuff TODO
        $!ssl = OpenSSL.new;
        $!ssl.set-fd($.fd);
        $!ssl.set-accept-state;
    }
    self;
}

method recv(Int $n, Bool :$bin = False) {
    $.ssl.read($n, :$bin);
}

method send(Str $s) {
    $.ssl.write($s);
}

sub str-to-carray(Str $s) {
    my @s = $s.split('');
    my $c = CArray[uint8].new;
    for 0 ..^ $s.chars -> $i {
        my uint8 $elem = @s[$i].ord;
        $c[$i] = $elem;
    }
    $c;
}
