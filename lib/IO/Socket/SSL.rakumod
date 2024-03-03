unit class IO::Socket::SSL does IO::Socket;

use IO::Socket::Async::SSL;


sub v4-split($uri) {
    $uri.split(':', 2);
}
sub v6-split($uri) {
    my ($host, $port) = ($uri ~~ /^'[' (.+) ']' \: (\d+)$/)[0, 1];
    $host ?? ($host, $port) !! $uri;
}

has Str $.host;
has Int $.port = 443;
has Str $.localhost;
has Int $.localport;
has Str $.certfile;
has Bool $.listening;
has Str $.input-line-separator is rw = "\n";
has Int $.ins = 0;

has $.client-socket;
has $.listen-socket;

has $!con-tap;
has Lock $!con-lock;
has $!con-lock-cond;
has $!next-con;

has IO::Socket::Async::SSL $!async is built;
has $!in-tap;
has Lock $!in-lock;
has $!in-lock-cond;
constant max-in-buf-size = 1048576; # 2^21
has Buf $!in-buf;

# TODO:
# IO::Socket has $.nl-in and $.nl-out instead of $.input-line-separator. Support both.

method TWEAK(*%args) {
    unless $!async {
        if %args<host> {
            my ($host, $port) = %args<family> && %args<family> == PIO::PF_INET6()
                ?? v6-split(%args<host>)
                !! v4-split(%args<host>);
            if $port {
                $!port //= $port;
                $!host = $host;
            }
        }
        if %args<localhost> {
            my ($peer, $port) = %args<family> && %args<family> == PIO::PF_INET6()
                ?? v6-split(%args<localhost>)
                !! v4-split(%args<localhost>);
            if $port {
                $!localport //= $port;
                $!localhost = $peer;
            }
        }

        $!listening = True if %args<listen>:exists;
        %args<enc> = %args<encoding> if %args<encoding>:exists;

        if !$!listening && $!host && $!port {
            $!async = await IO::Socket::Async::SSL.connect(
                $!host,
                $!port,
                |%args
            );
        }
        elsif $!listening && $!localhost && $!localport {
            $!con-lock .= new;
            my $con-supply = IO::Socket::Async::SSL.listen(
                $!localhost,
                $!localport,
                |%args
            );
            $!con-tap = $con-supply.tap: -> $v {
                $!con-lock.protect: {
                    $!next-con = $v;
                    $!con-lock-cond.signal;
                }
            };
        }
        elsif $!client-socket {
            # TODO
        }
        elsif $!listen-socket {
            # TODO
        }
        else {
            fail "Nothing given for new socket to connect or bind to"
        }
    }

    if $!async {
        $!in-lock .= new;
        $!in-lock-cond = $!in-lock.condition;
        $!in-buf .= new;
        $!in-tap = $!async.Supply(:bin).tap: -> $data is copy {
            $!in-lock.protect: {
                if $!in-buf.elems == max-in-buf-size {
                    $!in-lock-cond.wait({ $!in-buf.elems < max-in-buf-size });
                }
                loop {
                    if $!in-buf.elems + $data.elems > max-in-buf-size {
                        my $allowed = max-in-buf-size - $!in-buf.elems;
                        $!in-buf.elems.append($data.subbuf(0, $allowed));
                        $data .= subbuf($allowed);
                        $!in-lock-cond.wait({ $!in-buf.elems < max-in-buf-size });
                    }
                    else {
                        $!in-buf.append($data);
                        $!in-lock-cond.signal;
                        last;
                    }
                }
            }
        },
        done => { $!in-tap = Nil },
        quit => -> $ex {
            $!in-tap = Nil;
            $ex.throw
        }
    }
}

method recv(Int $n = 1048576, Bool :$bin = False, :$enc = 'utf-8') {
    sub decode($data) {
        if $bin {
            $data
        }
        else {
            my $norm-enc = Rakudo::Internals.NORMALIZE_ENCODING($enc);
            my $dec = Encoding::Registry.find($norm-enc).decoder();
            $dec.add-bytes($data);
            $dec.consume-available-chars();
        }
    }
    # Can't yet reliably return from within the `protect` block:
    # https://github.com/Raku/problem-solving/issues/417
    my $res;
    $!in-lock.protect: {
        loop {
            if $!in-buf.elems > $n {
                my $new-buf = $!in-buf.subbuf($n);
                $!in-buf.reallocate($n);
                my $data = $!in-buf;
                $!in-buf = $new-buf;
                $!in-lock-cond.signal;
                $res = decode($data);
                last
            }
            elsif $!in-buf.elems {
                my $data = $!in-buf;
                $!in-buf .= new;
                $!in-lock-cond.signal;
                $res = decode($data);
                last
            }
            elsif !$!in-tap { # Connection has closed
                $res = $!in-buf;
                last
            }
            else {
                $!in-lock-cond.wait({ $!in-buf.elems });
            }
        }
    }
    $res
}

method read(Int $n) {
    my $res = buf8.new;
    my $buf;
    repeat {
        $buf = self.recv($n - $res.elems, :bin);
        $res ~= $buf;
    } while $res.elems < $n && $buf.elems;
    $res;
}

method send(Str $s) {
    await $!async.print($s);
}

method print(Str $s) {
    my $res = await $!async.print($s);
    $res
}

method put(Str $s) {
    await $!async.print($s ~ $.nl-out);
}

method write(Blob $b) {
    await $!async.write($b);
}

method get() {
    my $buf = buf8.new;
    my $nl-bytes = $.input-line-separator.encode.bytes;
    loop {
        my $more = self.recv(1, :bin);
        if !$more {
            return Str unless $buf.bytes;
            return $buf.decode;
        }
        $buf ~= $more;
        next unless $buf.bytes >= $nl-bytes;

        if $buf.subbuf($buf.bytes - $nl-bytes, $nl-bytes).decode('latin-1') eq $.input-line-separator {
            return $buf.subbuf(0, $buf.bytes - $nl-bytes).decode;
        }
    }
}

method accept(IO::Socket::SSL:D:) {
    die "Not a server socket" unless $!listening;
    my $new-con;
    $!con-lock.protect: {
        $!con-lock-cond.wait({ $!next-con });
        $new-con = self.bless(async => $!next-con);
        $!next-con = Nil;
    }
    $new-con
}

method close(IO::Socket::SSL:D:) {
    .close with $!async;
    .close with $!in-tap;
    .close with $!con-tap;
}

method connect(IO::Socket::SSL:U: Str() $host, Int() $port) {
    self.new(:$host, :$port)
}

method listen(IO::Socket::SSL:U: Str() $localhost, Int() $localport) {
    self.new(:$localhost, :$localport, :listen)
}

=begin pod

=head1 NAME

IO::Socket::SSL - interface for SSL connection

=head1 SYNOPSIS

    use IO::Socket::SSL;
    my $ssl = IO::Socket::SSL.new(:host<example.com>, :port(443));
    if $ssl.print("GET / HTTP/1.1\r\n\r\n") {
        say $ssl.recv;
    }

=head1 DESCRIPTION

This module provides an interface for SSL connections.

It uses C to setting up the connection so far (hope it will change soon).

=head1 METHODS

=head2 method new

    method new(*%params) returns IO::Socket::SSL

Gets params like:

=item encoding             : connection's encoding
=item input-line-separator : specifies how lines of input are separated

for client state:
=item host : host to connect
=item port : port to connect

for server state:
=item localhost : host to use for the server
=item localport : port for the server
=item listen    : create a server and listen for a new incoming connection
=item certfile  : path to a file with certificates

=head2 method recv

    method recv(IO::Socket::SSL:, Int $n = 1048576, Bool :$bin = False)

Reads $n bytes from the other side (server/client).

Bool :$bin if we want it to return Buf instead of Str.

=head2 method print

    method print(IO::Socket::SSL:, Str $s)

=head2 method send

    DEPRECATED. Use `.print` instead

    method send(IO::Socket::SSL:, Str $s)

Sends $s to the other side (server/client).

=head2 method accept

    method accept(IO::Socket::SSL:)

Waits for a new incoming connection and accepts it.

=head2 close

    method close(IO::Socket::SSL:)

Closes the connection.

=head1 SEE ALSO

L<OpenSSL>

=head1 EXAMPLE

To download sourcecode of e.g. github.com:

    use IO::Socket::SSL;
    my $ssl = IO::Socket::SSL.new(:host<github.com>, :port(443));
    my $content = Buf.new;
    $ssl.print("GET /\r\n\r\n");
    while my $read = $ssl.recv {
        $content ~= $read;
    }
    say $content;

=end pod
