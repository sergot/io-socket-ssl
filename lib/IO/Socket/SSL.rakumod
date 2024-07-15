unit class IO::Socket::SSL does IO::Socket;

use IO::Socket::Async::SSL;


sub v4-split($uri) {
    $uri.split(':', 2);
}
sub v6-split($uri) {
    my ($host, $port) = ($uri ~~ /^'[' (.+) ']' \: (\d+)$/)[0, 1];
    $host ?? ($host, $port) !! $uri;
}

has Str $.encoding = 'utf8';
has $.nl-in is rw = ["\n", "\r\n"];
has Str:D $.nl-out is rw = "\n";

has ProtocolFamily:D $.family = PF_UNSPEC;

has SocketType:D   $.type  = SOCK_STREAM is built(False);
has ProtocolType:D $.proto = PROTO_TCP   is built(False);

#DIFF TCP protocol guts. Need to modify IO::Socket::Async::SSL to add support for this. IO::Socket::Async.listen already supports it.
has Int $.backlog;

has Str $.host;
has Int $.port = 443;
has Str $.localhost;
has Int $.localport;
has Str $.certfile;
has Bool $.listening;
has Int $.ins = 0;

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

has Encoding::Decoder $!decoder;
has Encoding::Encoder $!encoder;

method new() {
    die "Cannot create an IO::Socket::SSL::Via::Async object directly; please use\n" ~
        "IO::Socket::SSL::Via::Async.connect or IO::Socket::SSL::Via::Async.listen";
}

# TODO: syncronize this with IO:Socket::Async::SSL.
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

method !ensure-decoder(--> Nil) {
    unless $!decoder.DEFINITE {
        my $encoding = Encoding::Registry.find($!encoding);
        $!decoder := $encoding.decoder();
        $!decoder.set-line-separators($!nl-in.list);
    }
}

method !ensure-encoder(--> Nil) {
    unless $!encoder.DEFINITE {
        my $encoding = Encoding::Registry.find($!encoding);
        $!encoder := $encoding.encoder();
    }
}

method !pull-bytes-from-async(Int $limit) {
    my $res;
    $!in-lock.protect: {
        loop {
            if $!in-buf.elems > $limit {
                my $new-buf = $!in-buf.subbuf($limit);
                $!in-buf.reallocate($limit);
                my $data = $!in-buf;
                $!in-buf = $new-buf;
                $!in-lock-cond.signal;
                $res = $data;
                last
            }
            elsif $!in-buf.elems {
                my $data = $!in-buf;
                $!in-buf .= new;
                $!in-lock-cond.signal;
                $res = $data;
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

method !feed-decoder(Int $limit) {
    my $bytes = self!pull-bytes-from-async($limit);
    $!decoder.add-bytes($bytes);
}

method !pull-bytes(Int $limit) {
    if $!decoder.DEFINITE {
        $!decoder.consume-exactly-bytes($limit)
            // self!pull-bytes-from-async($limit)
    }
    else {
        self!pull-bytes-from-async($limit)
    }
}

method nl-in is rw {
    Proxy.new(
        FETCH => { $!nl-in },
        STORE => -> $, $nl-in {
            $!nl-in = $nl-in;
            with $!decoder {
                .set-line-separators($!nl-in.list);
            }
            $nl-in
        }
    )
}

# DIFF Limit in IO::Socket is 65535
method recv(Cool $limit = 1048576, Bool :$bin = False) {
    fail('Socket not available') unless $!async;
    if $bin {
        self!pull-bytes($limit)
    }
    else {
        self!ensure-decoder();
        my $result = $!decoder.consume-exactly-chars($limit);
        without $result {
            self!feed-decoder(65535);
            $result = $!decoder.consume-exactly-chars($limit);
            without $result {
                $result = $!decoder.consume-all-chars();
            }
        }
        $result
    }
}

method read(Int(Cool) $bufsize) {
    fail('Socket not available') unless $!async;
    my int $toread = $bufsize;

    my $res := self!pull-bytes($toread);

    while nqp::elems($res) < $toread {
        my $buf := self!pull-bytes($toread - nqp::elems($res));
        nqp::elems($buf)
          ?? $res.append($buf)
          !! return $res
    }
    $res
}

method get() {
    self!ensure-decoder();
    my Str $line = $!decoder.consume-line-chars(:chomp);
    if $line.DEFINITE {
        $line
    }
    else {
        loop {
            self!feed-decoder(65535);
            $line = $!decoder.consume-line-chars(:chomp);
            last if $line.DEFINITE;
            if $read == 0 {
                $line = $!decoder.consume-line-chars(:chomp, :eof)
                    unless $!decoder.is-empty;
                last;
            }
        }
        $line.DEFINITE ?? $line !! Nil
    }
}

method lines() {
    gather while (my $line = self.get()).DEFINITE {
        take $line;
    }
}

method print(Str(Cool) $s --> Int) {
    self!ensure-encoder();
    self.write($!encoder.encode-chars($string));
}

method put(Str(Cool) $string --> Int) {
    self.print($string ~ $!nl-out);
}

method write(Blob:D $buf --> Int) {
    fail('Socket not available') unless $!async;
    await $!async.write($buf)
}

method close(IO::Socket::SSL:D:) {
    fail("Not connected!") unless $!async;
    .close with $!async;
    .close with $!in-tap;
    .close with $!con-tap;
}

method native-descriptor(::?CLASS:D:) {
    fail("Not available on IO::Socket::SSL::Via::Async");
}

method connect(IO::Socket::SSL:U: Str() $host, Int() $port, ProtocolFamily:D(Int:D) :$family = PF_UNSPEC) {
    self.new(:$host, :$port, :$family)
}

method listen(IO::Socket::SSL:U: Str() $localhost, Int() $localport, ProtocolFamily:D(Int:D) :$family = PF_UNSPEC) {
    self.new(:$localhost, :$localport, :$family, :listen)
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

=begin pod

=head1 NAME

IO::Socket::SSL::Via::Async - Interface for TLS connections

=head1 SYNOPSIS

    use IO::Socket::SSL::Via::Async;
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
