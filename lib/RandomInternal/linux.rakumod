use NativeCall;
use Obscure::Completion;

unit module Obscure::RandomInternal::linux;

sub read(int32, buf8, size_t --> ssize_t) is native {};

our sub read-random-internal(buf8 $b) is error-type<minusonessize_t>  {
    my $fh = open '/dev/urandom', :r, :bin;
    return read($fh.native-descriptor, $b, $b.bytes);
    LEAVE try close $fh;
    CATCH {
        default {return -1;}
    }
}

our &secure-random-internal is export;

&secure-random-internal = &read-random-internal;
