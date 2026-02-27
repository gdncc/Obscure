use NativeCall;
use Obscure::Completion;

unit module Obscure::RandomInternal::macOS;


sub getentropy(buf8, size_t --> int32) is native {}; # $*DISTRO.version >= v10.12.0
sub read(int32, buf8, size_t --> ssize_t) is native {};

our sub read-random-internal(buf8 $b) is error-type<minusonessize_t>  {
    my $fh = open '/dev/random', :r, :bin;
    return read($fh.native-descriptor, $b, $b.bytes);
    LEAVE try close $fh;
    CATCH {
        default {return -1;}
    }
}

our sub getentropy-internal(buf8 $b where *.bytes ≤ 256 --> int32) is error-type<notzeroi32> {
    return getentropy($b, $b.bytes);
}

our &secure-random-internal is export;

given  $*DISTRO.version {
    when * >= v10.12.0 {
        &secure-random-internal = &getentropy-internal;
    }
    default {
        &secure-random-internal = &read-random-internal }
};


