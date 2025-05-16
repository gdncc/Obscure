unit module Obscure::Hashes::SHA3;

subset Capacity of Int where *== 256 | 448 | 512 | 768 | 1024;
# Padding for SHA-3, RawSHAKE, SHAKE (cipher specific padding, appended with 1st bit of pad1*1)
subset PaddingDelimiter of Int where *== 0x6 | 0x7 | 0x1f;

# Keccak-p permutation bits length AKA `b` - we only support 1600 support for now
subset PermutationsBitLength of Int where *== 25 | 50 | 100 | 200 | 400 | 800 | 1600;
# Keccak-p permutation lane bits length
subset LaneSize of Int where *== 1 | 2 | 4 | 8 | 16 | 32 | 64;

enum SpongeState <ABSORB SQUEEZE>;

# KECCAK is the family of sponge functions with KECCAK-p[b, 12+2l]
role KECCAK-p[PermutationsBitLength $b, Int $nr] {
    has Int $.b = $b div 8;
    has Int $.nr = $nr;
    has LaneSize $.lane-size is rw;
}

# When restricted to the case b=1600, the KECCAK family is denoted by KECCAK[c];
# KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600–c].
role KECCAK-c[Capacity $capacity,
                PaddingDelimiter $padding-delimiter,
                Int $output-bits-length where ($_ >= 8 and $_ mod 8 == 0) ]
        does KECCAK-p[1600,24] {
    has Int $.capacity = $capacity div 8;
    has PaddingDelimiter $!padding-delimiter = $padding-delimiter;

    has Int $.output-bytes-length is rw = 0;
    has Int $!last-read-pos = 0;
    
    has Int $!rate = 0;

    # State arrays
    has Int @!A = 0 xx 25;
    has Int @!A-prime = 0 xx 25;

    # Temp arrays required by θ()
    has Int @!C = 0 xx 5;
    has Int @!D = 0 xx 5;

    # Transient input buffer
    has Int $!buffer-written-index = 0;
    has Buf $!buffer;

    # Output buffer
    has Buf $!output-buffer;

    has SpongeState $!sponge-state = ABSORB;

    submethod TWEAK() {
        $!rate = self.b - $!capacity;
        $!output-bytes-length = $output-bits-length div 8;
        $!buffer = Buf.new(0 xx self.b); # rate + capacity
	$!output-buffer = Buf.new(0 xx $!rate); # rate
        self.lane-size = self.b div 25;
    }

    method store64(Int $n) {
        gather { for ^8 { take ($n +> (8 * $_) +& 0xff) } }
    }

    method θ() {
        # For all pairs (x,z) such that 0≤x<5 and 0≤z<w, let
        # C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z]
        for ^5 -> $x {
            @!C[$x] = @!A[$x] +^ @!A[$x + 5] +^ @!A[$x + 10] +^ @!A[$x + 15] +^ @!A[$x + 20]
        }

        # For all pairs (x, z) such that 0≤x<5 and 0≤z<w let
        # D[x,z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
        for ^5 -> $x {
            @!D[$x] = @!C[($x - 1) % 5]
                    +^ ((@!C[($x + 1) % 5] +< 1 +| @!C[($x + 1) % 5] +> 63) +& 0xffffffffffffffff);
            # For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
            # A′[x, y,z] = A[x, y,z] ⊕ D[x,z]
            for ^5 -> $y {
                @!A[$x + 5 * $y]  +^=  @!D[$x]
            }
        }
    }

    method rotate-by(Int $x, Int $how-much --> Int) {
        ($x +> $how-much) +| ( ($x +< (64 - $how-much)) +& 0xffffffffffffffff)
    }

    # One can mix rho and pi, we won't here
    method ρ() {
        # compute rotations at compile time, for illustration purposes
        my Int @rotations-values = BEGIN {
            my Int @values = 0 xx 25;
            my ($x, $y, $z) = (1, 0, 0);
            for ^24 -> $t {
                my $rotation = ($z - (($t + 1) * ($t + 2)) +> 1) % 64;
                my $i = $x + 5 * $y;
                @values[$i] = $rotation;
                ($x, $y) = ($y, (2 * $x + 3 * $y) % 5);
            }
            @values
        }
        # run time
        for 1 ..^ 25 -> $i {
            @!A[$i] = $.rotate-by(@!A[$i], @rotations-values[$i])
        }
    }

    method π() {
        # 1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
        # A′[x, y, z]=A[(x + 3y) mod 5, x, z].
        # 2. Return A′.
        for ^5 -> $x {
            for ^5 -> $y {
                @!A-prime[$x + 5 * $y] = @!A[($x + 3 * $y) % 5 + 5 * $x]
            }
        }
    }

    method χ() {
        # 1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
        #   A′[x, y,z] = A[x, y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
        # 2. Return A′.
        # (we return A instead in this step, since input is A')
        for ^5 -> $x {
            for ^5 -> $y {
                @!A[$x + 5 * $y] = @!A-prime[$x + 5 * $y]
                        +^ ((@!A-prime[($x + 1) % 5 + 5 * $y] +^ 0xffffffffffffffff)
                                +&  @!A-prime[($x + 2) % 5 + 5 * $y])
            }
        }
    }

    method ι(Int $ir) {
        # compute round constants at compile time, for illustration purposes
        my @round-constants = BEGIN {
            #  linear feedback shift register using x⁸ (0x0100) + x⁶ + x⁵ + x⁴ + 1 (0x71)
            sub rc(Int $t) {
                return 1 if $t % 255 == 0;
                my Int $R = 1;
                for 1 .. ($t % 255) {
                    $R +<= 1;
                    $R = $R +^ 0x71 if ($R +& 0x100)
                }
                return $R +& 1
            };

            my Int @values = 0 xx 23;

            for ^24 -> $i {
                my Int $result = 0;
                my Int $shift = 1;
                for ^7 -> $j {
                    my Int $val = rc(7 * $i + $j);
                    $result +|= $val +< ($shift - 1);
                    $shift *= 2
                }
                @values[$i] = $result;
            }
            @values
        };
        # run-time
        @!A[0] +^= @round-constants[$ir];
    }
    # KECCAK-p[b, nr] with b = 1600
    method keccak-p() {
        # Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
        for ^$.nr -> $round {
            $.θ; $.ρ; $.π; $.χ; $.ι($round)
        }
    }

    # reset state (but does not attempt to clear memory)
    method reset() {
        $!sponge-state = ABSORB;
        $.output-bytes-length = $output-bits-length div 8;

	for ^$!buffer.elems -> $i { $!buffer.write-uint8($i,0) };

        $!buffer-written-index = 0;

        for @!A <-> $e { $e = 0 }

        for @!A-prime <-> $e { $e = 0 }

	$!last-read-pos = 0;

    }

    method absorb(Blob $input-bytes) {
        if $!sponge-state eqv SQUEEZE {
            X::AdHoc.new(:payload<SpongeWrongDirection>).throw
        }

        my Int $input-bytes-length = $input-bytes.elems;

        for ^$input-bytes-length -> $i {
            $!buffer[$!buffer-written-index] = $input-bytes[$i];	    
            if $!buffer-written-index == $!rate -1 {

                for ^25 -> $j {
                    @!A[$j] +^= $!buffer.read-uint64($j * $.lane-size, LittleEndian)
                }
                $.keccak-p;
                $!buffer-written-index = 0;
                
            } else {
                $!buffer-written-index += 1
            }
        }
    }

    method squeeze() {
        if $!sponge-state eqv ABSORB {
            $!sponge-state = SQUEEZE;

            # pad
            my Int $q = $!rate - ($!buffer-written-index % $!rate);
            given $q {
                when 1 { $!buffer[$!buffer-written-index] = $!padding-delimiter + 0x80 }
                default { $!buffer[$!buffer-written-index .. $!buffer-written-index + 1 + $q - 2] = $!padding-delimiter, |(0x00 xx ($q - 2)), 0x80 }
            }

            # add last block to state
            for ^25 -> $i {
                @!A[$i] +^= $!buffer.read-uint64($i * $.lane-size, LittleEndian)
            }
            # keccak it
            $.keccak-p;

	    # copy state to $output-buffer ( 17 blocks out of 25)
	    for ^($!rate div 8) -> $i {
		$!output-buffer.write-uint64($i * 8, @!A[$i], LittleEndian);
	    }
        }

        # squeeze
	my $output = Buf.new;
	my $updated-output-bytes-length = $.output-bytes-length;

	while ($updated-output-bytes-length + $!last-read-pos > $!rate ) {

	    $output.append($!output-buffer.subbuf($!last-read-pos, $!rate - $!last-read-pos));
	    $.keccak-p;

	    for ^($!rate div 8) -> $i {
		$!output-buffer.write-uint64($i * 8, @!A[$i], LittleEndian);
	    }
	    $updated-output-bytes-length = $.output-bytes-length - ($!rate - $!last-read-pos);
	    $!last-read-pos = 0;
	}

	if ($updated-output-bytes-length > 0) {
	    $output.append($!output-buffer.subbuf($!last-read-pos,  $updated-output-bytes-length));
	    $!last-read-pos = $!last-read-pos + $updated-output-bytes-length;
	}

	$output;
	
    }
    
    submethod DESTROY {
        # attempt to clear temp data, no guarantees
	for ^$!buffer.elems -> $i { $!buffer.write-uint8($i,0) };

	for ^$!output-buffer.elems -> $i { $!output-buffer.write-uint8($i,0) };

        for @!A <-> $e { $e = 0 }; for @!A-prime <-> $e { $e = 0 };

        for @!C <-> $e { $e = 0 }; for @!D <-> $e { $e = 0 };
    }
}

role HashLike[KECCAK-c $k]  {
    has KECCAK-c $!k = $k;
    has Bool $!finalized = False;

    multi method hash(Blob $input-bytes ) {
        $!k.absorb($input-bytes);
        return $!k.squeeze()
    }

    multi method hash(Str $input-string ) {
        samewith $input-string.encode
    }

    multi method update(Blob $input-bytes) {
        $!k.absorb($input-bytes)
    }

    multi method update(Str $input-string) {
        samewith $input-string.encode
    }

    method final() {
	if $!finalized == False {
	    $!finalized = True;
            return $!k.squeeze()
	} else {
	    X::AdHoc.new(:payload<AlreadyCalledFinal>).throw	    
	}
    }

    method reset() {
	$!finalized = False;
        $!k.reset;
	return
    }
};

role SHAKELike[KECCAK-c $k] {
    has KECCAK-c $!k = $k;

    multi method absorb(Blob $input-bytes) {
        $!k.absorb($input-bytes)
    }

    multi method absorb(Str $input-string) {
        samewith ($input-string.encode)
    }

    multi method squeeze(UInt $bytes-count) {
        $!k.output-bytes-length = $bytes-count;
        $!k.squeeze()
    }

    # default output size if none specified
    multi method squeeze() {
        $!k.output-bytes-length = $k.capacity;
        $!k.squeeze()
    }

    method reset() {
        $!k.reset;
	return
    }
}

sub SHA3_224 () is export {
    HashLike[KECCAK-c[448, 0x06, 224].new].new
}

sub SHA3_256 () is export {
    HashLike[KECCAK-c[512, 0x06, 256].new].new
}

sub SHA3_384 () is export {
    HashLike[KECCAK-c[768, 0x06, 384].new].new
}

sub SHA3_512 () is export {
    HashLike[KECCAK-c[1024, 0x06, 512].new].new
}

sub SHAKE128() is export {
    SHAKELike[KECCAK-c[256, 0x1f, 256].new].new
}

sub SHAKE256() is export {
    SHAKELike[KECCAK-c[512, 0x1f, 512].new].new
}

