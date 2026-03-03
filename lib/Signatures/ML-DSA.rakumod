use v6.d;

use Obscure::Random;
use Obscure::Completion;
use Obscure::Hashes::SHA3;
use experimental :pack;

unit module Obscure::Signatures::ML-DSA;

sub bitlen(Int:D $x --> Int:D) { $x.msb + 1 };

constant q = 8380417;
constant d = 13;
constant t1-max = (1 +< (bitlen(q - 1) - d)) - 1;

constant @zetas = 0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
		     7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
		     5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
		     5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
		     3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
		     394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
		     3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
		     5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
		     3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
		     2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
		     1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
		     4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
		     5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
		     7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
		     1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
		     348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
		     1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
		     1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
		     8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
		     6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
		     4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
		     3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
		     2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
		     7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
		     6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
		     6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
		     5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
		     3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
		     3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
		     3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
		     6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
		     8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983 ;

subset Seed32 of blob8 where *.elems == 32;
subset Seed34 of blob8 where *.elems == 34;
subset Seed64 of blob8 where *.elems == 64;
subset Seed66 of blob8 where *.elems == 66;

subset Context is export of blob8 where *.elems ≤ 255;

subset ByteArray32 of blob8 where *.elems == 32;

subset CoeffEta2 of Int where -2 ≤ * ≤ 2;
subset CoeffEta4 of Int where -4 ≤ * ≤ 4;

sub sk-size($k, $l, $𝜂) { 32+32+64+32*(($l+$k) * bitlen(2 * $𝜂) + d * $k) }
sub pk-size($k) { 32 + 32 * $k * (bitlen(q - 1) - d) }
sub encoded-signature-size($k, $l, $λ, $ɣ1, $ω) {$λ div 4 + $l * 32 * (1 + bitlen($ɣ1 - 1)) + $ω + $k }
sub lambda-div-four($λ) {$λ div 4};
sub encoded-w̃1-size($k, $ɣ2) { 32 * $k * bitlen((q - 1) div (2 * $ɣ2) - 1) };

role KeyPair[::PK, ::SK] {
    has PK $.public;
    has SK $.private;

    submethod BUILD(:$!public, :$!private) {};

	method gist(--> Str) { "KeyPair(public: {$!public.elems} bytes, private: <redacted>)" }
}

subset FieldElement of Int where 0 ≤ * < q;
subset Bit of Int where 0|1;

role Ring[::CoeffType] {
    has CoeffType @.coeffs[256];
    method zero(--> ::?CLASS) {
        self.new(coeffs => [0 xx 256])
    }
}

class RingElement  does Ring[Int]           {}
class RqElement    does Ring[FieldElement]  {}  
class NTTElement   does Ring[FieldElement]  {}
class R2Element    does Ring[Bit]           {}

enum DimTag <K L>;

role Vec[::ElementType, DimTag $tag, UInt :$dim] {
    has ElementType @.elements[ $dim ];
    method dim() { $dim }
    method dim-tag() { $tag } 
}

role TwoTuple[::V1, ::V2] {
    has V1 $.v1;
    has V2 $.v2;
}

role DecodedPK[::V1] {
    has Seed32 $.rho;
    has V1 $.t1;
}

role DecodedSK[::V1, ::V2, ::V3, ::V4, ::V5, ::V6] {
    has V1 $.rho;
    has V2 $.K;
    has V3 $.tr;
    has V4 $.s1;
    has V5 $.s2;
    has V6 $.t0;        
}

role DecodedSignature[::V1, ::V2, ::V3] {
    has V1 $.c̃;
    has V2 $.z;
    has V3 $.h; 
}

# 𝑘 × ℓ matrix Â of elements of 𝑇𝑞 (NTTElement).
role NTTMatrix[UInt :$k where ($_ == 4 | 6 | 8), UInt :$l where ($_ == 4 | 5 | 7)] {};

# infinity norm function notation
sub circumfix:<‖ ‖∞>($x) {
    infinity-norm($x)
}

role ML-DSA[
    # Parametric method input/output types
    ::EncodedPublicKeyType,
    ::EncodedPrivateKeyType,
    ::EncodedSignatureType,
    ::LambdaDivFourSizedType,
    ::EncodedWTildeType,
    ::CoeffEtaType, 
    # 4. Parameter Sets
    UInt :$k where ($_ == 4 | 6 | 8),
    UInt :$l where ($_ == 4 | 5 | 7),
    UInt :$𝜂 where ($_ == 2 | 4 ),
    UInt :$λ where ($_ == 128 | 192 | 256 ),
    UInt :$ɣ1 where ($_ == 131072 | 524288 ),
    UInt :$ɣ2 where ($_ == 95232 | 261888 ),
    UInt :$𝜏 where ($_ == 39 | 49 | 60 ),
    UInt :$ω where ($_ == 80 | 55 | 75),
    UInt :$𝛽 where ($_ == 78 | 196 | 120)
] {

    # Algorithm 1 ML-DSA.KeyGen
    method keygen( --> KeyPair[EncodedPublicKeyType,EncodedPrivateKeyType])  {
	my $xi = buf8.allocate(32);
	secure-random($xi) ~~ Successful || die "random bit generation failed"; # does not use an approved RNG
	self!keygen-internal(Seed32.new: $xi)
    }

    # multi method crash if invalid parameters e.g., for when ctx.elems > 255
    proto method sign(:$deterministic = False, :$rnd-value, |) is export() {
	my $*rnd = $rnd-value // buf8.allocate(32); # dynamic variable that multi sign methods can use
	unless $deterministic {
	    secure-random($*rnd) ~~ Successful || die "random bit generation failed";		
        }	
	{*}
    }

    # Algorithm 2 ML-DSA.Sign
    # “pure” ML-DSA ML-DSA.sig
    # invoked when `:prehash-fn()` is not specified
    multi method sign(EncodedPrivateKeyType :$sk,
   		blob8 :$M, Context :$ctx = Context.new,
		:$deterministic = False, :$prehash-fn where * ~~ Any:U   --> EncodedSignatureType)  {
	self!sign-internal($sk, ([~] blob8.new(0), blob8.new($ctx.elems), $ctx, $M) , $*rnd, False) ;
    }

    # Algorithm 4 HashML-DSA.Sign
    # “pre-hash” ML-DSA or HashML-DSA
    # dispatched with a string e.g. :prehash-fn(“SHAKE-128”)
    multi method sign(EncodedPrivateKeyType :$sk,
   		blob8 :$M, Context :$ctx = Context.new,
		:$deterministic = False, :$prehash-fn where * ~~ Str  --> EncodedSignatureType)  {
	my $Mʹ = [~] blob8.new(1), blob8.new($ctx.elems), $ctx, |self!prehash($M, $prehash-fn);
	self!sign-internal($sk, $Mʹ , $*rnd, False) ;
    }

    proto method verify(|) is export() {*}

    # Algorithm 3 ML-DSA.Verify
    # "pure" ML-DSA verify
    multi method verify(EncodedPublicKeyType :$pk, blob8 :$M,
			EncodedSignatureType :$signature,
			Context :$ctx = Context.new,
			:$prehash-fn where * ~~ Any:U --> Bool) {
	self!verify-internal($pk, ([~] blob8.new(0), blob8.new($ctx.elems), $ctx, $M), $signature, False)
    }

    # Algorithm 5 HashML-DSA.Sign
    multi method verify(EncodedPublicKeyType :$pk, blob8 :$M,
			EncodedSignatureType :$signature,
			Context :$ctx = Context.new,
			:$prehash-fn where * ~~ Str --> Bool) {
	my $Mʹ = [~] blob8.new(1), blob8.new($ctx.elems), $ctx, |self!prehash($M, $prehash-fn);
	self!verify-internal($pk, $Mʹ, $signature, False)
    }

    # Algorithm 6 ML-DSA.KeyGen_internal
    method !keygen-internal(Seed32 $xi --> KeyPair[EncodedPublicKeyType,EncodedPrivateKeyType]) {
	# 1: (𝜌, 𝜌′ , 𝐾) ∈ 𝔹32 × 𝔹64 × 𝔹32 ← H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
	my $expanded-seed = blob8.new(|$xi, $k, $l);
	my $output = self!h($expanded-seed, 128);
	my ($rho, $rhoʹ, $K) = $output.subbuf(0, 32), $output.subbuf(32, 64), $output.subbuf(96, 32);

	# 3: 𝐀̂ ← ExpandA(𝜌)
	my $Â = self!expand-a($rho);

	# 4: (𝐬1 , 𝐬2 ) ← ExpandS(𝜌′ )
	my $expanded-s = self!expand-s($rhoʹ);

	# 5: 𝐭 ← NTT−1 (𝐀̂ ∘ NTT(𝐬1 )) + 𝐬2
	my $t = self.ntt-inv($Â ∘ self.ntt($expanded-s.v1)) + $expanded-s.v2;

	# 6: (𝐭1 , 𝐭0 ) ← Power2Round(𝐭)
	my $decomposed-t = self.power2-round($t);

	# 8: 𝑝𝑘 ← pkEncode(𝜌, 𝐭1 )
	my $pk = self!pk-encode($rho, $decomposed-t.v2);

	# 9: 𝑡𝑟 ← H(𝑝𝑘, 64)
	my $tr = self!h($pk, 64);

	# 10: 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1 , 𝐬2 , 𝐭0 )
	my $sk = self!sk-encode($rho, $K, $tr, $expanded-s.v1, $expanded-s.v2, $decomposed-t.v1);

	KeyPair[EncodedPublicKeyType,EncodedPrivateKeyType].new(public => $pk, private => $sk)
    }

    # Utility function
    # Shared OID + prehash computation for sign and verify
    method !prehash(blob8 $M, Str $prehash-fn --> List) {
	given $prehash-fn {
	    when "SHAKE-128" {
		my $sponge = SHAKE128.new;
		$sponge.absorb($M);
		(blob8.new(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B),
		 $sponge.squeeze(32))
	    }
	    when "SHAKE-256" {
		my $sponge = SHAKE256.new;
		$sponge.absorb($M);
		(blob8.new(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C),
		 $sponge.squeeze(64))
	    }
	    when "SHA3-224" {
		(blob8.new(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07),
		 SHA3_224.new.hash($M))
	    }
	    when "SHA3-256" {
		(blob8.new(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08),
		 SHA3_256.new.hash($M))
	    }
	    when "SHA3-384" {
		(blob8.new(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09),
		 SHA3_384.new.hash($M))
	    }
	    when "SHA3-512" {
		(blob8.new(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A),
		 SHA3_512.new.hash($M))
	    }
	    default { fail "Unsupported prehash algorithm: $prehash-fn" }
	}
    }

    # Algorithm 7 ML-DSA.Sign_internal
    method !sign-internal(EncodedPrivateKeyType $sk,
		          blob8 $Mʹ, ByteArray32 $rnd, Bool $external_mu = False --> EncodedSignatureType) {

	# 1: (𝜌, 𝐾, 𝑡𝑟, 𝐬1 , 𝐬2 , 𝐭0) ← skDecode(𝑠𝑘)
	my $decoded-sk = self!sk-decode($sk);

	# 2: 𝐬̂1 ← NTT(𝐬1)
	my $ŝ1 = self.ntt($decoded-sk.s1) ;

	# 3: 𝐬̂2 ← NTT(𝐬2)
	my $ŝ2 = self.ntt($decoded-sk.s2) ;

	# 4: 𝐭̃0 ← NTT(𝐭0)
	my $t̂0 = self.ntt($decoded-sk.t0) ;

	# 5: 𝐀̂ ← ExpandA(𝜌)
	my $Â = self!expand-a($decoded-sk.rho);

	# 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 , 64)
	my $mu = $external_mu ?? $Mʹ !! self!h(([~] $decoded-sk.tr, $Mʹ), 64);

	# 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
	my $rhoʺ = self!h(([~] $decoded-sk.K, $rnd, $mu), 64);

	# 8: 𝜅 ← 0
	my Int $kappa = 0;

	# 10: while (𝐳, 𝐡) = ⊥ do
	my $z = Nil;
	my $h = Nil;
	my $c̃;
	until $z.defined && $h.defined {

	    # 11: 𝐲 ∈ 𝑅𝑞 ← ExpandMask(𝜌 , 𝜅)
	    my $y = self!expand-mask($rhoʺ, $kappa);

	    # 12: 𝐰 ← NTT−1 (𝐀̂ ∘ NTT(𝐲))
	    my $w = self.ntt-inv($Â ∘ self.ntt($y));

	    # 13: 𝐰1 ← HighBits(𝐰)
	    my $w1 = self.high-bits($w);

	    # 15: 𝑐̃̃ ← H(𝜇||w1Encode(𝐰1 ), 𝜆/4)
	    $c̃ = self!h(([~] $mu, self!w1-encode($w1)),$λ div 4);

	    # 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(𝑐̃)
	    my $c = self!sample-in-ball($c̃);

	    # 17: 𝑐̂ ← NTT(𝑐)
	    my $ĉ = self.ntt($c);

	    # 18: ⟨⟨𝑐𝐬1⟩⟩ ← NTT−1 (𝑐̂  ∘ 𝐬̂1)
	    my $cs1 = self.ntt-inv($ĉ ∘ $ŝ1);

	    # 19: ⟨⟨𝑐𝐬2⟩⟩ ← NTT−1 (𝑐̂ ∘ 𝐬̂2)
	    my $cs2 = self.ntt-inv($ĉ ∘ $ŝ2);

	    # 20: 𝐳 ← 𝐲 + ⟨⟨𝑐𝐬1⟩⟩
	    $z = $y + $cs1;

	    # 21: 𝐫0 ← LowBits(𝐰 − ⟨⟨𝑐𝐬2⟩⟩)
	    my $r0 = self.low-bits($w - $cs2);

	    # 23: if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0 ||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
	    if ‖ $z ‖∞  ≥ ($ɣ1 - $𝛽) || ‖ $r0 ‖∞  ≥ ($ɣ2 - $𝛽) {
		$z = Nil;
		$h = Nil;
	    } else {
		# 24: ⟨⟨𝑐𝐭0⟩⟩ ← NTT−1 (𝑐̂ ∘ 𝐭̂0 )
		my $ct0 = self.ntt-inv($ĉ ∘ $t̂0);

		# 26: 𝐡 ← MakeHint(−⟨⟨𝑐𝐭0⟩⟩, 𝐰 − ⟨⟨𝑐𝐬2⟩⟩ + ⟨⟨𝑐𝐭0⟩⟩)
		$h = self.make-hint(-$ct0, $w - $cs2 + $ct0);

		# 28: if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
		if ‖ $ct0 ‖∞ >= $ɣ2 || ($h.elements.map(*.coeffs.grep(1).elems).sum > $ω) {
		    $z = Nil;
		    $h = Nil;
		}
	    }

	    # 31: 𝜅←𝜅+ℓ 
	    $kappa += $l;
	}

	# 33: 𝜎 ← sigEncode(𝑐̂ 𝐳 mod± 𝑞, 𝐡)
	self!sig-encode($c̃, mod-pm($z, q), $h);
    }

    # Algorithm 8 ML-DSA.Verify_internal
    method !verify-internal(EncodedPublicKeyType $pk, blob8 $Mʹ,
			    EncodedSignatureType $sigma, Bool $external_mu = False --> Bool) {
	# 1: (ρ, t1) ← pkDecode(pk)
	my $decoded-pk = self!pk-decode($pk);

	# 2: (c̃, z, h) ← sigDecode(σ)
	my $decoded-sig = try { self!sig-decode($sigma) };
	
	# 3: if h = ⊥ then return false
	return False without $decoded-sig;
	return False unless $decoded-sig.h.defined;

	# 5: Â ← ExpandA(ρ)
	my $Â = self!expand-a($decoded-pk.rho);

	# 6: tr ← H(pk, 64)
	my $tr = self!h($pk, 64);

	# 7: μ ← H(tr‖M', 64)
	my $mu = $external_mu ?? $Mʹ !! self!h(([~] $tr, $Mʹ), 64);

	# 8: c ← SampleInBall(c̃)
	my $c = self!sample-in-ball($decoded-sig.c̃);

	# 9: w'_Approx ← NTT⁻¹(Â ∘ NTT(z) − NTT(c) ∘ NTT(t1 · 2^d))
	my $t1-scaled = Vec[RingElement,K,:dim($k)].new(
	    elements => $decoded-pk.t1.elements.map: {
		RingElement.new: coeffs => [.coeffs.map: * +< d]
	    }
	);
	my $Âz = $Â ∘ self.ntt($decoded-sig.z);
	my $ĉt1 = self.ntt($c) ∘ self.ntt($t1-scaled);
	my $wʹ-approx = self.ntt-inv($Âz - $ĉt1);

	# 10: w'1 ← UseHint(h, w'_Approx)
	my $wʹ1 = self.use-hint($decoded-sig.h, $wʹ-approx);

	# 12: c̃' ← H(μ‖w1Encode(w'1), λ/4)
	my $c̃ʹ = blob8.new: self!h(([~] $mu, self!w1-encode($wʹ1)), $λ div 4);

	# 13: return [[‖z‖∞ < γ1 − β]] and [[c̃ = c̃']]
	(‖ $decoded-sig.z ‖∞ < ($ɣ1 - $𝛽)) && ($decoded-sig.c̃ eqv $c̃ʹ)
    }

    # H(str, ℓ) = SHAKE256(str, 8ℓ)
    method !h(blob8 $b, UInt $l --> blob8) {
	my $sponge = SHAKE256.new;
	$sponge.absorb($b);
	$sponge.squeeze($l);
    }

    # Algorithm 29 SampleInBall
    method !sample-in-ball(LambdaDivFourSizedType $rho --> RingElement) {
	my $c = RingElement.zero;
	my $ctx = SHAKE256.new;
	$ctx.absorb($rho);
	my @h = self!bytes-to-bits($ctx.squeeze(8));
	for (256 - $𝜏)..255 -> $i {
            my $j = $ctx.squeeze(1)[0];
            $j = $ctx.squeeze(1)[0] while $j > $i;
            $c.coeffs[$i] = $c.coeffs[$j];
            $c.coeffs[$j] = 1 - 2 * @h[$i + $𝜏 - 256];  # 0→1, 1→-1
	}
	$c
    }    
    
    # Algorithm 30 RejNTTPoly
    method !rej-ntt-poly(Seed34 $rho --> NTTElement) {
	my $g = SHAKE128.new;
	$g.absorb($rho);
	my @coeffs = gather {
	    for ^256 {
		loop {
		    my $s = $g.squeeze(3);
		    with self!coeff-from-three-bytes($s) { take($_); last; }
		}
	    }
	}
	NTTElement.new(:@coeffs)
    }

    # Algorithm 31 RejBoundedPoly
    method !rej-bounded-poly(Seed66 $rho --> RingElement) {
	my $h = SHAKE256.new;
	$h.absorb($rho);
	my $j = 0;
	my @coeffs = gather {
	    while $j < 256 {
		my $z = $h.squeeze(1)[0];
		with self!coeff-from-half-byte( $z % 16) {take $_; $j++} # z0
		with self!coeff-from-half-byte( $z div 16) { 
		    if $j < 256 {
			take $_; # z1
			$j++;
		    }
		}
	    }
	}
	RingElement.new(:@coeffs)
    }

    # Algorithm 32 ExpandA
    method !expand-a(Seed32 $rho --> NTTMatrix) {
	my @Â[$k; $l];
	# Use X (cross) to avoid nested loop and hyper for potential parallelism
	# Well for fun really
	(^$k X ^$l).hyper.map: -> ($r, $s) {
            @Â[$r; $s] = self!rej-ntt-poly(blob8.new(|$rho, $s, $r));
	}
	
	@Â but NTTMatrix[:k($k), :l($l)]
    }
    
    # Algorithm 33 ExpandS
    method !expand-s(Seed64 $rho --> TwoTuple[Vec[RingElement,L], Vec[RingElement,K]]) {
	my $s1 = Vec[RingElement, L, :dim($l)]
		    .new(elements =>
			 (^$l).map: -> $r {
				self!rej-bounded-poly(blob8.new(|$rho, |pack("S", $r)))
			    });
	my $s2 = Vec[RingElement,K, :dim($k)]
		    .new(elements => (^$k).map: -> $r {
				self!rej-bounded-poly(blob8.new(|$rho, |pack("S", $r + $l)))
			    });
	TwoTuple[Vec[RingElement,L,:dim($l)], Vec[RingElement,K, :dim($k)]]
	.new(v1 => $s1, v2 => $s2);
    }
    
    # Algorithm 34 ExpandMask
    method !expand-mask(Seed64 $rho, UInt:D $mu --> Vec[RingElement,L]) {
	my $c = 1 + bitlen($ɣ1 -1);

	Vec[RingElement,L, :dim($l)]
	.new(elements =>  (^$l).map: -> $r {
		    my $rhoʹ = blob8.new(|$rho.subbuf(0,64), |pack("S", $mu + $r ));
		    my $v = self!h($rhoʹ, 32 * $c);
		    self!bit-unpack($v, $ɣ1 -1, $ɣ1)
		})

    }

    # Algorithm 41
    # NTT and NTT-1 do not modify vector shapes, just their element types Ring <-> NTT Elements
    # Private multi-methods are not supported
    multi method ntt(Vec[RingElement,L] $ws --> Vec[NTTElement,L]) {
	Vec[NTTElement,L, :dim($l)].new(elements => $ws.elements.map({ self.ntt($_) }));
    }
    
    multi method ntt(Vec[RingElement,K] $ws --> Vec[NTTElement,K]) {
	Vec[NTTElement,K,:dim($k)].new(elements => $ws.elements.map({self.ntt($_)})); # Seq to Array
    }

    multi method ntt(RingElement $w --> NTTElement) {
	my @coeffs[256] = $w.coeffs;
	my ($m, $len) = 0, 128;
	while $len >= 1 {
            my $start = 0;
            while $start < 256 {
		$m += 1;
		my $z = @zetas[$m];
		for $start ..^ $start + $len -> $j {
                    my $t = ($z * @coeffs[$j + $len]) % q;
                    @coeffs[$j + $len] = (@coeffs[$j] - $t) % q;
                    @coeffs[$j] = (@coeffs[$j] + $t) % q;
		}
		$start += 2 * $len;
            }
            $len = $len div 2;
	}
	NTTElement.new(:@coeffs)
    }    

    # Algorithm 42 NTT−1
    multi method ntt-inv(Vec[NTTElement,K] $ŵs  --> Vec[RqElement,K]) {
	Vec[RqElement,K,:dim($k)].new(elements => $ŵs.elements.map({self.ntt-inv($_)})); # Seq to Array 
    }

    multi method ntt-inv(Vec[NTTElement,L] $ŵs  --> Vec[RqElement,L]) {
	Vec[RqElement,L,:dim($l)].new(elements => $ŵs.elements.map({self.ntt-inv($_)})); # Seq to Array 
    }
	
    multi method ntt-inv( NTTElement $ŵ  --> RqElement) { 
	my @coeffs[256] = $ŵ.coeffs;	
	my ($m, $len)  = 256, 1;
	while $len < 256 {
	    my $start = 0;
	    while $start < 256 {
		$m = $m - 1;
		my $z = -@zetas[$m];
		for $start ..^ $start + $len -> $j { 
		    my $t = @coeffs[$j];
		    @coeffs[$j] = ($t + @coeffs[$j + $len]) % q;
		    @coeffs[$j + $len] = ($t - @coeffs[$j + $len]) % q;
		    @coeffs[$j + $len] = ($z * @coeffs[$j + $len]) % q;				     
		}
		$start = $start + 2 * $len;
	    }
	    $len = 2 * $len;
	}
	my $f = 8347681;
	
	for ^256 -> $j {
	    @coeffs[$j] = ( $f * @coeffs[$j] ) % q
	}
	RqElement.new(coeffs => @coeffs)
    }

    # Algorithm 9 IntegerToBits
    # Decomposes Int $x into a Seq of 1 or 0 bits
    method !integer-to-bits(Int:D $x where * ≥ 0, Int:D $α where * > 0 --> Seq) {  # α is the number of bits
	(^$α).map: { $x +> $_ +& 1 }
    }

    # Algorithm 10 BitsToInteger
    method !bits-to-integer(@y where .all ~~ 0 | 1, Int:D $α where * > 0 --> Int:D ) {
	[+] @y[^$α] Z+< ^$α
    }

    # Algorithm 11 IntegerToBytes
	# (not implemented/not required)

    # Algorithm 12 BitsToBytes
    method !bits-to-bytes(@y where .all ~~ 0 | 1 --> blob8) {
	my $z = buf8.allocate((@y.elems + 7) div 8 );
	for @y.kv -> $i, $bit {
            $z[$i div 8] +|= $bit +< ($i % 8);
	}
	blob8.new: $z
    }

    # Algorithm 13 BytesToBits
    method !bytes-to-bits(blob8 $z --> Seq) {
	gather {
	    for $z {
		my $b = $_;
		for ^8 {
		    take($b +& 1);
		    $b = $b +> 1;
		}
	    }
	}
    }
    
    # Algorithm 14 CoeffFromThreeBytes
    method !coeff-from-three-bytes(blob8 $b where *.elems >= 3 --> FieldElement:_) {
	my $z = ($b[2] +& 0x7f) +< 16 + ($b.read-uint16(0, LittleEndian));
	$z < q ?? $z !! Nil
    }

    # Algorithm 15 CoeffFromHalfByte
    # Returns Int in range -$𝜂 .. $𝜂, or Nil
    method !coeff-from-half-byte(UInt:D $b where * <= 15 --> CoeffEtaType:_ ) {
	if $𝜂 == 2 and $b < 15 {
	    return 2 - ($b % 5)
	} else {
	    if $𝜂 == 4 and $b < 9 {
	    return 4 - $b
	    } else {
		Nil
	    }
	}
    }

    # Algorithm 16 SimpleBitPack
    method !simple-bit-pack(RingElement $w, Int:D $b where * >= 0 --> blob8) {
	my $bitlen = ENTER {bitlen($b)}
	POST { *.elems == 32 * $bitlen }
	self!bits-to-bytes(
	    gather {
		for $w.coeffs { take(slip(self!integer-to-bits($_, $bitlen))) };
	    }
	)
    }

    # Algorithm 17 BitPack
    method !bit-pack(RingElement $w, Int:D $a where * >= 0, Int:D $b where * >= 0 --> blob8) {
	my $bitlen = ENTER { bitlen($a + $b)};
	POST { *.elems == $bitlen * 32} ;
	self!bits-to-bytes(
	    gather {
		for $w.coeffs { take(slip(self!integer-to-bits($b - $_, $bitlen))) };
	    }
	)
    }

    # Algorithm 18 SimpleBitUnpack
    method !simple-bit-unpack(blob8 $v,  Int:D $b where * >= 0 --> RingElement:_)  {
	# inline check, as Raku processes signature parameters left to right
	# one can't reference $b before they're declared
	# and we dont want to change the order of arguments
	fail "Expected {bitlen($b) * 32} bytes, got {$v.elems}" unless $v.elems == bitlen($b) * 32;
	my @coeffs;
	my $c = bitlen($b);
	my @z = self!bytes-to-bits($v);
	for ^256 -> $i {
	    my $ic = $i * $c;
	    @coeffs[$i] = self!bits-to-integer(@z[$ic..$ic + $c - 1], $c);
	}
	RingElement.new(:@coeffs)
    }

    # Algorithm 19 BitUnpack
    # ⚠ May fail
    method !bit-unpack(blob8 $v, Int:D $a where * >= 0, Int:D $b where * >= 0 --> RingElement:_)  {
	# inline check, as Raku processes signature parameters left to right
	# one can't reference $a and $b before they're declared
	# and we dont want to change the order of arguments
	fail "Expected {bitlen($a + $b) * 32} bytes, got {$v.elems}" unless $v.elems == bitlen($a + $b) * 32;
	my @coeffs;
	my $c = bitlen($a + $b);
	my @z = self!bytes-to-bits($v);
	for ^256 -> $i {
	    my $ic = $i * $c;
	    @coeffs[$i] = $b - self!bits-to-integer(@z[$ic..$ic + $c - 1], $c);
	}
	RingElement.new(:@coeffs)
    }

    # Algorithm 20 HintBitPack
    method !hint-bit-pack(Vec[R2Element,K] $h --> blob8) {
	POST { $_.elems == $ω + $k }
	my $y = buf8.allocate($ω + $k);
	my $index = 0;
	for ^$k -> $i {
            for ^256 -> $j {
		if $h.elements[$i].coeffs[$j] != 0 {
                    $y[$index++] = $j;
		}
            }
            $y[$ω + $i] = $index;
	}
	blob8.new: $y
    }
    

    # Algorithm 21 HintBitUnpack
    # ⚠ May fail
    method !hint-bit-unpack(blob8 $y where *.elems == ($ω + $k) --> Vec[R2Element,K]) {
	my  $h = Vec[R2Element,K,:dim($k)].new(elements => [R2Element.zero xx $k]);
	my $index = 0;
	for ^$k -> $i {
            return Nil if $y[$ω + $i] < $index || $y[$ω + $i] > $ω;
            my $first = $index;
            while $index < $y[$ω + $i] {
		if $index > $first {
                    return Nil if $y[$index - 1] >= $y[$index];
		}
		$h.elements[$i].coeffs[$y[$index]] = 1;  
		$index++;                         
            }
	}
	for $index..^$ω -> $i {
            return Nil if $y[$i] != 0;
	}
	$h
    }

    # Algorithm 22 pkEncode
    method !pk-encode(Seed32 $rho, Vec[RingElement,K] $t1  --> EncodedPublicKeyType) {
	my $pk = buf8.new: $rho;
	for ^$k -> $i {
	    $pk.append(self!simple-bit-pack($t1.elements[$i], t1-max));
	}
	blob8.new: $pk
    }

    #Algorithm 23 pkDecode
    method !pk-decode(EncodedPublicKeyType $pk --> DecodedPK[Vec[RingElement,K]]) {
	my $t1 = Vec[RingElement,K,:dim($k)].new(elements => RingElement.zero xx $k);
	my $chunk-size = (bitlen(q - 1) - d) * 32;
	my $rho = Seed32.new: $pk.subbuf(0, 32);
	my @z = $pk.subbuf(32).rotor($chunk-size).map({ blob8.new($_) });

	for ^$k -> $i {
            $t1.elements[$i] = self!simple-bit-unpack(@z[$i],  t1-max);
	}
	DecodedPK[Vec[RingElement,K,:dim($k)]]
	.new(rho => $rho, t1 => $t1)
    }

    # Algorithm 24 skEncode
    method !sk-encode(Seed32 $rho, Seed32 $K, Seed64 $tr,
		      Vec[RingElement,L] $s1, Vec[RingElement,K] $s2,
		      Vec[RingElement,K] $t0 --> EncodedPrivateKeyType) {
	my $sk = buf8.new(|$rho, |$K, |$tr);
	for ^$l -> $i { $sk.append: self!bit-pack($s1.elements[$i], $𝜂, $𝜂) }
	for ^$k -> $i { $sk.append: self!bit-pack($s2.elements[$i], $𝜂, $𝜂 ) }
	for ^$k -> $i { $sk.append: self!bit-pack($t0.elements[$i], 1 +< (d - 1) - 1 , 1 +< (d - 1)) }
	blob8.new: $sk
    }

    # Algorithm 25 skDecode
    # ⚠ Call to bit-pack mail fail
    method !sk-decode(EncodedPrivateKeyType $sk 
		      --> DecodedSK[Seed32, Seed32, Seed64, Vec[RingElement,L],
				    Vec[RingElement,K], Vec[RingElement,K]]) {
	my $s1 = Vec[RingElement,L,:dim($l)].new(elements => RingElement.zero xx $l);
	my $s2 = Vec[RingElement,K,:dim($k)].new(elements => RingElement.zero xx $k);
	my $t0 = Vec[RingElement,K,:dim($k)].new(elements => RingElement.zero xx $k);
	my $rho = Seed32.new: $sk.subbuf(0, 32); 
	my $K = Seed32.new: $sk.subbuf(32, 32);
	my $tr =  Seed64.new: $sk.subbuf(64,64);
	my Int $offset = 32+32+64;
	my Int $amount = 32 * bitlen(2*$𝜂);
	
	for ^$l -> $i {
	    $s1.elements[$i] = self!bit-unpack($sk.subbuf($offset + $amount * $i,$amount), $𝜂, $𝜂);
	    fail "skDecode: s1[$i] has coefficient outside [-η, η]" unless all($s1.elements[$i].coeffs) ~~ -$𝜂..$𝜂;
	}

	$offset = $offset + $amount * $l;
	
	for ^$k -> $i {
	    $s2.elements[$i] = self!bit-unpack($sk.subbuf($offset+$amount * $i,$amount), $𝜂, $𝜂);
	    fail "skDecode: s2[$i] has coefficient outside [-η, η]" unless all($s2.elements[$i].coeffs) ~~ -$𝜂..$𝜂;
	}

	$offset = $offset + $amount * $k;
	$amount = 32 * d;
	
	for ^$k -> $i {
	    $t0.elements[$i] = self!bit-unpack($sk.subbuf($offset+$amount * $i,$amount),
				       (1 +< (d - 1)) - 1 , 1 +< (d - 1)); 	    
	}
	
	DecodedSK[
	    Seed32,
	    Seed32,
	    Seed64,
    	    Vec[RingElement,L,:dim($l)],
	    Vec[RingElement,K,:dim($k)],
	    Vec[RingElement,K,:dim($k)]
	]
	.new(rho => $rho, K => $K, tr => $tr, s1 => $s1, s2 => $s2, t0 => $t0)
	
    }

    # Algorithm 26 sigEncode
    method !sig-encode(LambdaDivFourSizedType $c̃, Vec[RingElement,L] $z, Vec[R2Element,K] $h --> EncodedSignatureType) {
	my $sigma = buf8.new($c̃);
	for ^$l -> $i {$sigma.append: self!bit-pack($z.elements[$i], $ɣ1 - 1, $ɣ1) };
	$sigma.append: |self!hint-bit-pack($h);
	blob8.new: $sigma
    }

    # Algorithm 27 sigDecode
    method !sig-decode(EncodedSignatureType $sigma -->DecodedSignature[LambdaDivFourSizedType, Vec[RingElement,L], Vec[R2Element,K]]) {
	my $z = Vec[RingElement,L,:dim($l)].new(elements =>  RingElement.zero xx $l);
	my $c̃ = LambdaDivFourSizedType.new: $sigma.subbuf(0, lambda-div-four($λ));
	my $chunk-size = 32 * (1 + bitlen($ɣ1 - 1));
	my @x = $sigma.subbuf(lambda-div-four($λ)).rotor($chunk-size).map({blob8.new($_)});
	my $y = blob8.new: $sigma.subbuf($sigma.elems - $ω - $k);
	for ^$l -> $i {
	    $z.elements[$i] = self!bit-unpack(@x[$i], $ɣ1 - 1, $ɣ1);
	}
	my $h = self!hint-bit-unpack($y);
	DecodedSignature[
	    LambdaDivFourSizedType,
	    Vec[RingElement,L,:dim($l)],
	    Vec[R2Element,K,:dim($k)]
	]
	.new( c̃ => $c̃, z => $z, h => $h)
    }

    # Algorithm 28 w1Encode
    method !w1-encode(Vec[RingElement,K] $w1 where 0 <= *.elements <= ((q - 1) div (2 * $ɣ2) - 1) --> EncodedWTildeType) {
	my $w̃1 = buf8.new;
	for ^$k -> $i {
	    $w̃1.append: self!simple-bit-pack($w1.elements[$i], (q - 1) div (2 * $ɣ2) - 1);
	}
	blob8.new: $w̃1	
    }    

    # Algorithm 35 Power2Round
    multi method power2-round(Vec[RqElement,K] $r --> TwoTuple[Vec[RingElement,K], Vec[RingElement,K]]) {
	my @t1;
	my @t0;
	
	for ^$k -> $i {
            my (@lt1s, @lt0s);

            for ^256 -> $j {
		my $decomposed-r = self.power2-round($r.elements[$i].coeffs[$j]);
		@lt1s.push: $decomposed-r.v2;
		@lt0s.push: $decomposed-r.v1;
            }
            @t1.push: RingElement.new(coeffs => @lt1s);
            @t0.push: RingElement.new(coeffs => @lt0s);
	}
    
	TwoTuple[Vec[RingElement,K,:dim($k)], Vec[RingElement,K,:dim($k)]].new(
	    v2 => Vec[RingElement,K,:dim($k)].new(elements => @t1),
	    v1 => Vec[RingElement,K,:dim($k)].new(elements => @t0))
    }

    multi method power2-round(FieldElement:D $r --> TwoTuple[Int:D, Int:D]) {
	my $rtmp = $r % q;
	my $r0 = mod-pm($rtmp, 1 +< d);
	TwoTuple[Int:D,Int:D].new(v2 => (($rtmp - $r0)  +> d), v1 => $r0)
    }

    
    # Algorithm 36 Decompose
    method !decompose(FieldElement $r --> TwoTuple[Int,Int]) {
	my $rplus = $r % q;
	my $r0 = mod-pm($rplus, $ɣ2 +< 1);
	if $rplus - $r0 == q - 1 {
	    TwoTuple[Int, Int].new: v1 => 0, v2 => $r0 - 1
	} else {
	    TwoTuple[Int, Int].new: v1 => ($rplus - $r0) div ($ɣ2 +< 1), v2 => $r0
	}
    }

    # Algorithm 37 HighBits
    multi method high-bits(Vec[RqElement,K] $r --> Vec[RingElement,K]) {
	Vec[RingElement,K,:dim($k)].new(elements => $r.elements.map: { self.high-bits($_) })
    }

    multi method high-bits(RqElement $r --> RingElement) {
	RingElement.new: coeffs => [$r.coeffs.map: { self.high-bits($_) }]
    }

    multi method high-bits(FieldElement $r --> Int) {
	self!decompose($r).v1
    }
 
    # Algorithm 38 LowBits
    multi method low-bits(Vec[RqElement,K] $r --> Vec[RingElement,K]) {
	Vec[RingElement,K,:dim($k)].new(elements => $r.elements.map: { self.low-bits($_) })
    }

    multi method low-bits(RqElement $r --> RingElement) {
	RingElement.new: coeffs => [$r.coeffs.map: { self.low-bits($_) }]
    }

    multi method low-bits(FieldElement $r --> Int) {
	self!decompose($r).v2
    }

    # Algorithm 39 MakeHint
    multi method make-hint(Vec[RqElement,K] $z, Vec[RqElement,K] $r --> Vec[R2Element,K]) {
	Vec[R2Element,K,:dim($k)].new(elements => [($z.elements Z $r.elements).map: -> ($zi, $ri) { self.make-hint($zi, $ri) }])
    }

    multi method make-hint(RqElement $z, RqElement $r --> R2Element) {
	R2Element.new: coeffs => [($z.coeffs Z $r.coeffs).map: -> ($zi, $ri) { self.make-hint($zi, $ri) }]
    }
    
    multi method make-hint(FieldElement:D $z, FieldElement:D $r --> Bit) {
	my $r1 = self.high-bits($r);
	my $v1 = self.high-bits((($r + $z) %q));  # check if you can overload + for FielddElement instead
	+($r1 != $v1)
    }

    # Algorithm 40 UseHint
    multi method use-hint(Vec[R2Element,K] $h, Vec[RqElement,K] $r --> Vec[RingElement,K]) {
	Vec[RingElement,K,:dim($k)].new(elements =>
	    ($h.elements Z $r.elements).map: -> ($hi, $ri) { self.use-hint($hi, $ri) }
	)
    }

    multi method use-hint(R2Element $h, RqElement $r --> RingElement) {
	RingElement.new: coeffs => [($h.coeffs Z $r.coeffs).map: -> ($hi, $ri) { self.use-hint(?$hi, $ri) }]
    }

    multi method use-hint(Bool:D $h, FieldElement:D $r --> Int:D) {

	my $m = ENTER { (q - 1) div (2 * $ɣ2) }

	POST { 0 <= $_ <= $m }

	my $d = self!decompose($r);

	return $h
        ?? $d.v2 > 0 ?? ($d.v1 + 1) % $m !! ($d.v1 - 1) % $m
	!! $d.v1;
    }
}

# Algorithm 44 AddNTT
multi sub infix:<+>(NTTElement $â, NTTElement $b̂ --> NTTElement) {
    NTTElement.new: coeffs => [($â.coeffs «+» $b̂.coeffs) «%» q]
}

# SubtractNTT
multi sub infix:<->(NTTElement $â, NTTElement $b̂ --> NTTElement) {
    NTTElement.new: coeffs => [($â.coeffs «-» $b̂.coeffs) «%» q]
}

multi sub infix:<->(Vec[NTTElement,K] $a, Vec[NTTElement,K] $b --> Vec[NTTElement,K]) {
    Vec[NTTElement,K,:dim($a.dim)].new: elements => [$a.elements «-» $b.elements]
}

# Algorithm 45 MultiplyNTT
multi sub infix:<∘>(NTTElement $â, NTTElement $b̂ --> NTTElement) {
    NTTElement.new: coeffs => [$â.coeffs «*» $b̂.coeffs «%» q]
}

# Algorithm 47 ScalarVectorNTT
multi sub infix:<∘>(NTTElement $â, Vec[NTTElement,L] $b̂ --> Vec[NTTElement, L]) {
    Vec[NTTElement, L, :dim($b̂.dim)].new: elements =>  [$b̂.elements.map: { $â ∘ $_ }];
}

multi sub infix:<∘>(NTTElement $â, Vec[NTTElement, K] $b̂ --> Vec[NTTElement, K]) {
    Vec[NTTElement, K, :dim($b̂.dim)].new: elements => [$b̂.elements.map: { $â ∘ $_ }] ;
}

# Algorithm 48 MatrixVectorNTT
# This is the only operation that takes a L length vector and return a K length vector
multi sub infix:<∘>(NTTMatrix $M̂, Vec[NTTElement, L] $v̂ --> Vec[NTTElement, K]) {
    my ($dim-k, $dim-l) = $M̂.shape;
    Vec[NTTElement, K, :dim($dim-k)].new:
    elements =>
    (^$dim-k).map: -> $i {
        (^$dim-l).map(-> $j
            {
                $M̂[$i;$j] ∘ $v̂.elements[$j]
        })
            .reduce: { $^a + $^b }
    }
}

# Other user defined arithmetic operators

# helper modulus reduction function
sub coeffs-op(&op, Ring $a, Ring $b, Bool :$reduce = False) {
    my @c = &op($a.coeffs, $b.coeffs);
    $reduce ?? (@c «%» q) !! @c
}

# When a product 𝑎 ⋅ 𝑏 or a sum 𝑎 + 𝑏 is written
# and either 𝑎 or 𝑏 is a congruence class modulo 𝑚
# (i.e., if either 𝑎 or 𝑏 is an element of ℤ𝑚 or 𝑅𝑚 ),
# then the product or sum is also understood
# to be a congruence class modulo 𝑚 (i.e., an element of ℤ𝑚 or 𝑅𝑚 ).    

multi sub infix:<->(RingElement $a, RingElement $b --> RingElement) {
    RingElement.new: coeffs => [coeffs-op(&[«-»], $a, $b)]
}

# Mixed → RqElement (promotion rule from spec)
multi sub infix:<+>(RingElement $a, RqElement $b --> RqElement) {
    RqElement.new: coeffs => [coeffs-op(&[«+»], $a, $b, :reduce)]
}

# Mixed → RqElement (promotion rule from spec)
multi sub infix:<+>(RqElement $a, RingElement $b --> RqElement) {
    RqElement.new: coeffs => [coeffs-op(&[«+»], $a, $b, :reduce)]
}

multi sub infix:<+>(RqElement $a, RqElement $b --> RqElement) {
    RqElement.new: coeffs => [coeffs-op(&[«+»], $a, $b, :reduce)]
}

multi sub infix:<->(RqElement $a, RqElement $b --> RqElement) {
    RqElement.new: coeffs => [coeffs-op(&[«-»], $a, $b, :reduce)]
}

multi sub prefix:<->(RqElement $a --> RqElement) {
    RqElement.new: coeffs => [(-«$a.coeffs) «%» q]
}

multi sub prefix:<->(Vec[RqElement,K] $a --> Vec[RqElement,K]) {
    Vec[RqElement,K,:dim($a.dim)].new: elements => (-« $a.elements)
}

# Mixed → RqElement (promotion rule from spec)
multi sub infix:<+>(Vec[RqElement,K] $a, Vec[RingElement,K] $b --> Vec[RqElement,K]) {
    Vec[RqElement,K,:dim($a.dim)].new: elements => [$a.elements «+» $b.elements]
}

# Mixed → RqElement (promotion rule from spec)
multi sub infix:<+>(Vec[RingElement,L] $a, Vec[RqElement,L] $b --> Vec[RqElement,L]) {
    Vec[RqElement,L,:dim($a.dim)].new: elements => [$a.elements «+» $b.elements]
}

multi sub infix:<->(Vec[RqElement,K] $a, Vec[RqElement,K] $b --> Vec[RqElement,K]) {
    Vec[RqElement,K,:dim($a.dim)].new: elements => [$a.elements «-» $b.elements]
}

multi sub infix:<+>(Vec[RqElement,K] $a, Vec[RqElement,K] $b --> Vec[RqElement,K]) {
    Vec[RqElement,K,:dim($a.dim)].new: elements => [$a.elements «+» $b.elements]
}

# mod±2𝑑
multi sub  mod-pm(Int:D $a, UInt:D $b --> Int:D) {
    my $r = $a % $b;
    $r > ($b +> 1) ?? $r - $b !! $r
}

multi sub mod-pm(RqElement $a, UInt:D $b --> RingElement) {
    RingElement.new: coeffs => [$a.coeffs.map: { mod-pm($_, $b) }]
}

multi sub mod-pm(Vec[RqElement,K] $a, UInt:D $b --> Vec[RingElement,K]) {
    Vec[RingElement,K,:dim($a.dim)].new(elements => $a.elements.map: { mod-pm($_, $b) })
}    

multi sub mod-pm(Vec[RqElement,L] $a, UInt:D $b --> Vec[RingElement,L]) {
    Vec[RingElement,L,:dim($a.dim)].new(elements => $a.elements.map: { mod-pm($_, $b) })
}    

# The infinity norm
# For a length-𝑚 vector 𝐰 with entries from 𝑅 or 𝑅𝑞 , ‖𝐰‖∞ = max0≤𝑖<𝑚 ‖𝑤[𝑖]‖∞
multi sub infinity-norm( Vec $w  --> Int:D) {
    $w.elements.map({infinity-norm($_)}).max
}

# For an element 𝑤 of 𝑅 or 𝑅𝑞 ,‖𝑤‖∞ = max0≤𝑖<256 ‖𝑤𝑖‖∞
multi sub infinity-norm(Ring $w --> Int:D) {
    $w.coeffs.map({infinity-norm($_)}).max
    
}

# For an element 𝑤 ∈ ℤ𝑞 ,‖𝑤‖∞ = ∣𝑤 mod± 𝑞∣	
multi sub infinity-norm(FieldElement $w --> Int:D) {
    mod-pm($w, q).abs
}

# For an element 𝑤 ∈ ℤ, ‖𝑤‖∞ = |𝑤|, the absolute value of 𝑤
multi sub infinity-norm(Int:D $w --> Int:D) {
    #  For an element 𝑤 ∈ ℤ, ‖𝑤‖ = |𝑤|, the absolute value	
    $w.abs()
}

# subsets creation helpers
sub vec-of($type, $n) {
    -> $arr { $arr ~~ Array && $arr.elems == $n && $arr.all ~~ $type }
}

# Helper to create subsets programmatically
sub make-subset(Str $name, Mu $base, &refinement) {
    Metamodel::SubsetHOW.new_type(
        name => $name,
        refinee => $base,
        refinement => &refinement
    )
}

# Factory function
sub make-ml-dsa(UInt :$k, UInt :$l, UInt :$η,
                UInt :$λ, UInt :$ɣ1, UInt :$ɣ2, UInt :$𝜏, UInt :$ω, UInt :$𝛽) {
    
    my \EncodedPKType = make-subset("EncodedPublicKey_{$k}{$l}", blob8, -> $v { $v.elems == pk-size($k) });
    my \EncodedSKType = make-subset("EncodedPrivateKey_{$k}{$l}", blob8, -> $v { $v.elems == sk-size($k, $l, $η) });
    my \EncodedSignatureType = make-subset("EncodedSignature_{$k}{$l}",
					   blob8, -> $v { $v.elems == encoded-signature-size($k, $l, $λ, $ɣ1, $ω) });
    my \LambdaDivFourSizedType = make-subset("LambdaDivFourSized_{$k}{$l}", blob8, -> $v { $v.elems == lambda-div-four($λ) });
    my \EncodedWTildeType = make-subset("SignatureCTilde_{$k}{$l}", blob8, -> $v { $v.elems == encoded-w̃1-size($k, $ɣ2) });

    my \CoeffType = $η == 2 ?? CoeffEta2 !! CoeffEta4;
    
    ML-DSA[EncodedPKType, EncodedSKType, EncodedSignatureType,
	   LambdaDivFourSizedType, EncodedWTildeType, CoeffType,

           :k($k), :l($l), :𝜂($η), :λ($λ), :ɣ1($ɣ1), :ɣ2($ɣ2), :𝜏($𝜏), :ω($ω), :𝛽($𝛽)]
}

# Instantiation - all types derived from parameters
constant ML_DSA_44 is export = make-ml-dsa(:k(4), :l(4), :η(2), :λ(128), :ɣ1(131072), :ɣ2(95232),  :𝜏(39), :ω(80), :𝛽(78));
constant ML_DSA_65 is export = make-ml-dsa(:k(6), :l(5), :η(4), :λ(192), :ɣ1(524288), :ɣ2(261888), :𝜏(49), :ω(55), :𝛽(196));
constant ML_DSA_87 is export = make-ml-dsa(:k(8), :l(7), :η(2), :λ(256), :ɣ1(524288), :ɣ2(261888), :𝜏(60), :ω(75), :𝛽(120));
