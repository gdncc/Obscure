NAME
====

Obscure::Signatures::ML-DSA

DESCRIPTION
===========

A pure Raku implementation of ML-DSA (Module-Lattice-Based Digital Signature Algorithm) as specified in FIPS 204. It provides three parameter sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87, offering NIST security categories 2, 3, and 5 respectively. It supports pure ML-DSA and prehash (HashML-DSA) modes with optional application context.

Caution! Under no circumstances should this be used for cryptographic applications. This is an educational resource. The intended use of this project is for learning and experimenting with cryptography using Raku.

SYNOPSIS
========

```raku
use Obscure::Signatures::ML-DSA;

# Key generation
my $dsa = ML_DSA_44.new;
my $kp = $dsa.keygen;
# $kp.public  — encoded public key (blob8)
# $kp.private — encoded secret key (blob8)

# Signing (pure ML-DSA)
my $msg = "Hello, post-quantum world!".encode;
my $sig = $dsa.sign(:sk($kp.private), :M($msg));

# Verification
say $dsa.verify(:pk($kp.public), :M($msg), :signature($sig)); # True

# Signing with context
my $ctx = buf8.new(0x41, 0x42); # application context, max 255 bytes
$sig = $dsa.sign(:sk($kp.private), :M($msg), :ctx($ctx));
say $dsa.verify(:pk($kp.public), :M($msg), :signature($sig), :ctx($ctx)); # True

# Prehash ML-DSA (HashML-DSA)
$sig = $dsa.sign(:sk($kp.private), :M($msg), :prehash-fn("SHAKE-128"));
say $dsa.verify(:pk($kp.public), :M($msg), :signature($sig),
                :prehash-fn("SHAKE-128")); # True

# Deterministic signing (no random nonce)
$sig = $dsa.sign(:sk($kp.private), :M($msg), :deterministic);
```

PARAMETER SETS
==============

<table class="pod-table">
<caption>ML-DSA Parameter Sets</caption>
<tbody>
<tr> <td></td> <td>ML-DSA-44</td> <td>ML-DSA-65</td> <td>ML-DSA-87</td> </tr> <tr> <td>NIST Security Category</td> <td>2</td> <td>3</td> <td>5</td> </tr> <tr> <td>Public key (bytes)</td> <td>1312</td> <td>1952</td> <td>2592</td> </tr> <tr> <td>Secret key (bytes)</td> <td>2560</td> <td>4032</td> <td>4896</td> </tr> <tr> <td>Signature (bytes)</td> <td>2420</td> <td>3309</td> <td>4627</td> </tr> <tr> <td>Raku constant</td> <td>ML_DSA_44</td> <td>ML_DSA_65</td> <td>ML_DSA_87</td> </tr>
</tbody>
</table>

API REFERENCE
=============

keygen() --> KeyPair
--------------------

Generates a fresh key pair. Returns a `KeyPair` object with two attributes:

  * `.public` — encoded public key (blob8)

  * `.private` — encoded secret key (blob8)

```raku
my $dsa = ML_DSA_65.new;
my $kp = $dsa.keygen;
```

sign(:sk, :M, :ctx?, :deterministic?, :prehash-fn?) --> blob8
-------------------------------------------------------------

Signs a message and returns the encoded signature.

  * `:sk` — secret key from keygen (blob8)

  * `:M` — message (blob8)

  * `:ctx` — optional application context (buf8, max 255 bytes, default empty)

  * `:deterministic` — optional Bool (default False); uses a zero nonce when True

  * `:prehash-fn` — optional Str; enables HashML-DSA mode. One of: `"SHAKE-128"`, `"SHAKE-256"`, `"SHA3-224"`, `"SHA3-256"`, `"SHA3-384"`, `"SHA3-512"`

verify(:pk, :M, :signature, :ctx?, :prehash-fn?) --> Bool
---------------------------------------------------------

Verifies a signature against a message and public key. Returns `True` if valid.

  * `:pk` — public key from keygen (blob8)

  * `:M` — message (blob8)

  * `:signature` — signature from sign (blob8)

  * `:ctx` — must match the context used during signing

  * `:prehash-fn` — must match the prehash function used during signing

ERROR HANDLING
==============

  * Wrong key or signature sizes cause a multi-dispatch failure (`X::Multi::NoMatch`) because the blob does not satisfy the subset type constraint.

  * Context longer than 255 bytes causes a subset constraint error.

  * An unsupported prehash string fails with "Unsupported prehash algorithm".

  * RNG failure dies with "random bit generation failed".

Raku's type system enforces correct parameter sizes at method boundaries. Passing a blob8 of the wrong length (e.g. a ML-DSA-44 key to ML-DSA-87) will cause a dispatch exception. Wrap calls in `try { }` blocks to handle gracefully.

```raku
# Handling errors
my $result = try {
    $dsa.verify(:pk($kp.public), :M($msg), :signature($bad-sig));
}
without $result { say "Verification failed or error: $!" }
```

MISC NOTES
==========

Installation
------------

The Raku module management tool `zef` performs module testing by default when installing a package. Some tests can be very slow, so you may want to skip them during the installation of Obscure and run them at a later stage. Use one of the following installation methods accordingly.

Install from a local directory without testing:

```bash
zef install --/test ./Obscure
```

Or install from a local directory with testing:

```bash
zef install -v --timeout=0 ./Obscure
```

Or install from GitHub without testing:

```bash
zef install --/test https://github.com/gdncc/Obscure.git
```

Or install from GitHub with testing:

```bash
zef install -v --timeout=0 https://github.com/gdncc/Obscure.git
```

Once successfully installed, you can remove Obscure as follows:

```bash
zef uninstall Obscure
```

Generate Markdown Documentation from Plain Old Documentation (pod)
------------------------------------------------------------------

```bash
raku --doc=Markdown doc/Signatures/ML-DSA.rakudoc > doc/Signatures/ML-DSA.md
```

Testing
-------

The test-suite validates against official NIST ACVP test vectors for all three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87). Running the full vector tests is very slow.

```bash
raku -I . t/03-ML-DSA.rakutest
```

See FIPS 204: [https://csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)

AUTHOR
======

Gérald Doussot

COPYRIGHT AND LICENSE
=====================

Copyright (c) 2026 Gérald Doussot

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

