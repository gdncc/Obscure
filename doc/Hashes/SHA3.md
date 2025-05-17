NAME
====

Obscure::Hashes::SHA3

DESCRIPTION
===========

A pure Raku implementation of the SHA‑3 and SHAKE hash families. It provides four cryptographic hash functions, SHA3-224, SHA3-256, SHA3-384, and SHA3-512, and two extendable-output functions (XOFs), SHAKE128 and SHAKE256 of the SHA-3 family of functions. It provides one-shot, and streaming APIs.

This module is self‑contained.

Caution! Under no circumstances should this be used for cryptographic applications. This is an educational resource. The intended use of this project is for learning and experimenting with cryptography using Raku.

SYNOPSIS
========

```raku
use Obscure::Hashes::SHA3;

# SHA-3, one-shot

say SHA3_224().hash("hello world"); 

# SHA-3, streaming

my $streaming-sha = SHA3_256();
$streaming-sha.update: "hello";
$streaming-sha.update: " world";
say $streaming-sha.final».fmt("%02x").join; # 644b ...

$streaming-sha.reset;

$streaming-sha.update(Buf.new(<0x74 0x65 0x73 0x74>)); 
say $streaming-sha.final».fmt("%02x").join # 36f0 ...

# SHAKE

my $shake = SHAKE128();
$shake.absorb("Hello");
say $shake.squeeze(3)>>.fmt("%02x").join; # 4131f8
say $shake.squeeze(1)>>.fmt("%02x").join; # db
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
raku --doc=Markdown doc/Hashes/SHA3.rakudoc > doc/Hashes/SHA3.md
```

Testing
-------

The test-suite contains Secure Hash Algorithm-3 Validation System (SHA3VS) vectors: the short message, long message, and Monte Carlo (pseudorandom) tests for every implemented hash and XOF, plus variable-length-output tests for each XOF. Some basic performance tests are also included.

Running all tests is slow. By default, all tests except the Monte Carlo and performance tests are run. To run the full test suite:

```bash
OBSCURE_MONTECARLO_TEST=1 OBSCURE_PERF_TEST=1 raku -I . t/02-SHA3.rakutest
```

AUTHOR
======

Gérald Doussot

COPYRIGHT AND LICENSE
=====================

Copyright (c) 2025 Gérald Doussot

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

