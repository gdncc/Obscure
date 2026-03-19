# Obscure: a Raku Programming Language Cryptography Playground

> [!CAUTION]
> :warning: **Under no circumstances should this be used for cryptographic
applications.** :warning:
> 
> This is an educational resource. The intended use of this project
> is for learning and experimenting with cryptography using the
> [Raku](https://raku.org/)  programming language.


Implemented: 

- [`Obscure::Hashes::SHA3`](doc/Hashes/SHA3.md): A pure Raku implementation of
the SHA‑3 and SHAKE hash families. It provides four cryptographic hash
functions, SHA3-224, SHA3-256, SHA3-384, and SHA3-512, and two extendable-output
functions (XOFs), SHAKE128 and SHAKE256 of the SHA-3 family of functions. It
provides one-shot, and streaming APIs.

- [`Obscure::Signatures::ML-DSA`](doc/Signatures/ML-DSA.md): A pure Raku
implementation of ML-DSA (FIPS 204), a post-quantum digital signature scheme.
It provides three parameter sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87. It
supports pure ML-DSA and prehash (HashML-DSA) modes with optional
application context.
