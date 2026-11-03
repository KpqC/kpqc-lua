# KpqC

KpqC provides synchronous Lua APIs for the AIMer and HAETAE signature schemes
and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs). This Lua package
is independently maintained and is not an official distribution from the
algorithm authors.

## Requirements

- Lua 5.1, 5.2, 5.3, 5.4, or 5.5
- CMake 3.18 or newer (4.3 or newer for direct Lua 5.5 auto-detection)
- A C11 compiler
- macOS or Linux

The package bundles its native algorithm sources and builds them locally. It
does not download native libraries during compilation.

## Install

From a release rock:

```sh
luarocks install kpqc
```

From a source checkout:

```sh
luarocks make kpqc-0.1.0-1.rockspec
```

## Available schemes

| Algorithm | Type | Values |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f`, `aimer128s`, `aimer192f`, `aimer192s`, `aimer256f`, `aimer256s` |
| **HAETAE** | Signature | `haetae2`, `haetae3`, `haetae5` |
| **NTRU+** | KEM | `ntruplus768`, `ntruplus864`, `ntruplus1152` |
| **SMAUG&#8209;T** | KEM | `smaugt128`, `smaugt192`, `smaugt256`, `timer` |

### Signatures

```lua
local kpqc = require("kpqc")

local keys = kpqc.aimer128f.generate_keypair()
local message = "release-manifest:v3"
local signature = kpqc.aimer128f.sign(message, keys.secret_key)
assert(kpqc.aimer128f.verify(message, signature, keys.public_key))
```

`sign` and `verify` accept an optional context string containing at most 255
bytes. Verification fails when the supplied context differs from the signing
context.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```lua
local kpqc = require("kpqc")

local recipient = kpqc.smaugt192.generate_keypair()
local outbound = kpqc.smaugt192.encapsulate(recipient.public_key)
local inbound = kpqc.smaugt192.decapsulate(
   outbound.ciphertext,
   recipient.secret_key
)
assert(inbound == outbound.shared_secret)
```

## Data and failures

Keys, signatures, ciphertexts, messages, contexts, and shared secrets are Lua
strings and may contain zero bytes. Native operation failures and invalid input
lengths raise Lua errors. Invalid signatures return `false`.

NTRU+ rejects non-canonical public keys and invalid ciphertexts. SMAUG-T uses
implicit rejection and returns a replacement secret for an invalid ciphertext;
it will not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Value | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `aimer128f` | 32 | 48 | 6,944 |
| `aimer128s` | 32 | 48 | 4,704 |
| `aimer192f` | 48 | 72 | 15,408 |
| `aimer192s` | 48 | 72 | 10,320 |
| `aimer256f` | 64 | 96 | 31,360 |
| `aimer256s` | 64 | 96 | 20,224 |
| `haetae2` | 992 | 1,408 | 1,474 |
| `haetae3` | 1,472 | 2,112 | 2,349 |
| `haetae5` | 2,080 | 2,752 | 2,948 |

#### KEMs

| Value | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `ntruplus768` | 1,152 | 2,336 | 1,152 | 32 |
| `ntruplus864` | 1,296 | 2,624 | 1,296 | 32 |
| `ntruplus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `smaugt128` | 672 | 832 | 672 | 32 |
| `smaugt192` | 1,088 | 1,312 | 992 | 32 |
| `smaugt256` | 1,440 | 1,728 | 1,376 | 32 |
| `timer` | 672 | 832 | 608 | 32 |

The same values are available at runtime through each algorithm's `sizes`
table. `kpqc.signature_algorithms` and `kpqc.kem_algorithms` list the supported
algorithm tables.

## Tests

After building the module in `build`:

```sh
LUA_CPATH="$PWD/build/?.so;;" lua test/api.lua
```

The optional known-answer suite validates all 1,600 records from the pinned
[`kpqc-test-vectors` revision `d75490bf824f`](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da):

```sh
cmake -S . -B build-kat -DKPQC_TEST_ENTROPY=ON
cmake --build build-kat
KPQC_TEST_VECTORS=../kpqc-test-vectors \
  LUA_CPATH="$PWD/build-kat/?.so;;" lua test/kat.lua
```

Deterministic entropy hooks are compiled only when `KPQC_TEST_ENTROPY=ON` and
are not present in normal builds.

## Security

The native cores are compiled from the upstream reference implementations.
This package has not received an independent security audit and does not
guarantee constant-time execution. Lua strings are immutable, so secret values
returned to Lua cannot be scrubbed in place. Assess these constraints before
using the package with sensitive production keys.

Algorithm encodings and parameter sizes follow the exact upstream revisions
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and may differ from
other revisions of the same algorithms.
