# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Mifano ya kawaida ya CTF

- "Saini" ni kweli `hash(secret || message)` → length extension.
- Unsalted password hashes → uvunjaji rahisi / kutafuta.
- Kuchanganya hash na MAC (hash != uthibitishaji).

## Hash length extension attack

### Mbinu

Unaweza mara nyingi kuitumia ikiwa server inahesabu "saini" kama:

`sig = HASH(secret || message)`

na inatumia Merkle–Damgård hash (mfano wa kawaida: MD5, SHA-1, SHA-256).

Ikiwa unajua:

- `message`
- `sig`
- hash function
- (au unaweza brute-force) `len(secret)`

Basi unaweza kuhesabu saini halali ya:

`message || padding || appended_data`

bila kujua siri.

### Kizuizi muhimu: HMAC haiathiriwi

Length extension attacks zinatumika kwa ujenzi kama `HASH(secret || message)` kwa Merkle–Damgård hashes. Hazihusiani na **HMAC** (kwa mfano, HMAC-SHA256), ambayo imeundwa mahsusi kuepuka daraja hili la tatizo.

### Zana

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Maelezo mazuri

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### Maswali ya kwanza

- Je, imekuwa **salted**? (tazama `salt$hash` formats)
- Je, ni **fast hash** (MD5/SHA1/SHA256) au **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Je, una **format hint** (hashcat mode / John format)?

### Mtiririko wa vitendo

1. Tambua hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Ikiwa unsalted na za kawaida: jaribu DB za mtandaoni na zana za utambuzi kutoka sehemu ya crypto workflow.
3. Vinginevyo vunja:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Makosa ya kawaida unayoweza kuyatumia

- Nywila ile ile iliyotumika tena kwa watumiaji → vunja moja, pivot.
- Truncated hashes / custom transforms → weka kwa muundo wa kawaida na jaribu tena.
- Weak KDF parameters (mfano, mzunguko mdogo wa PBKDF2) → bado vinauvunjika.

{{#include ../../banners/hacktricks-training.md}}
