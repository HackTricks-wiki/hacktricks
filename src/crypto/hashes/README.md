# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Algemene CTF-patrone

- "Signature" is eintlik `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Hash met MAC deurmekaar maak (hash != authentication).

## Hash length extension attack

### Tegniek

Jy kan dit dikwels misbruik as 'n bediener 'n "signature" bereken soos:

`sig = HASH(secret || message)`

en 'n Merkle–Damgård hash gebruik (klassieke voorbeelde: MD5, SHA-1, SHA-256).

As jy die volgende weet:

- `message`
- `sig`
- hash function
- (of kan brute-force) `len(secret)`

Dan kan jy 'n geldige signature bereken vir:

`message || padding || appended_data`

sonder om die geheim te ken.

### Belangrike beperking: HMAC is nie geraak nie

Length extension attacks apply to constructions like `HASH(secret || message)` for Merkle–Damgård hashes. Dit geld nie vir **HMAC** (bv. HMAC-SHA256) nie, wat spesifiek ontwerp is om hierdie soort probleem te vermy.

### Gereedskap

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Goeie verduideliking

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### Eerste vrae

- Is dit **salted**? (kyk na `salt$hash` formate)
- Is dit 'n **fast hash** (MD5/SHA1/SHA256) of 'n **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Het jy 'n **format hint** (hashcat mode / John format)?

### Praktiese werkvloei

1. Identifiseer die hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. As dit unsalted en algemeen is: probeer aanlyn DB's en identifikasie-gereedskap uit die crypto workflow-afdeling.
3. Anders, crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Algemene foute wat jy kan uitbuit

- Selfde wagwoord hergebruik tussen gebruikers → crack one, pivot.
- Afgeknotte hashes / aangepaste transformasies → normaliseer en probeer weer.
- Swak KDF-parameters (bv. lae PBKDF2-iterasies) → kan steeds gekraak word.

{{#include ../../banners/hacktricks-training.md}}
