# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Algemene CTF-patrone

- "Signature" is eintlik `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Hash word met MAC verwar (hash != authentication).

## Hash length extension attack

### Tegniek

Jy kan dit dikwels uitbuit as 'n bediener 'n "signature" soos die volgende bereken:

`sig = HASH(secret || message)`

en 'n Merkle–Damgård-hash gebruik (klassieke voorbeelde: MD5, SHA-1, SHA-256).

As jy die volgende ken:

- `message`
- `sig`
- hash-funksie
- (of `len(secret)` kan brute-force)

Dan kan jy 'n geldige signature bereken vir:

`message || padding || appended_data`

sonder om die secret te ken.<sup>[[1]](#references)</sup>

### Belangrike beperking: HMAC word nie geraak nie

Length extension attacks is van toepassing op konstruksies soos `HASH(secret || message)` vir Merkle–Damgård-hashes. Hulle is nie van toepassing op **HMAC** (byvoorbeeld HMAC-SHA256) nie, wat spesifiek ontwerp is om hierdie klas probleem te vermy.<sup>[[1]](#references)</sup>

### Tools

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

## Password hashing en cracking

### Eerste vrae

- Is dit **salted**? (soek na `salt$hash`-formate)
- Is dit 'n **fast hash** (MD5/SHA1/SHA256) of 'n **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Het jy 'n **format hint** (hashcat mode / John format)?

### Praktiese werkvloei

1. Identifiseer die hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. As dit unsalted en algemeen is: probeer online DBs en identification tooling uit die crypto workflow-afdeling.
3. Andersins, crack dit:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Algemene foute wat jy kan uitbuit

- Dieselfde password word oor gebruikers heen hergebruik → crack een, pivot.
- Truncated hashes / custom transforms → normaliseer en probeer weer.
- Weak KDF parameters (byvoorbeeld lae PBKDF2-iterations) → steeds crackable.

## Verwysings

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
