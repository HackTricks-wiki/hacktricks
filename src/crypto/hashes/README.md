# Hashes, MAC's en KDF's

{{#include ../../banners/hacktricks-training.md}}

## Algemene CTF-patrone

- "Signature" is eintlik `hash(secret || message)` → length extension.
- Hashes van wagwoorde sonder salt → vinniger herhaalde cracking en voorafberekende opsoekaanvalle.
- Hash en MAC word verwar (hash != verifikasie).

## Length extension attack

### Tegniek

'n Length-extension attack kan moontlik wees wanneer 'n bediener 'n "signature" soos hierdie bereken:

`sig = HASH(secret || message)`

en 'n Merkle-Damgård-hash soos MD5, SHA-1 of SHA-256 gebruik.

As jy die volgende ken:

- `message`
- `sig`
- hash-funksie
- (of `len(secret)` met brute-force kan bepaal)

Dan kan jy 'n geldige signature vir die volgende bereken:

`message || padding || appended_data`

sonder om die secret te ken.<sup>[[1]](#references)</sup>

### Belangrike beperking: HMAC word nie geraak nie

Length-extension attacks is van toepassing op kwesbare prefix-konstruksies soos `HASH(secret || message)`. Hulle stel nie die HMAC-konstruksie bloot nie (byvoorbeeld HMAC-SHA256), wat 'n sleutel met afsonderlike binneste en buitenste hash-bewerkings kombineer.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-bindings vir die HashPump length-extension-tool<sup>[[7]](#references)</sup>

### Goeie verduideliking

[Alles wat jy oor hash length extension attacks moet weet](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing en cracking van wagwoorde

### Eerste vrae<sup>[[4]](#references)</sup>

- Is dit **gesout**? (soek na formate soos `salt$hash`)
- Is dit 'n **vinnige hash** (MD5/SHA1/SHA256) of 'n **stadige KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Het jy 'n **formaatwenk** (hashcat-modus / John-formaat)?

### Praktiese werkvloei<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiseer die hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. As dit ongesout en algemeen is: probeer aanlyn DB's en identifikasie-instrumente uit die crypto-werkvloei-afdeling.
3. Andersins, crack dit:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Algemene foute wat jy kan uitbuit

- Dieselfde wagwoord word deur verskeie gebruikers hergebruik → crack een, pivot.
- Afgekapte hashes / pasgemaakte transformasies → normaliseer en probeer weer.
- Swak KDF-parameters (bv. min PBKDF2-iterasies) → steeds crackbaar.

### bcrypt-orakel met gekose invoer en 'n bygevoegde secret

'n Aanroepbare helper wat `bcrypt(user_input || secret)` teruggee, kan inligting oor 'n bygevoegde secret blootlê as sy bcrypt-implementering invoer ná 72 **bytes** stilweg afkap. 'n Limiet op die aantal karakters voor UTF-8-enkodering dwing nie daardie byte-limiet af nie: multigreepkarakters kan die bcrypt-invoer vul en net plek vir 'n klein voorvoegsel van die secret oorlaat. Gekose invoere en hul teruggekeerde hashes kan dan vanlyn kontroles van kandidaat-agtervoegselbytes moontlik maak. Dit vereis beheer oor die helper se invoer, kennis van die presiese transformasie en enkodering daarvan, en 'n implementering wat werklik afkap; 'n aanroepbare helper of 'n bcrypt-hash alleen bewys nie dié ketting nie. [pyca/bcrypt dokumenteer](https://github.com/pyca/bcrypt#maximum-password-length) dat huidige `hashpw` 'n fout veroorsaak vir invoere langer as 72 bytes, terwyl vorige gedrag dit stilweg afgekap het. Ander wrappers kan lang invoere vooraf hash of verwerp, so verifieer die geïnstalleerde implementering eerder as om afkapping te veronderstel.

Om 'n herwonne secret teen 'n ander rekening te gebruik, vereis ook bewyse dat sy blootgestelde hash met **dieselfde** secret en transformasie gegenereer is, plus 'n aparte geloofsbrief- of aanmeldpad. 'n Hashing-helper wat as root loop, moet slegs as 'n orakel beskou word as die gebruiker met minder voorregte dit onder die effektiewe beleid kan aanroep; passiewe gasheerenumerasie hoef dit nie aan te roep of gekose wagwoorde in te dien nie.

## References

- [1] [SkullSecurity - Alles wat jy oor hash length-extension attacks moet weet](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Die Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP-kontrolelys vir die stoor van wagwoorde](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-voorbeeldhashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper-opdragreëlopsies](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python-bindings vir HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
