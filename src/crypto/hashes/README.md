# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Algemene CTF-patrone

- “Signature” is eintlik `hash(secret || message)` → length extension.
- Hashes sonder salt → vinniger herhaalde cracking en voorafberekende opsoekaanvalle.
- Hash met MAC verwar (hash != authentication).

## Hash length extension attack

### Tegniek

’n Length-extension-aanval kan moontlik wees wanneer ’n bediener ’n “signature” soos die volgende bereken:

`sig = HASH(secret || message)`

en ’n Merkle-Damgård-hash soos MD5, SHA-1 of SHA-256 gebruik.

As jy die volgende ken:

- `message`
- `sig`
- die hash-funksie
- (of `len(secret)` kan brute-force)

Dan kan jy ’n geldige signature vir die volgende bereken:

`message || padding || appended_data`

sonder om die secret te ken.<sup>[[1]](#references)</sup>

### Belangrike beperking: HMAC word nie beïnvloed nie

Length-extension-aanvalle is van toepassing op kwesbare prefix-konstruksies soos `HASH(secret || message)`. Dit ontbloot nie die HMAC-konstruksie nie (byvoorbeeld HMAC-SHA256), wat ’n sleutel kombineer met afsonderlike inner- en outer-hash-bewerkings.<sup>[[1]](#references)[[2]](#references)</sup>

### Gereedskap

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-bindings vir die HashPump length-extension tool<sup>[[7]](#references)</sup>

### Goeie verduideliking

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Wagwoord-hashing en cracking

### Eerste vrae<sup>[[4]](#references)</sup>

- Is dit **salted**? (soek na formate soos `salt$hash`)
- Is dit ’n **vinnige hash** (MD5/SHA1/SHA256) of ’n **stadige KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Het jy ’n **formaatwenk** (hashcat-modus / John-formaat)?

### Praktiese werkvloei<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiseer die hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. As dit unsalted en algemeen is: probeer aanlyndatabasisse en identifikasiehulpmiddels uit die crypto-werkvloeiafdeling.
3. Crack dit andersins:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Algemene foute wat jy kan uitbuit

- Dieselfde wagwoord word oor verskeie gebruikers hergebruik → crack een en pivot.
- Afgekapte hashes / pasgemaakte transformasies → normaliseer en probeer weer.
- Swak KDF-parameters (bv. min PBKDF2-iterasies) → steeds crackbaar.

### bcrypt-oracle met gekose invoer en ’n aangehegte secret

’n Aanroepbare helper wat `bcrypt(user_input || secret)` teruggee, kan inligting oor ’n aangehegte secret blootlê as die bcrypt-implementering invoer ná 72 **bytes** stilweg afkap. ’n Karakterlimiet voor UTF-8-kodering dwing nie daardie greeplimiet af nie: multigreepkarakters kan die bcrypt-invoer vul en net ruimte vir ’n klein voorvoegsel van die secret oorlaat. Gekose invoere en hul teruggestuurde hashes kan dan vanlynkontroles van kandidaat-agtervoegselgrepe moontlik maak. Dit vereis beheer oor die helper se invoer, kennis van die presiese transformasie en kodering, en ’n implementering wat werklik afkap; ’n aanroepbare helper of ’n bcrypt-hash alleen bewys nie die hele ketting nie. [pyca/bcrypt dokumenteer](https://github.com/pyca/bcrypt#maximum-password-length) dat huidige `hashpw` ’n fout veroorsaak vir invoere langer as 72 bytes, terwyl vroeëre gedrag dit stilweg afgekap het. Ander wrappers kan lang invoere vooraf hash of verwerp, dus moet jy die geïnstalleerde implementering verifieer eerder as om afkapping te aanvaar.

Om ’n herwonne secret teen ’n ander rekening te gebruik, vereis ook bewyse dat die blootgestelde hash met **dieselfde** secret en transformasie gegenereer is, plus ’n afsonderlike aanmeldbewys of aanmeldroete. ’n Hashing-helper wat as root loop, moet slegs as ’n oracle beskou word as die gebruiker met laer voorregte dit volgens die effektiewe beleid kan aanroep; passiewe gasheer-openumerasie hoef dit nie aan te roep of gekose wagwoorde in te dien nie.

## References

- [1] [SkullSecurity - Alles wat jy moet weet oor hash length-extension-aanvalle](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Die Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP-kontrolelys vir wagwoordberging](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-voorbeeldhashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper-opdragreëlopsies](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python-bindings vir HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
