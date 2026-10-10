# Simmetriese Crypto

{{#include ../../banners/hacktricks-training.md}}

## Waarna om in CTFs te kyk

- **Misbruik van modes**: ECB-patrone, CBC-malleability, hergebruik van CTR/GCM-nonce.
- **Padding oracles**: verskillende foute/tydsberekeninge vir verkeerde padding.
- **MAC-verwarring**: gebruik van CBC-MAC met boodskappe van veranderlike lengte, of foute met MAC-then-encrypt.
- **XOR oral**: stream ciphers en pasgemaakte konstruksies kom dikwels neer op XOR met ’n keystream.

## AES-modes en misbruik

NIST spesifiseer die ECB-, CBC- en CTR-vertroulikheidsmodes in SP 800-38A en GCM-geënkripteerde verifikasie in SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB lek patrone: identiese plaintext-blokke → identiese ciphertext-blokke. Dit maak die volgende moontlik:

- Cut-and-paste / herrangskikking van blokke
- Skrap van blokke (as die formaat geldig bly)

As jy plaintext kan beheer en ciphertext (of cookies) kan waarneem, probeer om herhaalde blokke te skep (bv. baie `A`s) en soek na herhalings.

### CBC: Cipher Block Chaining

- CBC is **malleable**: die omslaan van bisse in `C[i-1]` laat voorspelbare bisse in `P[i]` omslaan, terwyl dit ook `P[i-1]` beskadig. Deur die IV te verander, kan jy die eerste plaintext-blok teiken sonder om ’n vorige plaintext-blok te beskadig.
- As die stelsel geldige padding van ongeldige padding onderskei, het jy dalk ’n **padding oracle**.

### CTR

CTR verander AES in ’n stream cipher: `C = P XOR keystream`.

As ’n nonce/IV met dieselfde sleutel hergebruik word:

- `C1 XOR C2 = P1 XOR P2` (klassieke hergebruik van keystream)
- Met bekende plaintext kan jy die keystream herwin en ander boodskappe dekripteer.

**Patrone vir die uitbuiting van hergebruikte nonce/IV**

- Herwin die keystream waar plaintext bekend/raai­baar is:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Pas die herwonne keystream-grepe toe om enige ander ciphertext te dekripteer wat met dieselfde key+IV by dieselfde offsets geproduseer is.
- Data met ’n hoogs gestruktureerde formaat (bv. ASN.1/X.509-sertifikate, lêeropskrifte, JSON/CBOR) bevat groot gebiede bekende plaintext. Jy kan dikwels die ciphertext van die sertifikaat met die voorspelbare sertifikaatinhoud XOR om die keystream af te lei, en dan ander geheime dekripteer wat onder die hergebruikte IV geënkripteer is. Sien ook [TLS & Certificates](../tls-and-certificates/README.md) vir tipiese sertifikaatuitlegte.<sup>[[1]](#references)</sup>
- Wanneer verskeie geheime met dieselfde geserialiseerde formaat/grootte onder dieselfde key+IV geënkripteer word, lek veldbelyning selfs sonder volledige bekende plaintext. Voorbeeld: PKCS#8 RSA-sleutels met dieselfde modulusgrootte plaas priemfaktore by ooreenstemmende offsets (~99.6% belyning vir 2048-bit). Deur twee ciphertexts onder die hergebruikte keystream te XOR, word `p ⊕ p'` / `q ⊕ q'` geïsoleer, wat binne sekondes met brute force herwin kan word.<sup>[[1]](#references)</sup>
- Standaard-IV’s in biblioteke (bv. konstante `000...01`) is ’n kritieke voetgeweer: elke enkripsie herhaal dieselfde keystream, wat CTR in ’n hergebruikte eenmalige sleutelblok verander.<sup>[[1]](#references)</sup>

**CTR se manipuleerbaarheid**

- CTR bied slegs vertroulikheid: die omkeer van bisse in ciphertext keer dieselfde bisse in plaintext deterministies om. Sonder ’n verifikasietag kan aanvallers data ongemerk verander (bv. sleutels, vlae of boodskappe wysig).
- Gebruik AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ens.) en dwing tag-verifikasie af om bit-flips op te spoor.

### GCM

GCM faal ook ernstig wanneer ’n nonce hergebruik word. As dieselfde key+nonce meer as een keer gebruik word, kry jy tipies:

- Hergebruik van die keystream vir enkripsie (soos CTR), wat herstel van plaintext moontlik maak wanneer enige plaintext bekend is.
- Verlies van integriteitswaarborge. Afhangend van wat blootgelê word (verskeie boodskap-/tag-pare onder dieselfde nonce), kan aanvallers moontlik tags vervals.

Operasionele riglyne:

- Behandel “nonce-hergebruik” in AEAD as ’n kritieke kwesbaarheid.
- Misbruikbestande AEAD’s soos AES-GCM-SIV verminder die gevolge van nonce-hergebruik. Bellers moet steeds unieke nonces verskaf soos die konstruksie se koppelvlak vereis; toevallige hergebruik het begrensde gevolge vergeleke met gewone GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- As jy verskeie ciphertexts onder dieselfde nonce het, begin deur verhoudings van die vorm `C1 XOR C2 = P1 XOR P2` na te gaan.

### Gereedskap

- [CyberChef](https://gchq.github.io/CyberChef/) vir vinnige eksperimente.<sup>[[8]](#references)</sup>
- Python se [PyCryptodome](https://www.pycryptodome.org/) pakket vir scripting.<sup>[[9]](#references)</sup>

## ECB-ontginningspatrone

ECB (Electronic Code Book) enkripteer elke blok afsonderlik:

- gelyke plaintext-blokke → gelyke ciphertext-blokke
- dit lek struktuur en maak cut-and-paste-aanvalle moontlik

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Opsporingsidee: token-/koekiepatroon

As jy verskeie kere aanmeld en **elke keer dieselfde koekie kry**, kan die ciphertext deterministies wees (ECB of ’n vaste IV).

As jy twee gebruikers skep met grotendeels identiese plaintext-uitlegte (bv. lang rye herhaalde karakters) en herhaalde ciphertext-blokke by dieselfde offsets sien, is ECB ’n waarskynlike verdagte.

### Ontginningspatrone

#### Verwydering van volledige blokke

As die tokenformaat iets soos `<username>|<password>` is en die blokgrens belyn, kan jy soms ’n gebruiker skep sodat die `admin`-blok belyn is, en dan voorafgaande blokke verwyder om ’n geldige token vir `admin` te kry.

#### Verskuiwing van blokke

As die backend opvulling/bykomende spasies verdra (`admin` teenoor `admin    `), kan jy:

- ’n blok belyn wat `admin   ` bevat
- daardie ciphertext-blok na ’n ander token omruil/hergebruik

## Padding Oracle

### Wat dit is

In CBC-modus, as die bediener direk of indirek openbaar of gedekripteerde plaintext **geldige PKCS#7-opvulling** het, kan jy dikwels:<sup>[[7]](#references)</sup>

- ciphertext sonder die sleutel dekripteer
- ’n ciphertext saamstel wat na gekose plaintext dekripteer wanneer jy voorafgaande blokke of IV’s kan indien wat jy self saamgestel het, en die toepassing die gevolglike boodskap met geldige opvulling aanvaar

Die oracle kan wees:

- ’n Spesifieke foutboodskap
- ’n Ander HTTP-status / reaksiegrootte
- ’n Tydsverskil

### Praktiese ontginning

PadBuster is die klassieke hulpmiddel:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Voorbeeld:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

Notas:

- Blokgrootte is dikwels `16` vir AES.
- `-encoding 0` beteken Base64.
- Gebruik `-error` as die oracle ’n spesifieke string is.

### Waarom dit werk

CBC-dekripsie bereken `P[i] = D(C[i]) XOR C[i-1]`. Deur grepe in `C[i-1]` te wysig en te kyk of die padding geldig is, kan jy `P[i]` greep vir greep herwin.

## Bit-flipping in CBC

Selfs sonder ’n padding oracle is CBC manipuleerbaar. As jy ciphertext-blokke kan wysig en die toepassing die gedekripteerde plaintext as gestruktureerde data gebruik (bv. `role=user`), kan jy spesifieke bisse verander om geselekteerde plaintext-grepe op ’n gekose posisie in die volgende blok om te skakel.

Tipiese CTF-patroon:

- Token = `IV || C1 || C2 || ...`
- Jy beheer grepe in `C[i]`
- Jy teiken plaintext-grepe in `P[i+1]` omdat `P[i+1] = D(C[i+1]) XOR C[i]`

Dit is op sigself nie ’n skending van vertroulikheid nie, maar dit is ’n algemene privilege-escalation-primitief wanneer integriteit ontbreek.

## CBC-MAC

CBC-MAC is slegs onder spesifieke voorwaardes veilig (veral **boodskappe met vaste lengte** en korrekte domeinskeiding). AES-CMAC is ’n gestandaardiseerde konstruksie wat veranderlike-lengte-insette veilig hanteer.<sup>[[5]](#references)</sup>

### Klassieke vervalsingspatroon vir veranderlike lengte

CBC-MAC word gewoonlik soos volg bereken:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

As jy tags vir gekose boodskappe kan verkry, kan jy dikwels ’n tag vir ’n aaneenskakeling (of verwante konstruksie) skep sonder om die sleutel te ken, deur uit te buit hoe CBC blokke aan mekaar koppel.

Dit kom dikwels voor in CTF-cookies/tokens wat die gebruikersnaam of rol met CBC-MAC MAC.

### Veiliger alternatiewe

- Gebruik HMAC (SHA-256/512)
- Gebruik CMAC (AES-CMAC) korrek
- Sluit boodskaplengte / domeinskeiding in

## Stroomsyfers: XOR en RC4

### Die denkraamwerk

Die meeste situasies met stroomsyfers kom neer op:

`ciphertext = plaintext XOR keystream`

Dus:

- As jy plaintext ken, herwin jy die keystream.
- As die keystream hergebruik word (dieselfde sleutel+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-gebaseerde enkripsie

As jy enige plaintext-segment by posisie `i` ken, kan jy keystream-grepe herwin en ander ciphertexts op daardie posisies dekripteer.

Outomatiese oplossers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is ’n verouderde stroomsyfer; enkripsie/dekripsie is dieselfde XOR-bewerking. Die bekende biases maak dit ongeskik vir nuwe stelsels, en TLS verbied die cipher suites daarvan uitdruklik.<sup>[[6]](#references)</sup>

As jy RC4-enkripsie van bekende plaintext met dieselfde sleutel kan kry, kan jy die keystream herwin en ander boodskappe van dieselfde lengte/verskuiwing dekripteer.

Verwysingskrywe (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Nalatigheid teenoor vakmanskap in kriptografie](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Aanbeveling vir bloksyferbedryfsmodusse](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Aanbeveling vir Galois/Counter Mode (GCM) en GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Nonce-misbruikweerstandige geverifieerde enkripsie](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Die AES-CMAC-algoritme](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Verbod op RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Toetsing vir Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome-dokumentasie](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
