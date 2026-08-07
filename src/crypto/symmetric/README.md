# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Cha kutafuta katika CTFs

- **Mode misuse**: mifumo ya ECB, CBC malleability, na nonce reuse katika CTR/GCM.
- **Padding oracles**: errors/timings tofauti kwa padding isiyo sahihi.
- **MAC confusion**: kutumia CBC-MAC na messages zenye urefu unaobadilika, au makosa ya MAC-then-encrypt.
- **XOR kila mahali**: stream ciphers na custom constructions mara nyingi hupunguzwa kuwa XOR yenye keystream.

## AES modes na misuse

### ECB: Electronic Codebook

ECB hu-leak patterns: plaintext blocks zilizo sawa → ciphertext blocks zilizo sawa. Hili huwezesha:

- Cut-and-paste / block reordering
- Block deletion (ikiwa format itaendelea kuwa valid)

Ikiwa unaweza kudhibiti plaintext na kuona ciphertext (au cookies), jaribu kutengeneza blocks zinazorudiwa (kwa mfano, `A` nyingi) na utafute marudio.

### CBC: Cipher Block Chaining

- CBC ni **malleable**: kubadilisha bits katika `C[i-1]` hubadilisha bits zinazotabirika katika `P[i]`.
- Ikiwa mfumo unaonyesha padding valid dhidi ya padding invalid, huenda una **padding oracle**.

### CTR

CTR hubadilisha AES kuwa stream cipher: `C = P XOR keystream`.

Ikiwa nonce/IV inatumiwa tena na key ileile:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Ukiwa na plaintext inayojulikana, unaweza kurecover keystream na ku-decrypt nyingine.

**Nonce/IV reuse exploitation patterns**

- Recover keystream mahali popote ambapo plaintext inajulikana au inaweza kukisiwa:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Tumia bytes za keystream zilizorecoveriwa ku-decrypt ciphertext nyingine yoyote iliyotengenezwa kwa key+IV ileile katika offsets zilezile.
- Data yenye muundo mkubwa (kwa mfano, vyeti vya ASN.1/X.509, file headers, JSON/CBOR) hutoa maeneo makubwa ya known-plaintext. Mara nyingi unaweza kufanya XOR ya ciphertext ya certificate na certificate body inayotabirika ili kupata keystream, kisha ku-decrypt secrets nyingine zilizonencryptiwa chini ya IV iliyotumiwa tena. Tazama pia [TLS & Certificates](../tls-and-certificates/README.md) kwa miundo ya kawaida ya certificates.<sup>[[1]](#references)</sup>
- Secrets nyingi zenye **serialized format/size ileile** zinapo-encryptiwa chini ya key+IV ileile, field alignment hu-leak hata bila known plaintext kamili. Mfano: PKCS#8 RSA keys zenye modulus size ileile huweka prime factors katika offsets zinazolingana (~99.6% alignment kwa 2048-bit). Kufanya XOR ya ciphertext mbili chini ya keystream iliyotumiwa tena hutenga `p ⊕ p'` / `q ⊕ q'`, ambazo zinaweza kurecoveriwa kwa brute force ndani ya sekunde.<sup>[[1]](#references)</sup>
- Default IVs katika libraries (kwa mfano, constant `000...01`) ni critical footgun: kila encryption hurudia keystream ileile, na kugeuza CTR kuwa one-time pad iliyotumiwa tena.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR hutoa confidentiality pekee: kubadilisha bits katika ciphertext hubadilisha deterministically bits zilezile katika plaintext. Bila authentication tag, attackers wanaweza kutamper data (kwa mfano, kubadilisha keys, flags, au messages) bila kugunduliwa.
- Tumia AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, n.k.) na enforce tag verification ili kugundua bit-flips.

### GCM

GCM pia huvunjika vibaya nonce inapotumiwa tena. Ikiwa key+nonce ileile inatumiwa zaidi ya mara moja, kwa kawaida utapata:

- Keystream reuse kwa encryption (kama CTR), inayowezesha plaintext recovery wakati plaintext yoyote inajulikana.
- Kupotea kwa guarantees za integrity. Kulingana na kinachowekwa wazi (message/tag pairs nyingi chini ya nonce ileile), attackers wanaweza kuwa na uwezo wa kuforge tags.

Mwongozo wa uendeshaji:

- Chukulia "nonce reuse" katika AEAD kuwa vulnerability muhimu.
- Misuse-resistant AEADs (kwa mfano, GCM-SIV) hupunguza madhara ya nonce-misuse lakini bado zinahitaji nonces/IVs za kipekee.
- Ikiwa una ciphertexts nyingi chini ya nonce ileile, anza kwa kuangalia mahusiano ya aina ya `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef kwa majaribio ya haraka: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` kwa scripting

## ECB exploitation patterns

ECB (Electronic Code Book) hu-encrypt kila block kivyake:

- plaintext blocks zilizo sawa → ciphertext blocks zilizo sawa
- hii hu-leak structure na kuwezesha attacks za mtindo wa cut-and-paste

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Uki-login mara kadhaa na **kila mara ukapata cookie ileile**, ciphertext huenda ni deterministic (ECB au fixed IV).

Ukitengeneza users wawili wenye plaintext layouts zinazofanana kwa kiasi kikubwa (kwa mfano, characters ndefu zinazojirudia) na ukaona ciphertext blocks zinazorudiwa katika offsets zilezile, ECB ni suspect mkubwa.

### Exploitation patterns

#### Removing entire blocks

Ikiwa token format ni kitu kama `<username>|<password>` na block boundary inalingana, wakati mwingine unaweza kuunda user ili block ya `admin` iwe aligned, kisha uondoe blocks zilizo mbele ili kupata token valid ya `admin`.

#### Moving blocks

Ikiwa backend inavumilia padding/extra spaces (`admin` dhidi ya `admin    `), unaweza:

- Ku-align block yenye `admin   `
- Kubadilisha/kutumia tena ciphertext block hiyo katika token nyingine

## Padding Oracle

### Ni nini

Katika CBC mode, ikiwa server inaonyesha (moja kwa moja au kwa njia isiyo ya moja kwa moja) ikiwa plaintext iliyodecryptiwa ina **valid PKCS#7 padding**, mara nyingi unaweza:

- Ku-decrypt ciphertext bila key
- Ku-encrypt chosen plaintext (ku-forge ciphertext)

Oracle inaweza kuwa:

- Ujumbe maalum wa error
- HTTP status / response size tofauti
- Tofauti ya timing

### Practical exploitation

PadBuster ni tool ya classic:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Mfano:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Ukubwa wa block mara nyingi ni `16` kwa AES.
- `-encoding 0` inamaanisha Base64.
- Tumia `-error` ikiwa oracle ni string maalum.

### Kwa nini inafanya kazi

CBC decryption hukokotoa `P[i] = D(C[i]) XOR C[i-1]`. Kwa kurekebisha bytes katika `C[i-1]` na kuchunguza ikiwa padding ni valid, unaweza kurejesha `P[i]` byte kwa byte.

## Bit-flipping katika CBC

Hata bila padding oracle, CBC inaweza kubadilishwa. Ikiwa unaweza kurekebisha ciphertext blocks na application inatumia plaintext iliyodecryptiwa kama structured data (kwa mfano, `role=user`), unaweza kubadilisha bits maalum ili kubadilisha plaintext bytes zilizochaguliwa katika nafasi fulani ya block inayofuata.

Muundo wa kawaida wa CTF:

- Token = `IV || C1 || C2 || ...`
- Unadhibiti bytes katika `C[i]`
- Unalenga plaintext bytes katika `P[i+1]` kwa sababu `P[i+1] = D(C[i+1]) XOR C[i]`

Hii si kuvunja confidentiality yenyewe, lakini ni privilege-escalation primitive ya kawaida wakati integrity haipo.

## CBC-MAC

CBC-MAC ni secure tu chini ya masharti maalum (hasa **fixed-length messages** na domain separation sahihi).

### Classic variable-length forgery pattern

CBC-MAC kwa kawaida hukokotolewa kama:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ikiwa unaweza kupata tags za messages ulizochagua, mara nyingi unaweza kutengeneza tag ya concatenation (au construction inayohusiana) bila kujua key, kwa kutumia jinsi CBC inavyounganisha blocks.

Hii hutokea mara nyingi katika CTF cookies/tokens ambazo hufanya MAC ya username au role kwa kutumia CBC-MAC.

### Safer alternatives

- Tumia HMAC (SHA-256/512)
- Tumia CMAC (AES-CMAC) kwa usahihi
- Jumuisha message length / domain separation

## Stream ciphers: XOR na RC4

### The mental model

Hali nyingi za stream cipher hupunguzwa kuwa:

`ciphertext = plaintext XOR keystream`

Kwa hiyo:

- Ikiwa unajua plaintext, unapata keystream.
- Ikiwa keystream imetumika tena (key+nonce ileile), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ikiwa unajua plaintext segment yoyote katika position `i`, unaweza kupata keystream bytes na ku-decrypt ciphertext nyingine katika positions hizo.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ni stream cipher; encrypt/decrypt ni operation ileile.

Ikiwa unaweza kupata RC4 encryption ya plaintext unayoijua kwa kutumia key ileile, unaweza kupata keystream na ku-decrypt messages nyingine zenye length/offset ileile.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Marejeo

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
