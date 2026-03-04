# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Nini cha kutafuta katika CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: makosa/nyakati tofauti kwa bad padding.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR kila mahali**: stream ciphers na custom constructions mara nyingi hupungua kuwa XOR na keystream.

## AES modes na matumizi mabaya

### ECB: Electronic Codebook

ECB leak patterns: equal plaintext blocks → equal ciphertext blocks. Hii inaruhusu:

- Cut-and-paste / block reordering
- Uondoaji wa block (ikiwa format bado halali)

Ikiwa unaweza kudhibiti plaintext na kuangalia ciphertext (au cookies), jaribu kutengeneza repeated blocks (mfano, `A` nyingi) na angalia repeats.

### CBC: Cipher Block Chaining

- CBC ni **malleable**: flipping bits in `C[i-1]` kunasababisha flips za predictable bits katika `P[i]`.
- Ikiwa mfumo unaonyesha valid padding dhidi ya invalid padding, unaweza kuwa na **padding oracle**.

### CTR

CTR hubadilisha AES kuwa stream cipher: `C = P XOR keystream`.

Ikiwa nonce/IV imetumika tena kwa key ile ile:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Kwa known plaintext, unaweza kurecover keystream na decrypt ciphertext nyingine.

**Nonce/IV reuse exploitation patterns**

- Recover keystream wherever plaintext is known/guessable:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Apply recovered keystream bytes ili ku-decrypt ciphertext nyingine yoyote iliyotengenezwa na key+IV ile ile kwenye offsets sawa.
- Data iliyo na muundo imara (mfano, ASN.1/X.509 certificates, file headers, JSON/CBOR) hutoa maeneo makubwa ya known-plaintext. Mara nyingi unaweza XOR ciphertext ya certificate na predictable certificate body kupata keystream, kisha u-decrypt siri nyingine zilizo-encrypt kwa reused IV. Angalia pia [TLS & Certificates](../tls-and-certificates/README.md) kwa muundo wa kawaida wa certificate.
- Wakati siri nyingi za same serialized format/size zina-encrypt under same key+IV, alignment ya field inaonyesha hata bila full known plaintext. Mfano: PKCS#8 RSA keys za modulus size ile ile zinaweka prime factors kwenye offsets zinazolingana (~99.6% alignment kwa 2048-bit). XOR ya two ciphertexts chini ya reused keystream inatenganisha `p ⊕ p'` / `q ⊕ q'`, ambayo inaweza kufuatiliwa kwa brute force kwa sekunde.
- Default IVs katika libraries (mfano, constant `000...01`) ni hatari kubwa: kila encryption inarudia keystream ile ile, ikibadilisha CTR kuwa reused one-time pad.

**CTR malleability**

- CTR inatoa confidentiality tu: flipping bits katika ciphertext kunabadilisha kwa deterministic bits sawa katika plaintext. Bila authentication tag, attackers wanaweza kutamper data (mfano, tweak keys, flags, au messages) bila kugunduliwa.
- Tumia AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, n.k.) na tinye verification ya tag ili kugundua bit-flips.

### GCM

GCM pia huvunjika vibaya chini ya nonce reuse. Ikiwa key+nonce inatumiwa zaidi ya mara moja, kawaida unapata:

- Keystream reuse kwa encryption (kama CTR), ikiruhusu plaintext recovery pale ambapo plaintext yoyote inajulikana.
- Kupoteza guarantees za integrity. Kutegemea ni nini kinachoongezwa (multiple message/tag pairs under same nonce), attackers wanaweza kufanikiwa kuforge tags.

Mwongozo wa uendeshaji:

- Tazama "nonce reuse" katika AEAD kama vulnerability muhimu.
- Misuse-resistant AEADs (mfano, GCM-SIV) hupunguza fallout ya nonce-misuse lakini bado zinahitaji nonces/IVs za kipekee.
- Ikiwa una ciphertexts nyingi chini ya nonce ile ile, anza kwa kukagua uhusiano wa `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef kwa majaribio ya haraka: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` kwa scripting

## ECB exploitation patterns

ECB (Electronic Code Book) encrypts kila block kwa kujitegemea:

- equal plaintext blocks → equal ciphertext blocks
- hii inafanya structure ionekane na kuruhusu cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Wazo la kugundua: token/cookie pattern

Ikiwa una-login mara kadhaa na **kila mara ukapata cookie ile ile**, ciphertext inaweza kuwa deterministic (ECB au fixed IV).

Ikiwa unaunda users wawili wenye layouts za plaintext karibu sawa (mfano, characters zilizorudiwa kwa muda mrefu) na unaona ciphertext blocks zilizorudiwa kwenye offsets sawa, ECB ni mshukiwa mkuu.

### Exploitation patterns

#### Removing entire blocks

Ikiwa token format ni kama `<username>|<password>` na block boundary inalingana, unaweza wakati mwingine kutengeneza user ili block yenye `admin` ionekane imepangiliwa, kisha uondoe blocks zilizo mbele kupata token halali kwa `admin`.

#### Moving blocks

Ikiwa backend inakubali padding/extra spaces (`admin` vs `admin    `), unaweza:

- Pangilia block inayojumuisha `admin   `
- Swap/reuse ciphertext block hiyo ndani ya token nyingine

## Padding Oracle

### Nini ni

Katika CBC mode, ikiwa server inaonyesha (mara moja au kwa njia isiyo ya moja kwa moja) kama decrypted plaintext ina **valid PKCS#7 padding**, mara nyingi unaweza:

- Decrypt ciphertext bila key
- Encrypt chosen plaintext (forge ciphertext)

Oracle inaweza kuwa:

- Ujumbe wa error maalum
- HTTP status / response size tofauti
- Tofauti ya timing

### Exploitation ya vitendo

PadBuster ni tool ya classic:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Vidokezo:

- Block size is often `16` for AES.
- `-encoding 0` inamaanisha Base64.
- Tumia `-error` ikiwa the oracle ni string maalum.

### Why it works

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Kwa kubadili bytes katika `C[i-1]` na kutazama kama padding ni halali, unaweza kupata `P[i]` kibao-kibao.

## Bit-flipping in CBC

Hata bila padding oracle, CBC ni inayoweza kubadilika. Ikiwa unaweza kubadilisha ciphertext blocks na application inatumia decrypted plaintext kama data iliyopangwa (mfano, `role=user`), unaweza kubadili bits maalum ili kubadilisha bytes za plaintext zilizochaguliwa katika nafasi iliyoteuliwa katika block inayofuata.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

Hii si kuvunja usiri yenyewe, lakini ni primitive ya kawaida ya privilege-escalation wakati integrity haipo.

## CBC-MAC

CBC-MAC ni salama tu chini ya masharti maalum (hasa ujumbe wa urefu thabiti na domain separation sahihi).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

Hii mara nyingi huonekana katika CTF cookies/tokens zinazotumia CBC-MAC ku-MAC username au role.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Jumuisha message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

Hivyo:

- Ikiwa unajua plaintext, unapata keystream.
- Ikiwa keystream imetumika tena (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ikiwa unajua sehemu yoyote ya plaintext katika nafasi `i`, unaweza kupata bytes za keystream na ku-decrypt ciphertext nyingine katika nafasi hizo.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ni stream cipher; encrypt/decrypt ni operesheni ile ile.

Ikiwa unaweza kupata RC4 encryption ya plaintext inayojulikana chini ya key ile ile, unaweza kupata keystream na ku-decrypt ujumbe mwingine wenye urefu/offset sawa.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
