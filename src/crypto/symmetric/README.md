# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Nini cha kutafuta katika CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: makosa tofauti / utofauti wa muda wa majibu kwa bad padding.
- **MAC confusion**: kutumia CBC-MAC na ujumbe wenye urefu tofauti, au makosa ya MAC-then-encrypt.
- **XOR everywhere**: stream ciphers na custom constructions mara nyingi hupungua kuwa XOR na keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Hii inaruhusu:

- Cut-and-paste / block reordering
- Block deletion (ikiwa format inabaki kuwa valid)

Kama unaweza kudhibiti plaintext na kuona ciphertext (au cookies), jaribu kutengeneza repeated blocks (mfano, many `A`s) na angalia repeats.

### CBC: Cipher Block Chaining

- CBC ni **malleable**: flipping bits katika `C[i-1]` hupiga bits zinazoweza kutabiriwa katika `P[i]`.
- Ikiwa mfumo unaonyesha valid padding dhidi ya invalid padding, unaweza kuwa na **padding oracle**.

### CTR

CTR inaweka AES kuwa stream cipher: `C = P XOR keystream`.

Kama nonce/IV inatumiwa tena kwa key ileile:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Kwa known plaintext, unaweza kurecover keystream na ku-decrypt nyingine.

**Nonce/IV reuse exploitation patterns**

- Recover keystream ambapo plaintext inajulikana/inatabirika:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Tumia keystream uliopatikana ku-decrypt ciphertext nyingine yoyote iliyotengenezwa na key+IV ileile kwa offsets ileile.
- Data yenye muundo thabiti (mfano, ASN.1/X.509 certificates, file headers, JSON/CBOR) inatoa maeneo makubwa ya known-plaintext. Mara nyingi unaweza XOR ciphertext ya certificate na sehemu inayotarajiwa ya certificate kupata keystream, kisha u-decrypt siri nyingine zilizofunikwa chini ya IV iliyotumika tena. Angalia pia [TLS & Certificates](../tls-and-certificates/README.md) kwa layouts za kawaida za certificate.
- Wakati siri nyingi za same serialized format/size zinafunikwa chini ya key+IV ileile, alignment ya fields huitoka hata bila known plaintext kamili. Mfano: PKCS#8 RSA keys za size ya modulus ileile zinaweka factors za primes kwenye offsets zinazolingana (~99.6% alignment kwa 2048-bit). XOR ya ciphertext mbili chini ya reused keystream inatoa `p ⊕ p'` / `q ⊕ q'`, ambazo zinaweza ku-recover kwa brute force kwa sekunde.
- Default IVs katika libraries (mfano, constant `000...01`) ni hatari muhimu: kila encryption inarudia keystream ileile, ikigeuza CTR kuwa reused one-time pad.

**CTR malleability**

- CTR inatoa confidentiality tu: flipping bits katika ciphertext kwa deterministic huweka flip za bits sawa katika plaintext. Bila authentication tag, attackers wanaweza tamper data (mfano, tweak keys, flags, au messages) bila kugunduliwa.
- Tumia AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) na linde verification ya tag ili kugundua bit-flips.

### GCM

GCM pia huharibika vibaya chini ya nonce reuse. Ikiwa key+nonce ileile inatumiwa zaidi ya mara moja, kawaida unapata:

- Keystream reuse kwa encryption (kama CTR), kuruhusu recovery ya plaintext pale plaintext yoyote inapoonekana.
- Kupoteza guarantees za integrity. Kulingana na kinachochapuka (multiple message/tag pairs chini ya nonce ileile), attackers wanaweza kufaulu ku-forge tags.

Mwongozo wa uendeshaji:

- Tendea "nonce reuse" katika AEAD kama vulnerability muhimu.
- Misuse-resistant AEADs (mfano, GCM-SIV) hupunguza fallout ya nonce-misuse lakini bado zinahitaji nonces/IVs za kipekee.
- Kama una ciphertext nyingi chini ya nonce ileile, anza kwa kuangalia relation za `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef kwa majaribio ya haraka: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` kwa scripting

## ECB exploitation patterns

ECB (Electronic Code Book) ina-encrypt kila block kwa njia huru:

- equal plaintext blocks → equal ciphertext blocks
- hii inaonyesha structure na inaruhusu cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Kama una-login mara kadhaa na **daima unapata cookie ileile**, ciphertext inaweza kuwa deterministic (ECB au fixed IV).

Kama unatumia two users wenye layout ya plaintext karibu sawa (mfano, long repeated characters) na unaona repeated ciphertext blocks kwa offsets sawa, ECB ni mshukiwa mkuu.

### Exploitation patterns

#### Removing entire blocks

Kama format ya token iko kama `<username>|<password>` na block boundary inalingana, unaweza mara nyingine kuunda user ili block yenye `admin` ionekane imepangwa, kisha uondoe blocks zilizotangulia kupata token halali ya `admin`.

#### Moving blocks

Kama backend inakubali padding/extra spaces (`admin` vs `admin    `), unaweza:

- Panga block yenye `admin   `
- Badilisha/tumiza ciphertext block hiyo katika token nyingine

## Padding Oracle

### What it is

Katika CBC mode, kama server inaonyesha (moja kwa moja au kwa njia isiyo ya moja kwa moja) kama decrypted plaintext ina **valid PKCS#7 padding**, mara nyingi unaweza:

- Decrypt ciphertext bila key
- Encrypt chosen plaintext (forge ciphertext)

Oracle inaweza kuwa:

- Ujumbe maalum wa error
- HTTP status tofauti / response size tofauti
- Tofauti ya timing

### Practical exploitation

PadBuster ni tool classic:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Vidokezo:

- Ukubwa wa block mara nyingi ni `16` kwa AES.
- `-encoding 0` inamaanisha Base64.
- Tumia `-error` ikiwa oracle ni string maalum.

### Kwa nini inafanya kazi

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Kwa kurekebisha baiti katika `C[i-1]` na kuangalia kama padding ni halali, unaweza kurejesha `P[i]` baiti kwa baiti.

## Bit-flipping in CBC

Hata bila padding oracle, CBC inaweza kubadilishwa. Ikiwa unaweza kubadilisha ciphertext blocks na application inatumia plaintext iliyofumbuliwa kama data iliyopangwa (mfano, `role=user`), unaweza kubadili biti maalumu kubadilisha baiti maalum za plaintext katika nafasi uliyochagua katika block inayofuata.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Unadhibiti baiti katika `C[i]`
- Unalenga baiti za plaintext katika `P[i+1]` kwa sababu `P[i+1] = D(C[i+1]) XOR C[i]`

Hii sio kuvunjwa kwa usiri yenyewe, lakini ni primitive ya kawaida ya privilege-escalation wakati uadilifu (integrity) unapokosekana.

## CBC-MAC

CBC-MAC ni salama tu chini ya masharti maalum (notably **fixed-length messages** and correct domain separation).

### Classic variable-length forgery pattern

CBC-MAC kawaida huhesabiwa kama:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ikiwa unaweza kupata tags kwa ujumbe uliyochagua, mara nyingi unaweza kutengeneza tag kwa concatenation (au muundo unaohusiana) bila kujua key, kwa kutumia jinsi CBC inavyounganisha blocks.

Hii mara nyingi inaonekana katika CTF cookies/tokens ambazo MAC username au role kwa CBC-MAC.

### Safer alternatives

- Tumia HMAC (SHA-256/512)
- Tumia CMAC (AES-CMAC) kwa usahihi
- Jumuisha urefu wa ujumbe / domain separation

## Stream ciphers: XOR and RC4

### Mfano wa kifikiri

Mazingira mengi ya stream cipher yanarejea kwa:

`ciphertext = plaintext XOR keystream`

Hivyo:

- Ikiwa unajua plaintext, unapata keystream.
- Ikiwa keystream imetumika tena (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ikiwa unajua sehemu yoyote ya plaintext katika nafasi `i`, unaweza kupata baiti za keystream na kufumbua ciphertext nyingine katika nafasi hizo.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ni stream cipher; encrypt/decrypt ni operesheni moja hiyo.

Ikiwa unaweza kupata RC4 encryption ya plaintext inayojulikana kwa key ile ile, unaweza kupata keystream na kufumbua ujumbe mwingine wenye urefu/offset sawa.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
