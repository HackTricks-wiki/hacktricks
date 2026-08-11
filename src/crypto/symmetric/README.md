# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Mambo ya kutafuta katika CTFs

- **Matumizi mabaya ya mode**: mifumo ya ECB, CBC malleability, kutumia tena nonce ya CTR/GCM.
- **Padding oracles**: errors/timings tofauti kwa padding mbaya.
- **Mkanganyiko wa MAC**: kutumia CBC-MAC na messages zenye urefu unaobadilika, au makosa ya MAC-then-encrypt.
- **XOR kila mahali**: stream ciphers na custom constructions mara nyingi huishia kwenye XOR na keystream.

## AES modes na matumizi mabaya

NIST inabainisha ECB, CBC, na CTR confidentiality modes katika SP 800-38A na GCM authenticated encryption katika SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB hufanya patterns zivuje: plaintext blocks zilizo sawa → ciphertext blocks zilizo sawa. Hilo huwezesha:

- Cut-and-paste / kupanga upya blocks
- Kufuta block (ikiwa format bado ni valid)

Ikiwa unaweza kudhibiti plaintext na kuona ciphertext (au cookies), jaribu kutengeneza blocks zinazorudiwa (kwa mfano, `A` nyingi) na utafute marudio.

### CBC: Cipher Block Chaining

- CBC ni **malleable**: kubadilisha bits katika `C[i-1]` hubadilisha bits zinazotabirika katika `P[i]`, huku pia ikiharibu `P[i-1]`. Kubadilisha IV hulenga plaintext block ya kwanza bila kuharibu plaintext block ya awali.
- Ikiwa system inaonyesha padding valid dhidi ya padding invalid, huenda una **padding oracle**.

### CTR

CTR hubadilisha AES kuwa stream cipher: `C = P XOR keystream`.

Ikiwa nonce/IV itatumika tena pamoja na key ileile:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Ukiwa na known plaintext, unaweza kurecover keystream na ku-decrypt nyingine.

**Nonce/IV reuse exploitation patterns**

- Recover keystream popote plaintext inajulikana/inaweza kukisiwa:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Tumia recovered keystream bytes ku-decrypt ciphertext nyingine yoyote iliyotengenezwa kwa key+IV ileile katika offsets zilezile.
- Data yenye structure kubwa (kwa mfano, ASN.1/X.509 certificates, file headers, JSON/CBOR) hutoa maeneo makubwa ya known-plaintext. Mara nyingi unaweza kufanya XOR ya ciphertext ya certificate na certificate body inayotabirika ili kupata keystream, kisha ku-decrypt secrets nyingine zilizokuwa encrypted kwa IV iliyotumika tena. Tazama pia [TLS & Certificates](../tls-and-certificates/README.md) kwa certificate layouts za kawaida.<sup>[[1]](#references)</sup>
- Secrets nyingi zenye **serialized format/size ileile** ziki-encryptiwa kwa key+IV ileile, field alignment huvujisha taarifa hata bila known plaintext kamili. Mfano: PKCS#8 RSA keys zenye modulus size ileile huweka prime factors katika offsets zinazolingana (~99.6% alignment kwa 2048-bit). Kufanya XOR ya ciphertext mbili chini ya reused keystream hutenga `p ⊕ p'` / `q ⊕ q'`, ambazo zinaweza kurecoveriwa kwa brute force ndani ya sekunde.<sup>[[1]](#references)</sup>
- IVs za default katika libraries (kwa mfano, constant `000...01`) ni critical footgun: kila encryption hurudia keystream ileile, na kugeuza CTR kuwa one-time pad iliyotumika tena.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR hutoa confidentiality pekee: kubadilisha bits katika ciphertext hubadilisha deterministically bits zilezile katika plaintext. Bila authentication tag, attackers wanaweza ku-tamper data (kwa mfano, kubadilisha keys, flags, au messages) bila kugunduliwa.
- Tumia AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, n.k.) na enforce tag verification ili kugundua bit-flips.

### GCM

GCM pia huvunjika vibaya nonce inapotumika tena. Ikiwa key+nonce ileile itatumika zaidi ya mara moja, kwa kawaida utapata:

- Keystream reuse kwa encryption (kama CTR), kuwezesha plaintext recovery wakati plaintext yoyote inajulikana.
- Kupotea kwa integrity guarantees. Kulingana na kinachoonekana (message/tag pairs nyingi chini ya nonce ileile), attackers wanaweza kuwa na uwezo wa ku-forge tags.

Mwongozo wa kiutendaji:

- Chukulia "nonce reuse" katika AEAD kuwa critical vulnerability.
- Misuse-resistant AEADs kama AES-GCM-SIV hupunguza madhara ya nonce-reuse. Callers bado wanapaswa kutoa nonces za kipekee kama inavyohitajika na interface ya construction; reuse ya bahati mbaya huwa na madhara yaliyodhibitiwa ikilinganishwa na GCM ya kawaida.<sup>[[3]](#references)[[4]](#references)</sup>
- Ikiwa una ciphertexts nyingi zenye nonce ileile, anza kwa kuangalia relations za aina ya `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) kwa experiments za haraka.<sup>[[8]](#references)</sup>
- Package ya Python ya [PyCryptodome](https://www.pycryptodome.org/) kwa scripting.<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB (Electronic Code Book) hu-encrypt kila block kwa kujitegemea:

- plaintext blocks zilizo sawa → ciphertext blocks zilizo sawa
- hii huvujisha structure na kuwezesha attacks za aina ya cut-and-paste

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Uki-login mara kadhaa na **kila mara ukapata cookie ileile**, ciphertext inaweza kuwa deterministic (ECB au fixed IV).

Ukitengeneza users wawili wenye plaintext layouts zinazofanana kwa kiasi kikubwa (kwa mfano, characters nyingi zinazorudiwa) na ukaona ciphertext blocks zinazorudiwa katika offsets zilezile, ECB ndiye mshukiwa mkuu.

### Exploitation patterns

#### Removing entire blocks

Ikiwa token format ni kitu kama `<username>|<password>` na block boundary ime-align, wakati mwingine unaweza kuunda user ili `admin` block ionekane ikiwa ime-align, kisha uondoe blocks zinazotangulia ili kupata token valid ya `admin`.

#### Moving blocks

Ikiwa backend inakubali padding/spaces za ziada (`admin` dhidi ya `admin    `), unaweza:

- Ku-align block iliyo na `admin   `
- Kubadilisha/kutumia tena ciphertext block hiyo katika token nyingine

## Padding Oracle

### What it is

Katika CBC mode, ikiwa server itaonyesha (moja kwa moja au kwa njia isiyo ya moja kwa moja) kama decrypted plaintext ina **valid PKCS#7 padding**, mara nyingi unaweza:<sup>[[7]](#references)</sup>

- Ku-decrypt ciphertext bila key
- Kutengeneza ciphertext inayodecrypt kuwa chosen plaintext unapoweza ku-submit crafted preceding blocks au IVs na application ikakubali message inayotokana yenye valid padding

Oracle inaweza kuwa:

- Specific error message
- HTTP status / response size tofauti
- Timing difference

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
Vidokezo:

- Block size mara nyingi ni `16` kwa AES.
- `-encoding 0` inamaanisha Base64.
- Tumia `-error` ikiwa oracle ni string maalum.

### Kwa nini inafanya kazi

CBC decryption hukokotoa `P[i] = D(C[i]) XOR C[i-1]`. Kwa kubadilisha bytes katika `C[i-1]` na kuangalia ikiwa padding ni valid, unaweza kurejesha `P[i]` byte baada ya byte.

## Bit-flipping in CBC

Hata bila padding oracle, CBC inaweza kubadilishwa. Ikiwa unaweza kubadilisha ciphertext blocks na application inatumia plaintext iliyodecryptiwa kama structured data (kwa mfano, `role=user`), unaweza kubadilisha bits maalum ili kubadilisha plaintext bytes zilizochaguliwa katika position maalum ya block inayofuata.

Muundo wa kawaida wa CTF:

- Token = `IV || C1 || C2 || ...`
- Unadhibiti bytes katika `C[i]`
- Unalenga plaintext bytes katika `P[i+1]` kwa sababu `P[i+1] = D(C[i+1]) XOR C[i]`

Hii si break ya confidentiality yenyewe, lakini ni privilege-escalation primitive ya kawaida wakati integrity haipo.

## CBC-MAC

CBC-MAC ni secure tu chini ya masharti maalum (hasa **fixed-length messages** na domain separation sahihi). AES-CMAC ni construction iliyosanifiwa inayoshughulikia kwa usalama variable-length inputs.<sup>[[5]](#references)</sup>

### Muundo wa kawaida wa variable-length forgery

CBC-MAC kwa kawaida huhesabiwa hivi:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ikiwa unaweza kupata tags za messages ulizochagua, mara nyingi unaweza kutengeneza tag ya concatenation (au construction inayohusiana) bila kujua key, kwa kutumia jinsi CBC inavyounganisha blocks.

Hii hujitokeza mara kwa mara katika CTF cookies/tokens zinazotumia CBC-MAC kufanya MAC ya username au role.

### Njia mbadala salama zaidi

- Tumia HMAC (SHA-256/512)
- Tumia CMAC (AES-CMAC) kwa usahihi
- Jumuisha message length / domain separation

## Stream ciphers: XOR and RC4

### Muundo wa kiakili

Hali nyingi za stream cipher hupunguzwa kuwa:

`ciphertext = plaintext XOR keystream`

Kwa hiyo:

- Ikiwa unajua plaintext, unapata keystream.
- Ikiwa keystream inatumiwa tena (key+nonce ileile), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ikiwa unajua plaintext segment yoyote katika position `i`, unaweza kupata keystream bytes na kudecrypt ciphertext nyingine katika positions hizo.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ni legacy stream cipher; encrypt/decrypt ni XOR operation ileile. Biases zake zinazojulikana zinaifanya isifae kwa systems mpya, na TLS inakataza wazi cipher suites zake.<sup>[[6]](#references)</sup>

Ikiwa unaweza kupata RC4 encryption ya plaintext inayojulikana chini ya key ileile, unaweza kupata keystream na kudecrypt messages nyingine zenye length/offset ileile.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Uzembe dhidi ya ustadi katika cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Pendekezo la Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Pendekezo la Galois/Counter Mode (GCM) na GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Authenticated Encryption Inayostahimili Matumizi Mabaya ya Nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Algorithm ya AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Kukataza RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Testing for Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome documentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
