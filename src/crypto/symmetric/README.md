# Kriptografia ya Simetriki

{{#include ../../banners/hacktricks-training.md}}

## Nini cha kutafuta katika CTFs

- **Matumizi mabaya ya mode**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: makosa tofauti / tofauti za muda kwa padding mbaya.
- **MAC confusion**: kutumia CBC-MAC kwa messages zenye variable-length, au makosa ya MAC-then-encrypt.
- **XOR everywhere**: stream ciphers na custom constructions mara nyingi hupunguzwa kuwa XOR na keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Hii inaruhusu:

- Cut-and-paste / block reordering
- Block deletion (ikiwa format bado ni halali)

Ikiwa unaweza kudhibiti plaintext na kuangalia ciphertext (au cookies), jaribu kutengeneza blocks zilizorudiwa (mfano, many `A`s) na tazama repeats.

### CBC: Cipher Block Chaining

- CBC ni **malleable**: flipping bits katika `C[i-1]` hubadilisha bits zinazotarajiwa ndani ya `P[i]`.
- Ikiwa mfumo unaonyesha valid padding dhidi ya invalid padding, unaweza kuwa na **padding oracle**.

### CTR

CTR hugeuza AES kuwa stream cipher: `C = P XOR keystream`.

Ikiwa nonce/IV imetumika tena na key ile ile:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Ukiwa na known plaintext, unaweza kupata keystream na ku-decrypt wengine.

### GCM

GCM pia inavunjika vibaya chini ya nonce reuse. Ikiwa key+nonce ile ile imetumika zaidi ya mara moja, kwa kawaida unapata:

- Keystream reuse kwa encryption (kama CTR), ikiruhusu kupata plaintext pale yoyote plaintext inajulikana.
- Kupoteza dhamana za integrity. Kulingana na kile kinacho wazi (pamoja mbalimbali za message/tag chini ya nonce ile ile), attackers wanaweza kuweza ku-forge tags.

Mwongozo wa uendeshaji:

- Tibu "nonce reuse" katika AEAD kama udhaifu wa hatari.
- Ikiwa una ciphertext nyingi chini ya nonce ile ile, anza kwa kukagua `C1 XOR C2 = P1 XOR P2` mtindo wa uhusiano.

### Tools

- CyberChef kwa majaribio ya haraka: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` kwa scripting

## ECB exploitation patterns

ECB (Electronic Code Book) hu-encrypt kila block kwa uhuru:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Ikiwa unajiunga mara kadhaa na **daima unapata cookie ile ile**, ciphertext inaweza kuwa deterministic (ECB au fixed IV).

Ikiwa unaweka watumiaji wawili wenye layout ya plaintext karibu sawa (mfano, tabia nyingi zilizorudiwa) na kuona repeated ciphertext blocks katika offsets zile zile, ECB ni mshukiwa mkuu.

### Exploitation patterns

#### Removing entire blocks

Ikiwa format ya token ni kitu kama `<username>|<password>` na block boundary inalingana, unaweza wakati mwingine kuunda user ili block ya `admin` ionekane imelingana, kisha kuondoa blocks za mbele kupata token halali kwa `admin`.

#### Moving blocks

Ikiwa backend inavumilia padding/nafasi za ziada (`admin` vs `admin    `), unaweza:

- Aligned block inayoshikilia `admin   `
- Swap/reuse hiyo ciphertext block ndani ya token nyingine

## Padding Oracle

### What it is

In CBC mode, if the server reveals (directly or indirectly) whether decrypted plaintext has **valid PKCS#7 padding**, you can often:

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

The oracle can be:

- A specific error message
- A different HTTP status / response size
- A timing difference

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Mfano:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Vidokezo:

- Ukubwa wa block mara nyingi ni `16` kwa AES.
- `-encoding 0` ina maana Base64.
- Tumia `-error` ikiwa oracle ni string maalum.

### Kwa nini inafanya kazi

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Kwa kubadilisha bytes katika `C[i-1]` na kuangalia whether the padding ni valid, unaweza kupata `P[i]` bayti kwa bayti.

## Bit-flipping in CBC

Hata bila padding oracle, CBC inaweza kubadilishwa. Ikiwa unaweza kubadilisha ciphertext blocks na application inatumia decrypted plaintext kama structured data (e.g., `role=user`), unaweza flip specific bits ili kubadilisha selected plaintext bytes katika nafasi uliyochagua katika block inayofuata.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Unadhibiti bytes katika `C[i]`
- Unalenga plaintext bytes katika `P[i+1]` kwa sababu `P[i+1] = D(C[i+1]) XOR C[i]`

Hii si kuvunjwa kwa confidentiality peke yake, lakini ni primitive ya kawaida ya privilege-escalation wakati integrity haipo.

## CBC-MAC

CBC-MAC ni salama tu chini ya masharti maalum (notably **fixed-length messages** na correct domain separation).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ikiwa unaweza kupata tags kwa messages ulizoamua, mara nyingi unaweza kutengeneza tag kwa concatenation (au konstruksheni inayohusiana) bila kujua key, kwa kutumia jinsi CBC inavyochain blocks.

Hii mara nyingi huonekana katika CTF cookies/tokens ambazo zina-MAC username au role na CBC-MAC.

### Mbadala salama

- Tumia HMAC (SHA-256/512)
- Tumia CMAC (AES-CMAC) kwa usahihi
- Jumuisha message length / domain separation

## Stream ciphers: XOR and RC4

### Mfano wa kifikra

Katika hali nyingi za stream cipher, mambo yanarekebishwa kuwa:

`ciphertext = plaintext XOR keystream`

Kwa hivyo:

- Ikiwa unajua plaintext, unapata keystream.
- Ikiwa keystream inarudiwa (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ikiwa unajua sehemu yoyote ya plaintext katika nafasi `i`, unaweza kupata bytes za keystream na ku-decrypt ciphertext nyingine katika nafasi hizo.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ni stream cipher; encrypt/decrypt ni operesheni ile ile.

Ikiwa unaweza kupata RC4 encryption ya plaintext inayojulikana chini ya key ile ile, unaweza kupata keystream na ku-decrypt messages nyingine zenye urefu/offset sawa.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
