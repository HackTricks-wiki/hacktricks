# Kriptografia ya Ulinganifu

{{#include ../../banners/hacktricks-training.md}}

## Mambo ya kuangalia kwenye CTFs

- **Matumizi mabaya ya mode**: mifumo ya ECB, CBC malleability, matumizi tena ya nonce ya CTR/GCM.
- **Padding oracles**: makosa/muda tofauti kwa padding isiyo sahihi.
- **Mkanganyiko wa MAC**: kutumia CBC-MAC na ujumbe wa urefu unaobadilika, au makosa ya MAC-then-encrypt.
- **XOR kila mahali**: stream ciphers na miundo maalum mara nyingi hutegemea XOR na keystream.

## AES modes na matumizi mabaya

NIST inabainisha modes za usiri za ECB, CBC na CTR katika SP 800-38A, na encryption iliyothibitishwa ya GCM katika SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB huvuja mifumo: vitalu vya plaintext vinavyolingana → vitalu vya ciphertext vinavyolingana. Hilo huwezesha:

- Cut-and-paste / kupanga upya vitalu
- Kufuta vitalu (ikiwa muundo utaendelea kuwa halali)

Ikiwa unaweza kudhibiti plaintext na kuona ciphertext (au cookies), jaribu kutengeneza vitalu vinavyojirudia (kwa mfano, `A` nyingi) na utafute vinavyojirudia.

### CBC: Cipher Block Chaining

- CBC ni **malleable**: kubadilisha bits katika `C[i-1]` hubadilisha bits zinazotabirika katika `P[i]`, huku pia kukiharibu `P[i-1]`. Kubadilisha IV hulenga kitalu cha kwanza cha plaintext bila kuharibu kitalu cha awali cha plaintext.
- Ikiwa mfumo unaonyesha padding halali dhidi ya padding batili, huenda una **padding oracle**.

### CTR

CTR hubadilisha AES kuwa stream cipher: `C = P XOR keystream`.

Ikiwa nonce/IV itatumika tena na key ileile:

- `C1 XOR C2 = P1 XOR P2` (matumizi tena ya keystream ya kawaida)
- Kwa plaintext inayojulikana, unaweza kurejesha keystream na kusimbua mingine.

**Miundo ya unyonyaji wa matumizi tena ya Nonce/IV**

- Rejesha keystream mahali popote ambapo plaintext inajulikana/inaweza kukisiwa:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Tumia bytes za keystream zilizorejeshwa kufungua ciphertext nyingine yoyote iliyotengenezwa kwa key+IV ileile kwenye offsets zilezile.
- Data yenye muundo dhahiri (kwa mfano, vyeti vya ASN.1/X.509, vichwa vya faili, JSON/CBOR) huwa na sehemu kubwa za known-plaintext. Mara nyingi unaweza kufanya XOR ya ciphertext ya cheti na mwili wa cheti unaotabirika ili kupata keystream, kisha kufungua secrets nyingine zilizosimbwa kwa kutumia IV ileile. Tazama pia [TLS & Certificates](../tls-and-certificates/README.md) kwa miundo ya kawaida ya vyeti.<sup>[[1]](#references)</sup>
- Secrets nyingi za **muundo/ukubwa uleule wa serialized** zikisimbwa kwa key+IV ileile, upangaji wa fields huvuja hata bila known plaintext kamili. Mfano: funguo za PKCS#8 RSA zenye ukubwa sawa wa modulus huweka prime factors kwenye offsets zinazolingana (takriban 99.6% ya mpangilio hulingana kwa biti 2048). Kufanya XOR ya ciphertext mbili zilizotumia keystream ileile hutenga `p ⊕ p'` / `q ⊕ q'`, ambazo zinaweza kurejeshwa kwa brute force ndani ya sekunde.<sup>[[1]](#references)</sup>
- IV za chaguo-msingi kwenye libraries (kwa mfano, `000...01` isiyobadilika) ni footgun muhimu: kila usimbaji hurudia keystream ileile, na kugeuza CTR kuwa one-time pad inayotumiwa tena.<sup>[[1]](#references)</sup>

**Ubadilikaji wa CTR**

- CTR hutoa usiri pekee: kubadilisha bits kwenye ciphertext hubadilisha bits zilezile kwenye plaintext kwa namna inayotabirika. Bila authentication tag, washambuliaji wanaweza kuchezea data (kwa mfano, kurekebisha funguo, flags au ujumbe) bila kugunduliwa.
- Tumia AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, n.k.) na uhakikishe tag inathibitishwa ili kugundua mabadiliko ya bits.

### GCM

GCM pia huharibika vibaya nonce ikitumiwa tena. Ikiwa key+nonce ileile itatumika zaidi ya mara moja, kwa kawaida utapata:

- Keystream kutumiwa tena kwa usimbaji (kama CTR), hivyo kuwezesha kurejesha plaintext wakati plaintext yoyote inajulikana.
- Kupotea kwa dhamana za integrity. Kulingana na data inayofichuliwa (jozi nyingi za message/tag zenye nonce ileile), washambuliaji wanaweza kuwa na uwezo wa kughushi tags.

Mwongozo wa kiutendaji:

- Chukulia "nonce reuse" kwenye AEAD kama udhaifu muhimu.
- AEAD zinazostahimili matumizi mabaya, kama AES-GCM-SIV, hupunguza madhara ya nonce kutumiwa tena. Wanaoiita wanapaswa bado kutoa nonces za kipekee kama inavyotakiwa na kiolesura cha construction; matumizi ya bahati mbaya ya nonce ileile yana madhara yenye kikomo ikilinganishwa na GCM ya kawaida.<sup>[[3]](#references)[[4]](#references)</sup>
- Ikiwa una ciphertext nyingi zenye nonce ileile, anza kwa kuangalia uhusiano wa aina ya `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) kwa majaribio ya haraka.<sup>[[8]](#references)</sup>
- Kifurushi cha Python cha [PyCryptodome](https://www.pycryptodome.org/) kwa scripting.<sup>[[9]](#references)</sup>

## Miundo ya unyonyaji wa ECB

ECB (Electronic Code Book) husimba kila block kivyake:

- blocks za plaintext zilizo sawa → ciphertext zilizo sawa
- hii huvuja muundo na kuwezesha mashambulizi ya mtindo wa kukata-na-kuunganisha

![Mchoro wa block wa ufunguaji wa ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Wazo la kugundua: muundo wa token/cookie

Ukiingia mara kadhaa na **kupata cookie ileile kila wakati**, ciphertext inaweza kuwa deterministic (ECB au IV isiyobadilika).

Ukiunda watumiaji wawili wenye mpangilio wa plaintext unaofanana kwa sehemu kubwa (kwa mfano, herufi zinazojirudia kwa muda mrefu) na ukaona blocks za ciphertext zinazojirudia kwenye offsets zilezile, ECB ni mshukiwa mkuu.

### Miundo ya unyonyaji

#### Kuondoa blocks nzima

Ikiwa muundo wa token ni kitu kama `<username>|<password>` na mpaka wa block umejipanga sawasawa, wakati mwingine unaweza kuunda mtumiaji ili block ya `admin` ijipange sawasawa, kisha uondoe blocks zilizotangulia ili kupata token halali ya `admin`.

#### Kuhamisha blocks

Ikiwa backend inaruhusu padding/nafasi za ziada (`admin` dhidi ya `admin    `), unaweza:

- Kupanga block iliyo na `admin   `
- Kubadilisha/ kutumia tena block hiyo ya ciphertext kwenye token nyingine

## Padding Oracle

### Ni nini

Katika hali ya CBC, ikiwa server itafichua (moja kwa moja au kwa njia isiyo ya moja kwa moja) iwapo plaintext iliyofunguliwa ina **PKCS#7 padding halali**, mara nyingi unaweza:<sup>[[7]](#references)</sup>

- Kufungua ciphertext bila key
- Kutengeneza ciphertext inayofunguka kuwa plaintext uliyochagua, ikiwa unaweza kuwasilisha blocks zilizotangulia au IV zilizotengenezwa kwa makusudi na programu ikakubali ujumbe wenye padding halali

Oracle inaweza kuwa:

- Ujumbe maalum wa hitilafu
- Hali tofauti ya HTTP / ukubwa tofauti wa jibu
- Tofauti ya muda

### Unyonyaji wa vitendo

PadBuster ndiyo tool ya kawaida:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Mfano:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

Maelezo:

- Ukubwa wa block mara nyingi ni `16` kwa AES.
- `-encoding 0` inamaanisha Base64.
- Tumia `-error` ikiwa oracle inatumia string maalum.

### Kwa nini inafanya kazi

CBC decryption hukokotoa `P[i] = D(C[i]) XOR C[i-1]`. Kwa kubadilisha bytes katika `C[i-1]` na kuangalia kama padding ni halali, unaweza kurejesha `P[i]` byte kwa byte.

## Kubadilisha bits katika CBC

Hata bila padding oracle, CBC inaweza kubadilishwa. Ukiweza kubadilisha ciphertext blocks na programu ikatumia plaintext iliyodecryptiwa kama data yenye muundo (k.m., `role=user`), unaweza kubadilisha bits mahususi ili kubadili bytes zilizochaguliwa za plaintext katika nafasi maalum ya block inayofuata.

Muundo wa kawaida wa CTF:

- Token = `IV || C1 || C2 || ...`
- Unadhibiti bytes katika `C[i]`
- Unalenga bytes za plaintext katika `P[i+1]` kwa sababu `P[i+1] = D(C[i+1]) XOR C[i]`

Huu si uvunjaji wa usiri wenyewe, lakini ni mbinu ya kawaida ya kupandisha marupurupu pale integrity inapokosekana.

## CBC-MAC

CBC-MAC ni salama tu chini ya masharti maalum (hasa **ujumbe wenye urefu usiobadilika** na domain separation sahihi). AES-CMAC ni construction sanifu inayoshughulikia kwa usalama inputs zenye urefu unaobadilika.<sup>[[5]](#references)</sup>

### Muundo wa kawaida wa kughushi ujumbe wenye urefu unaobadilika

CBC-MAC kwa kawaida hukokotolewa hivi:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ukiweza kupata tags za ujumbe uliochagua, mara nyingi unaweza kutengeneza tag ya ujumbe uliounganishwa (au construction inayohusiana) bila kujua key, kwa kutumia jinsi CBC inavyounganisha blocks.

Hili hutokea mara nyingi katika cookies/tokens za CTF zinazotumia CBC-MAC kutengeneza MAC ya username au role.

### Njia mbadala zilizo salama zaidi

- Tumia HMAC (SHA-256/512)
- Tumia CMAC (AES-CMAC) kwa usahihi
- Jumuisha urefu wa ujumbe / domain separation

## Stream ciphers: XOR na RC4

### Muundo wa kufikiria

Hali nyingi za stream cipher hupunguzwa kuwa:

`ciphertext = plaintext XOR keystream`

Kwa hiyo:

- Ukijua plaintext, unaweza kurejesha keystream.
- Keystream ikitumika tena (key+nonce ileile), `C1 XOR C2 = P1 XOR P2`.

### Usimbaji fiche unaotumia XOR

Ukiijua sehemu yoyote ya plaintext katika nafasi `i`, unaweza kurejesha bytes za keystream na kudecode ciphertexts nyingine katika nafasi hizo.

Zana za utatuzi otomatiki:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ni stream cipher ya zamani; encrypt/decrypt ni operesheni ileile ya XOR. Upendeleo wake unaojulikana unaifanya isifae kwa mifumo mipya, na TLS inakataza waziwazi cipher suites zake.<sup>[[6]](#references)</sup>

Ukiweza kupata usimbaji fiche wa RC4 wa plaintext inayojulikana ukitumia key ileile, unaweza kurejesha keystream na kudecode ujumbe mwingine wenye urefu/offset sawa.

Andiko la marejeleo (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Uzembe dhidi ya ufundi makini katika cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Mapendekezo ya mbinu za uendeshaji za block cipher](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Mapendekezo ya Galois/Counter Mode (GCM) na GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Usimbaji Fiche Uliohakikiwa Unaostahimili Matumizi Mabaya ya Nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Algoriti ya AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Kuzuia RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Kupima Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Nyaraka za PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
