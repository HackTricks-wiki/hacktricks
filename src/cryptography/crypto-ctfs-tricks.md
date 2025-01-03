# Crypto CTFs Tricks

{{#include ../banners/hacktricks-training.md}}

## Online Hashes DBs

- _**구글 검색**_
- [http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240](http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com)
- [https://crackstation.net/](https://crackstation.net)
- [https://md5decrypt.net/](https://md5decrypt.net)
- [https://www.onlinehashcrack.com](https://www.onlinehashcrack.com)
- [https://gpuhash.me/](https://gpuhash.me)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.cmd5.org/](https://www.cmd5.org)
- [https://hashkiller.co.uk/Cracker/MD5](https://hashkiller.co.uk/Cracker/MD5)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)

## Magic Autosolvers

- [**https://github.com/Ciphey/Ciphey**](https://github.com/Ciphey/Ciphey)
- [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) (Magic module)
- [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)
- [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking)

## Encoders

Most of encoded data can be decoded with these 2 ressources:

- [https://www.dcode.fr/tools-list](https://www.dcode.fr/tools-list)
- [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### Substitution Autosolvers

- [https://www.boxentriq.com/code-breaking/cryptogram](https://www.boxentriq.com/code-breaking/cryptogram)
- [https://quipqiup.com/](https://quipqiup.com) - 매우 좋음!

#### Caesar - ROTx Autosolvers

- [https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)

#### Atbash Cipher

- [http://rumkin.com/tools/cipher/atbash.php](http://rumkin.com/tools/cipher/atbash.php)

### Base Encodings Autosolver

Check all these bases with: [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)

- **Ascii85**
- `BQ%]q@psCd@rH0l`
- **Base26** \[_A-Z_]
- `BQEKGAHRJKHQMVZGKUXNT`
- **Base32** \[_A-Z2-7=_]
- `NBXWYYLDMFZGCY3PNRQQ====`
- **Zbase32** \[_ybndrfg8ejkmcpqxot1uwisza345h769_]
- `pbzsaamdcf3gna5xptoo====`
- **Base32 Geohash** \[_0-9b-hjkmnp-z_]
- `e1rqssc3d5t62svgejhh====`
- **Base32 Crockford** \[_0-9A-HJKMNP-TV-Z_]
- `D1QPRRB3C5S62RVFDHGG====`
- **Base32 Extended Hexadecimal** \[_0-9A-V_]
- `D1NMOOB3C5P62ORFDHGG====`
- **Base45** \[_0-9A-Z $%\*+-./:_]
- `59DPVDGPCVKEUPCPVD`
- **Base58 (bitcoin)** \[_1-9A-HJ-NP-Za-km-z_]
- `2yJiRg5BF9gmsU6AC`
- **Base58 (flickr)** \[_1-9a-km-zA-HJ-NP-Z_]
- `2YiHqF5bf9FLSt6ac`
- **Base58 (ripple)** \[_rpshnaf39wBUDNEGHJKLM4PQ-T7V-Z2b-eCg65jkm8oFqi1tuvAxyz_]
- `pyJ5RgnBE9gm17awU`
- **Base62** \[_0-9A-Za-z_]
- `g2AextRZpBKRBzQ9`
- **Base64** \[_A-Za-z0-9+/=_]
- `aG9sYWNhcmFjb2xh`
- **Base67** \[_A-Za-z0-9-_.!\~\_]
- `NI9JKX0cSUdqhr!p`
- **Base85 (Ascii85)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
- `BQ%]q@psCd@rH0l`
- **Base85 (Adobe)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
- `<~BQ%]q@psCd@rH0l~>`
- **Base85 (IPv6 or RFC1924)** \[_0-9A-Za-z!#$%&()\*+-;<=>?@^_\`{|}\~\_]
- `Xm4y`V\_|Y(V{dF>\`
- **Base85 (xbtoa)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
- `xbtoa Begin\nBQ%]q@psCd@rH0l\nxbtoa End N 12 c E 1a S 4e6 R 6991d`
- **Base85 (XML)** \[\_0-9A-Za-y!#$()\*+,-./:;=?@^\`{|}\~z\_\_]
- `Xm4y|V{~Y+V}dF?`
- **Base91** \[_A-Za-z0-9!#$%&()\*+,./:;<=>?@\[]^\_\`{|}\~"_]
- `frDg[*jNN!7&BQM`
- **Base100** \[]
- `👟👦👣👘👚👘👩👘👚👦👣👘`
- **Base122** \[]
- `4F ˂r0Xmvc`
- **ATOM-128** \[_/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC_]
- `MIc3KiXa+Ihz+lrXMIc3KbCC`
- **HAZZ15** \[_HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5_]
- `DmPsv8J7qrlKEoY7`
- **MEGAN35** \[_3G-Ub=c-pW-Z/12+406-9Vaq-zA-F5_]
- `kLD8iwKsigSalLJ5`
- **ZONG22** \[_ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2_]
- `ayRiIo1gpO+uUc7g`
- **ESAB46** \[]
- `3sHcL2NR8WrT7mhR`
- **MEGAN45** \[]
- `kLD8igSXm2KZlwrX`
- **TIGO3FX** \[]
- `7AP9mIzdmltYmIP9mWXX`
- **TRIPO5** \[]
- `UE9vSbnBW6psVzxB`
- **FERON74** \[]
- `PbGkNudxCzaKBm0x`
- **GILA7** \[]
- `D+nkv8C1qIKMErY1`
- **Citrix CTX1** \[]
- `MNGIKCAHMOGLKPAKMMGJKNAINPHKLOBLNNHILCBHNOHLLPBK`

[http://k4.cba.pl/dw/crypo/tools/eng_atom128c.html](http://k4.cba.pl/dw/crypo/tools/eng_atom128c.html) - 404 Dead: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng_hackerize.html)

### HackerizeXS \[_╫Λ↻├☰┏_]
```
╫☐↑Λ↻Λ┏Λ↻☐↑Λ
```
- [http://k4.cba.pl/dw/crypo/tools/eng_hackerize.html](http://k4.cba.pl/dw/crypo/tools/eng_hackerize.html) - 404 데드: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng_hackerize.html)

### 모스
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
- [http://k4.cba.pl/dw/crypo/tools/eng_morse-encode.html](http://k4.cba.pl/dw/crypo/tools/eng_morse-encode.html) - 404 데드: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### UUencoder
```
begin 644 webutils_pl
M2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(
M3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/
F3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$$`
`
end
```
- [http://www.webutils.pl/index.php?idx=uu](http://www.webutils.pl/index.php?idx=uu)

### XXEncoder
```
begin 644 webutils_pl
hG2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236
5Hol-G2xAEE++
end
```
- [www.webutils.pl/index.php?idx=xx](https://github.com/carlospolop/hacktricks/tree/bf578e4c5a955b4f6cdbe67eb4a543e16a3f848d/crypto/www.webutils.pl/index.php?idx=xx)

### YEncoder
```
=ybegin line=128 size=28 name=webutils_pl
ryvkryvkryvkryvkryvkryvkryvk
=yend size=28 crc32=35834c86
```
- [http://www.webutils.pl/index.php?idx=yenc](http://www.webutils.pl/index.php?idx=yenc)

### BinHex
```
(This file must be converted with BinHex 4.0)
:#hGPBR9dD@acAh"X!$mr2cmr2cmr!!!!!!!8!!!!!-ka5%p-38K26%&)6da"5%p
-38K26%'d9J!!:
```
- [http://www.webutils.pl/index.php?idx=binhex](http://www.webutils.pl/index.php?idx=binhex)

### ASCII85
```
<~85DoF85DoF85DoF85DoF85DoF85DoF~>
```
- [http://www.webutils.pl/index.php?idx=ascii85](http://www.webutils.pl/index.php?idx=ascii85)

### 드보락 키보드
```
drnajapajrna
```
- [https://www.geocachingtoolbox.com/index.php?lang=en\&page=dvorakKeyboard](https://www.geocachingtoolbox.com/index.php?lang=en&page=dvorakKeyboard)

### A1Z26

문자를 숫자 값으로 변환
```
8 15 12 1 3 1 18 1 3 15 12 1
```
### Affine Cipher Encode

문자를 숫자로 변환 `(ax+b)%26` (_a_와 _b_는 키이고 _x_는 문자) 그리고 결과를 다시 문자로 변환
```
krodfdudfrod
```
### SMS 코드

**Multitap** [는 문자를 대체합니다](https://www.dcode.fr/word-letter-change) 반복된 숫자로, 이는 모바일 [전화 키패드](https://www.dcode.fr/phone-keypad-cipher)의 해당 키 코드에 의해 정의됩니다 (이 모드는 SMS를 작성할 때 사용됩니다).\
예를 들어: 2=A, 22=B, 222=C, 3=D...\
이 코드는\*\* 여러 숫자가 반복되는 것을 볼 수 있기 때문에 식별할 수 있습니다\*\*.

이 코드는 다음에서 해독할 수 있습니다: [https://www.dcode.fr/multitap-abc-cipher](https://www.dcode.fr/multitap-abc-cipher)

### 베이컨 코드

각 문자를 4개의 A 또는 B (또는 1과 0)로 대체합니다.
```
00111 01101 01010 00000 00010 00000 10000 00000 00010 01101 01010 00000
AABBB ABBAB ABABA AAAAA AAABA AAAAA BAAAA AAAAA AAABA ABBAB ABABA AAAAA
```
### 룬

![](../images/runes.jpg)

## 압축

**Raw Deflate**와 **Raw Inflate**(두 가지 모두 Cyberchef에서 찾을 수 있음)는 헤더 없이 데이터를 압축하고 압축 해제할 수 있습니다.

## 쉬운 암호화

### XOR - 자동 해결기

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### 비피드

키워드가 필요합니다.
```
fgaargaamnlunesuneoa
```
### Vigenere

키워드가 필요합니다.
```
wodsyoidrods
```
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)
- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)

## 강력한 암호

### 페르네트

2개의 base64 문자열 (토큰 및 키)
```
Token:
gAAAAABWC9P7-9RsxTz_dwxh9-O2VUB7Ih8UCQL1_Zk4suxnkCvb26Ie4i8HSUJ4caHZuiNtjLl3qfmCv_fS3_VpjL7HxCz7_Q==

Key:
-s6eI5hyNh8liH7Gq0urPC-vzPgNnxauKvRO4g03oYI=
```
- [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode)

### Samir 비밀 공유

비밀은 X 부분으로 나뉘며, 이를 복구하려면 Y 부분이 필요합니다 (_Y <=X_).
```
8019f8fa5879aa3e07858d08308dc1a8b45
80223035713295bddf0b0bd1b10a5340b89
803bc8cf294b3f83d88e86d9818792e80cd
```
[http://christian.gen.co/secrets/](http://christian.gen.co/secrets/)

### OpenSSL 무차별 대입

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

## 도구

- [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
- [https://github.com/lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [https://github.com/nccgroup/featherduster](https://github.com/nccgroup/featherduster)

{{#include ../banners/hacktricks-training.md}}
