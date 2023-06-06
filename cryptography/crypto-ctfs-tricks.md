# Truques de Crypto CTFs

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bancos de dados de Hashes Online

* _**Pesquise no Google**_
* [http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240](http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com)
* [https://crackstation.net/](https://crackstation.net)
* [https://md5decrypt.net/](https://md5decrypt.net)
* [https://www.onlinehashcrack.com](https://www.onlinehashcrack.com)
* [https://gpuhash.me/](https://gpuhash.me)
* [https://hashes.org/search.php](https://hashes.org/search.php)
* [https://www.cmd5.org/](https://www.cmd5.org)
* [https://hashkiller.co.uk/Cracker/MD5](https://hashkiller.co.uk/Cracker/MD5)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)

## Magic Autosolvers

* [**https://github.com/Ciphey/Ciphey**](https://github.com/Ciphey/Ciphey)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) (Módulo Mágico)
* [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)
* [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking)

## Codificadores

A maioria dos dados codificados pode ser decodificada com esses 2 recursos:

* [https://www.dcode.fr/tools-list](https://www.dcode.fr/tools-list)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### Substituição Autosolvers

* [https://www.boxentriq.com/code-breaking/cryptogram](https://www.boxentriq.com/code-breaking/cryptogram)
* [https://quipqiup.com/](https://quipqiup.com) - Muito bom!

#### Caesar - ROTx Autosolvers

* [https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)

#### Cifra de Atbash

* [http://rumkin.com/tools/cipher/atbash.php](http://rumkin.com/tools/cipher/atbash.php)

### Base Encodings Autosolver

Verifique todas essas bases com: [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)

* **Ascii85**
  * `BQ%]q@psCd@rH0l`
* **Base26** \[_A-Z_]
  * `BQEKGAHRJKHQMVZGKUXNT`
* **Base32** \[_A-Z2-7=_]
  * `NBXWYYLDMFZGCY3PNRQQ====`
* **Zbase32** \[_ybndrfg8ejkmcpqxot1uwisza345h769
```
╫☐↑Λ↻Λ┏Λ↻☐↑Λ
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html) - 404 Morto: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html](http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html) - 404 Não encontrado: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### UUencoder
```
begin 644 webutils_pl
M2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(
M3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/
F3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$$`
`
end
```
* [http://www.webutils.pl/index.php?idx=uu](http://www.webutils.pl/index.php?idx=uu)

### Codificador XX
```
begin 644 webutils_pl
hG2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236
5Hol-G2xAEE++
end
```
* [www.webutils.pl/index.php?idx=xx](https://github.com/carlospolop/hacktricks/tree/bf578e4c5a955b4f6cdbe67eb4a543e16a3f848d/crypto/www.webutils.pl/index.php?idx=xx)

### YEncoder

O YEncoder é um algoritmo de codificação que converte dados binários em ASCII. Ele é usado para codificar e-mails, arquivos e outras informações que precisam ser transmitidas em formato de texto. O YEncoder é semelhante ao Base64, mas usa um conjunto de caracteres diferente para representar os dados. Para decodificar dados codificados com YEncoder, você pode usar uma ferramenta online ou um script Python.
```
=ybegin line=128 size=28 name=webutils_pl
ryvkryvkryvkryvkryvkryvkryvk
=yend size=28 crc32=35834c86
```
* [http://www.webutils.pl/index.php?idx=yenc](http://www.webutils.pl/index.php?idx=yenc)

### BinHex

BinHex é um método de codificação de arquivos binários em ASCII para que possam ser enviados por e-mail. É semelhante ao Uuencode, mas é mais antigo e menos comum.
```
(This file must be converted with BinHex 4.0)
:#hGPBR9dD@acAh"X!$mr2cmr2cmr!!!!!!!8!!!!!-ka5%p-38K26%&)6da"5%p
-38K26%'d9J!!:
```
* [http://www.webutils.pl/index.php?idx=binhex](http://www.webutils.pl/index.php?idx=binhex)

### ASCII85

ASCII85 é um formato de codificação de dados que permite representar dados binários em ASCII. É semelhante ao Base64, mas é mais eficiente em termos de espaço. É comumente usado em PDFs e PostScript.
```
<~85DoF85DoF85DoF85DoF85DoF85DoF~>
```
* [http://www.webutils.pl/index.php?idx=ascii85](http://www.webutils.pl/index.php?idx=ascii85)

### Teclado Dvorak
```
drnajapajrna
```
* [https://www.geocachingtoolbox.com/index.php?lang=en\&page=dvorakKeyboard](https://www.geocachingtoolbox.com/index.php?lang=en\&page=dvorakKeyboard)

### A1Z26

Letras para seu valor numérico
```
8 15 12 1 3 1 18 1 3 15 12 1
```
### Cifra de Afine Codificar

Letra para número `(ax+b)%26` (_a_ e _b_ são as chaves e _x_ é a letra) e o resultado volta para letra.
```
krodfdudfrod
```
### Código SMS

**Multitap** [substitui uma letra](https://www.dcode.fr/word-letter-change) por dígitos repetidos definidos pelo código de tecla correspondente em um teclado de [telefone móvel](https://www.dcode.fr/phone-keypad-cipher) (Este modo é usado ao escrever SMS).\
Por exemplo: 2=A, 22=B, 222=C, 3=D...\
Você pode identificar este código porque verá\*\* vários números repetidos\*\*.

Você pode decodificar este código em: [https://www.dcode.fr/multitap-abc-cipher](https://www.dcode.fr/multitap-abc-cipher)

### Código Bacon

Substitua cada letra por 4 As ou Bs (ou 1s e 0s)
```
00111 01101 01010 00000 00010 00000 10000 00000 00010 01101 01010 00000
AABBB ABBAB ABABA AAAAA AAABA AAAAA BAAAA AAAAA AAABA ABBAB ABABA AAAAA
```
### Runas

![](../.gitbook/assets/runes.jpg)

## Compressão

**Raw Deflate** e **Raw Inflate** (você pode encontrar ambos no Cyberchef) podem comprimir e descomprimir dados sem cabeçalhos.

## Criptografia Fácil

### XOR - Autosolver

* [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### Bifid

Uma palavra-chave é necessária.
```
fgaargaamnlunesuneoa
```
### Vigenere

É necessário uma palavra-chave.
```
wodsyoidrods
```
* [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)
* [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
* [https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)

## Criptografia Forte

### Fernet

2 strings em base64 (token e chave)
```
Token:
gAAAAABWC9P7-9RsxTz_dwxh9-O2VUB7Ih8UCQL1_Zk4suxnkCvb26Ie4i8HSUJ4caHZuiNtjLl3qfmCv_fS3_VpjL7HxCz7_Q==

Key:
-s6eI5hyNh8liH7Gq0urPC-vzPgNnxauKvRO4g03oYI=
```
* [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode)

### Compartilhamento Secreto de Samir

Um segredo é dividido em X partes e para recuperá-lo você precisa de Y partes (_Y <=X_).
```
8019f8fa5879aa3e07858d08308dc1a8b45
80223035713295bddf0b0bd1b10a5340b89
803bc8cf294b3f83d88e86d9818792e80cd
```
[http://christian.gen.co/secrets/](http://christian.gen.co/secrets/)

### Força bruta OpenSSL

* [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
* [https://github.com/carlospolop/easy\_BFopensslCTF](https://github.com/carlospolop/easy\_BFopensslCTF)

## Ferramentas

* [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
* [https://github.com/lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom)
* [https://github.com/nccgroup/featherduster](https://github.com/nccgroup/featherduster)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
