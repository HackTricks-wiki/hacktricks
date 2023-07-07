# Crypto CTFsのトリック

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## オンラインハッシュDB

* _**Googleで検索**_
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

## マジックオートソルバー

* [**https://github.com/Ciphey/Ciphey**](https://github.com/Ciphey/Ciphey)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) (マジックモジュール)
* [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)
* [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking)

## エンコーダ

ほとんどのエンコードされたデータは、次の2つのリソースでデコードできます：

* [https://www.dcode.fr/tools-list](https://www.dcode.fr/tools-list)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### 代替オートソルバー

* [https://www.boxentriq.com/code-breaking/cryptogram](https://www.boxentriq.com/code-breaking/cryptogram)
* [https://quipqiup.com/](https://quipqiup.com) - 非常に優れています！

#### シーザー - ROTxオートソルバー

* [https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)

#### アトバッシュ暗号

* [http://rumkin.com/tools/cipher/atbash.php](http://rumkin.com/tools/cipher/atbash.php)

### ベースエンコーディングオートソルバー

これらのベースはすべて、[https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)でチェックできます。

* **Ascii85**
* `BQ%]q@psCd@rH0l`
* **Base26** \[_A-Z_]
* `BQEKGAHRJKHQMVZGKUXNT`
* **Base32** \[_A-Z2-7=_]
* `NBXWYYLDMFZGCY3PNRQQ====`
* **Zbase32** \[_ybndrfg8ejkmcpqxot1uwisza345h769_]
* `pbzsaamdcf3gna5xptoo====`
* **Base32 Geohash** \[_0-9b-hjkmnp-z_]
* `e1rqssc3d5t62svgejhh====`
* **Base32 Crockford** \[_0-9A-HJKMNP-TV-Z_]
* `D1QPRRB3C5S62RVFDHGG====`
* **Base32 Extended Hexadecimal** \[_0-9A-V_]
* `D1NMOOB3C5P62ORFDHGG====`
* **Base45** \[_0-9A-Z $%\*+-./:_]
* `59DPVDGPCVKEUPCPVD`
* **Base58 (bitcoin)** \[_1-9A-HJ-NP-Za-km-z_]
* `2yJiRg5BF9gmsU6AC`
* **Base58 (flickr)** \[_1-9a-km-zA-HJ-NP-Z_]
* `2YiHqF5bf9FLSt6ac`
* **Base58 (ripple)** \[_rpshnaf39wBUDNEGHJKLM4PQ-T7V-Z2b-eCg65jkm8oFqi1tuvAxyz_]
* `pyJ5RgnBE9gm17awU`
* **Base62** \[_0-9A-Za-z_]
* `g2AextRZpBKRBzQ9`
* **Base64** \[_A-Za-z0-9+/=_]
* `aG9sYWNhcmFjb2xh`
* **Base67** \[_A-Za-z0-9-_.!\~\_]
* `NI9JKX0cSUdqhr!p`
* **Base85 (Ascii85)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `BQ%]q@psCd@rH0l`
* **Base85 (Adobe)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `<~BQ%]q@psCd@rH0l~>`
* **Base85 (IPv6 or RFC1924)** \[_0-9A-Za-z!#$%&()\*+-;<=>?@^_\`{|}\~\_]
* `Xm4y`V\_|Y(V{dF>\`
* **Base85 (xbtoa)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `xbtoa Begin\nBQ%]q@psCd@rH0l\nxbtoa End N 12 c E 1a S 4e6 R 6991d`
* **Base85 (XML)** \[_0-9A-Za-y!#$()\*+,-./:;=?@^\`{|}\~z\__]
* `Xm4y|V{~Y+V}dF?`
* **Base91** \[_A-Za-z0-9!#$%&()\*+,./:;<=>?@\[]^\_\`{|}\~"_]
* `frDg[*jNN!7&BQM`
* **Base100** \[]
* `👟👦👣👘👚👘👩👘👚👦👣👘`
* **Base122** \[]
* `4F ˂r0Xmvc`
* **ATOM-128** \[_/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC_]
* `MIc3KiXa+Ihz+lrXMIc3KbCC`
* **HAZZ15** \[_HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5_]
* `DmPsv8J7qrlKEoY7`
* **MEGAN35** \[_3G-Ub=c-pW-Z/12+406-9Vaq-zA-F5_]
* `kLD8iwKsigSalLJ5`
* **ZONG22** \[_ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2_]
* `ayRiIo1gpO+uUc7g`
* **ESAB46** \[]
* `3sHcL2NR8WrT7mhR`
* **MEGAN45** \[]
* `kLD8igSXm2KZlwrX`
* **TIGO3FX** \[]
* `7AP9mIzdmltYmIP9mWXX`
* **TRIPO5** \[]
* `UE9vSbnBW6psVzxB`
* **FERON74** \[]
* `PbGkNudxCzaKBm0x`
* **GILA7** \[]
* `D+nkv8C1qIKMErY1`
* **Citrix CTX1** \[]
* `MNGIKCAHMOGLKPAKMMGJKNAINPHKLOBLNNHILCBHNOHLLPBK`

[http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html](http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html) - 404 Dead: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### HackerizeXS \[_╫Λ↻├☰┏_]

* **Base85 (IPv6またはRFC1924)** \[_0-9A-Za-z!#$%&()\*+-;<=>?@^_\`{|}\~\_]
* `Xm4y`V\_|Y(V{dF>\`
* **Base85 (xbtoa)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `xbtoa Begin\nBQ%]q@psCd@rH0l\nxbtoa End N 12 c E 1a S 4e6 R 6991d`
* **Base85 (XML)** \[_0-9A-Za-y!#$()\*+,-./:;=?@^\`{|}\~z\__]
* `Xm4y|V{~Y+V}dF?`
* **Base91** \[_A-Za-z0-9!#$%&()\*+,./:;<=>?@\[]^\_\`{|}\~"_]
* `frDg[*jNN!7&BQM`
* **Base100** \[]
* `👟👦👣👘👚👘👩👘👚👦👣👘`
* **Base122** \[]
* `4F ˂r0Xmvc`
* **ATOM-128** \[_/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC_]
* `MIc3KiXa+Ihz+lrXMIc3KbCC`
* **HAZZ15** \[_HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5_]
* `DmPsv8J7qrlKEoY7`
* **MEGAN35** \[_3G-Ub=c-pW-Z/12+406-9Vaq-zA-F5_]
* `kLD8iwKsigSalLJ5`
* **ZONG22** \[_ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2_]
* `ayRiIo1gpO+uUc7g`
* **ESAB46** \[]
* `3sHcL2NR8WrT7mhR`
* **MEGAN45** \[]
* `kLD8igSXm2KZlwrX`
* **TIGO3FX** \[]
* `7AP9mIzdmltYmIP9mWXX`
* **TRIPO5** \[]
* `UE9vSbnBW6psVzxB`
* **FERON74** \[]
* `PbGkNudxCzaKBm0x`
* **GILA7** \[]
* `D+nkv8C1qIKMErY1`
* **Citrix CTX1** \[]
* `MNGIKCAHMOGLKPAKMMGJKNAINPHKLOBLNNHILCBHNOHLLPBK`

[http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html](http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html) - 404 Dead: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### HackerizeXS \[_╫Λ↻├☰┏_]
```
╫☐↑Λ↻Λ┏Λ↻☐↑Λ
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html) - 404 Not Found: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### モールス符号
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html](http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html) - 404 Not Found: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### UUエンコーダー
```
begin 644 webutils_pl
M2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(
M3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/
F3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$$`
`
end
```
* [http://www.webutils.pl/index.php?idx=uu](http://www.webutils.pl/index.php?idx=uu)

### XXエンコーダー
```
begin 644 webutils_pl
hG2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236
5Hol-G2xAEE++
end
```
* [www.webutils.pl/index.php?idx=xx](https://github.com/carlospolop/hacktricks/tree/bf578e4c5a955b4f6cdbe67eb4a543e16a3f848d/crypto/www.webutils.pl/index.php?idx=xx)

### Yエンコーダー
```
=ybegin line=128 size=28 name=webutils_pl
ryvkryvkryvkryvkryvkryvkryvk
=yend size=28 crc32=35834c86
```
* [http://www.webutils.pl/index.php?idx=yenc](http://www.webutils.pl/index.php?idx=yenc)

### BinHex
```
(This file must be converted with BinHex 4.0)
:#hGPBR9dD@acAh"X!$mr2cmr2cmr!!!!!!!8!!!!!-ka5%p-38K26%&)6da"5%p
-38K26%'d9J!!:
```
* [http://www.webutils.pl/index.php?idx=binhex](http://www.webutils.pl/index.php?idx=binhex)

### ASCII85

ASCII85は、バイナリデータをテキスト形式に変換するためのエンコーディングスキームです。このスキームは、バイナリデータをテキスト形式で表現することで、データの転送や保存を容易にします。ASCII85は、AdobeがPostScriptファイルで使用するために開発したもので、データの圧縮や暗号化にも使用されます。

ASCII85エンコーディングは、5バイトのバイナリデータを4文字のテキストに変換します。変換されたテキストは、ASCII文字の範囲内で表現され、可読性が高いです。デコードする際には、テキストを元のバイナリデータに戻すことができます。

ASCII85は、CTF（Capture The Flag）や暗号解読のコンテストでよく使用される暗号化スキームです。データの変換や解読には、オンラインツールやPythonのライブラリを使用することができます。
```
<~85DoF85DoF85DoF85DoF85DoF85DoF~>
```
* [http://www.webutils.pl/index.php?idx=ascii85](http://www.webutils.pl/index.php?idx=ascii85)

### Dvorakキーボード
```
drnajapajrna
```
* [https://www.geocachingtoolbox.com/index.php?lang=ja\&page=dvorakKeyboard](https://www.geocachingtoolbox.com/index.php?lang=ja\&page=dvorakKeyboard)

### A1Z26

文字を数値に変換します。
```
8 15 12 1 3 1 18 1 3 15 12 1
```
### アフィン暗号のエンコード

文字を数値に変換する `(ax+b)%26` (_a_ と _b_ は鍵であり、_x_ は文字) し、結果を再び文字に変換します。
```
krodfdudfrod
```
### SMSコード

**マルチタップ**は、モバイル[電話のキーパッド](https://www.dcode.fr/phone-keypad-cipher)上の対応するキーコードによって定義された繰り返し数字によって、[文字を置き換えます](https://www.dcode.fr/word-letter-change)（このモードはSMSを書くときに使用されます）。
例えば：2=A、22=B、222=C、3=D...
このコードは、**複数の数字が繰り返されている**ことで識別できます。

このコードは、[https://www.dcode.fr/multitap-abc-cipher](https://www.dcode.fr/multitap-abc-cipher)でデコードすることができます。

### ベーコンコード

各文字を4つのAまたはB（または1と0）に置き換えます。
```
00111 01101 01010 00000 00010 00000 10000 00000 00010 01101 01010 00000
AABBB ABBAB ABABA AAAAA AAABA AAAAA BAAAA AAAAA AAABA ABBAB ABABA AAAAA
```
### ルーン

![](../.gitbook/assets/runes.jpg)

## 圧縮

**Raw Deflate**と**Raw Inflate**（どちらもCyberchefで見つけることができます）は、ヘッダーなしでデータを圧縮および展開することができます。

## 簡単な暗号

### XOR - 自動解読

* [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### Bifid

キーワードが必要です
```
fgaargaamnlunesuneoa
```
### ヴィジュネル暗号

キーワードが必要です。
```
wodsyoidrods
```
* [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)
* [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
* [https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)

## 強力な暗号

### Fernet

2つのBase64文字列（トークンとキー）
```
Token:
gAAAAABWC9P7-9RsxTz_dwxh9-O2VUB7Ih8UCQL1_Zk4suxnkCvb26Ie4i8HSUJ4caHZuiNtjLl3qfmCv_fS3_VpjL7HxCz7_Q==

Key:
-s6eI5hyNh8liH7Gq0urPC-vzPgNnxauKvRO4g03oYI=
```
* [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode)

### サミールの秘密共有

秘密はX個の部分に分割され、回復するにはY個の部分が必要です（_Y <=X_）。
```
8019f8fa5879aa3e07858d08308dc1a8b45
80223035713295bddf0b0bd1b10a5340b89
803bc8cf294b3f83d88e86d9818792e80cd
```
### OpenSSLブルートフォース

* [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
* [https://github.com/carlospolop/easy\_BFopensslCTF](https://github.com/carlospolop/easy\_BFopensslCTF)

## ツール

* [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
* [https://github.com/lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom)
* [https://github.com/nccgroup/featherduster](https://github.com/nccgroup/featherduster)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**または**[telegramグループ](https://t.me/peass)**に参加するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
