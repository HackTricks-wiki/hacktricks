# PhishingにおけるHomograph / Homoglyph Attacks

## 概要

Homograph（別名Homoglyph）attackは、**非ラテン文字の多くのUnicode code pointが、ASCII文字と見た目が同一または極めて類似している**という事実を悪用します。1つ以上のラテン文字を、見た目が似た文字に置き換えることで、攻撃者は次のようなものを作成できます。

* 人間の目には正規に見える一方、keywordベースの検知を回避する表示名、件名、またはメッセージ本文。
* 被害者に信頼できるサイトを訪問していると思わせるドメイン、サブドメイン、またはURL path。<sup>[[1]](#references)</sup>

すべてのglyphは内部的に**Unicode code point**によって識別されるため、1文字を置き換えるだけで、単純な文字列比較（例: `"Παypal.com"` と `"Paypal.com"`）を回避できます。<sup>[[1]](#references)[[3]](#references)</sup>

## 典型的なPhishing Workflow

1. **メッセージ内容を作成** – なりすますブランド / keyword内の特定のラテン文字を、別のscript（Greek、Cyrillic、Armenian、Cherokeeなど）の、見分けがつかない文字に置き換えます。
2. **関連するinfrastructureを登録** – 必要に応じてhomoglyph domainを登録し、TLS certificateを取得します（ほとんどのCAは視覚的な類似性チェックを行いません）。
3. **email / SMSを送信** – メッセージには、次のいずれか1つ以上の場所にhomoglyphsが含まれます。
* Sender display name（例: `Ηеlрdеѕk`）
* Subject line（`Urgеnt Аctіon Rеquіrеd`）
* Hyperlink textまたはfully qualified domain name
4. **Redirect chain** – 被害者を、一見無害なwebサイトやURL shortenerを経由させた後、credentialsを窃取したりmalwareを配布したりするmalicious hostへ誘導します。<sup>[[1]](#references)</sup>

## よく悪用されるUnicode Ranges

以下は、scriptをまたいだlook-alikeの作成に一般的に使われる文字を含むUnicode blockの例です。<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Unicode code chartを使用して、blockとcode pointを確認します。

## Detection Techniques

### 1. Mixed-Script Inspection

English-speaking organisationを対象とするPhishing emailで、複数のscriptの文字が混在することはほとんどありません。シンプルですが効果的なheuristicは、次のとおりです。

1. 検査対象のstringの各characterを順番に処理します。
2. code pointをそのscript nameまたはUnicode blockにマッピングします。
3. 複数のscriptが存在する**場合、または**想定されていない場所（display name、domain、subject、URLなど）にnon-Latin scriptが現れた場合にalertを発生させます。<sup>[[3]](#references)</sup>

Python proof-of-concept:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Punycode の正規化（ドメイン）

国際化ドメイン名（IDN）には、Unicode形式と、`xn--` を先頭に付けたASCII互換の **Punycode** 形式があります。allow-listing や比較を行う前に、ホスト名をIDNA/Punycode形式に変換し、表示にはUnicode形式を使用します。<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph 辞書 / アルゴリズム

**dnstwist**（`--fuzzers homoglyph`）や **urlcrazy** などの Tools は、視覚的に類似したドメインの組み合わせを列挙でき、プロアクティブな takedown / monitoring に役立ちます。<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* 厳格な DMARC/DKIM/SPF ポリシーを適用する – unauthorised なドメインからの spoofing を防止します。
* 上記の detection logic を **Secure Email Gateways** および **SIEM/XSOAR** playbooks に実装します。
* display name domain ≠ sender domain となっているメッセージにフラグを付けるか、quarantine します。
* ユーザーを教育する：疑わしいテキストを Unicode inspector に copy-paste し、リンクに hover し、URL shorteners を決して信用しないようにします。

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt`（Cyrillic の `С`、`е`、`а`；Cherokee の `Ꭲ`；Latin small capital の `ꮯ`）。
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA で保護された、`mlcorsftpsswddprotcct.approaches.it.com` の fake Microsoft login。
* Spotify impersonation: `redirects.ca` の背後にリンクを隠した `Sρօtifս` sender。

これらのサンプルは Unit 42 の research（2025 年 7 月）に由来し、homograph abuse が URL redirection および CAPTCHA evasion と組み合わされ、自動分析を bypass する方法を示しています。<sup>[[1]](#references)</sup>

## References

- [1] [Homograph の錯覚：すべてが見た目どおりとは限らない](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode 文字コードチャート](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39：Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [4] [dnstwist – ドメイン組み合わせエンジン](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – ドメインの typo および variation generator](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890：Internationalized Domain Names for Applications (IDNA)：Definitions and Document Framework](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
