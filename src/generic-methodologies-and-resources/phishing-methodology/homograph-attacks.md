# Phishing における Homograph / Homoglyph Attacks

{{#include ../../banners/hacktricks-training.md}}

## 概要

Homograph（別名 homoglyph）attack は、**非ラテン文字の多くの Unicode code point が ASCII 文字と視覚的に同一、または非常によく似ている**という事実を悪用します。1 つ以上のラテン文字を、見た目が似た別の文字に置き換えることで、攻撃者は次のようなものを作成できます。

* 人間の目には正規のものに見える一方で、keyword-based detection を回避する Display name、件名、メッセージ本文。
* 被害者に信頼できるサイトへアクセスしていると思わせる Domain、sub-domain、URL path。<sup>[[1]](#references)</sup>

各 glyph は内部的に **Unicode code point** によって識別されるため、1 文字を置き換えるだけで、単純な文字列比較（例：`"Παypal.com"` と `"Paypal.com"`）を回避できます。<sup>[[1]](#references)[[3]](#references)</sup>

## Typical Phishing Workflow

1. **メッセージ内容を作成する** – なりすますブランド / keyword 内の特定のラテン文字を、別の script（Greek、Cyrillic、Armenian、Cherokee など）の視覚的に区別できない文字に置き換えます。
2. **Supporting infrastructure を登録する** – 必要に応じて homoglyph domain を登録し、TLS certificate を取得します（ほとんどの CA は視覚的な類似性をチェックしません）。
3. **Email / SMS を送信する** – メッセージ内の次のいずれか 1 つ以上の場所に homoglyph を含めます。
* Sender display name（例：`Ηеlрdеѕk`）
* Subject line（`Urgеnt Аctіon Rеquіrеd`）
* Hyperlink text または fully qualified domain name
4. **Redirect chain** – 被害者を、一見無害な website や URL shortener を経由させ、credentials を収集したり malware を配布したりする malicious host に誘導します。<sup>[[1]](#references)</sup>

## Unicode Ranges Commonly Abused

以下は、script をまたいだ look-alike の作成に一般的に使用される文字を含む Unicode block の例です。<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Unicode code chart を使用して block と code point を確認してください。

## Detection Techniques

### 1. Mixed-Script Inspection

英語圏の組織を標的とする Phishing email で、複数の script の文字が混在することはほとんどありません。シンプルですが効果的な heuristic は次のとおりです。

1. 検査対象の string の各 character を順番に処理します。
2. code point を script name または Unicode block にマッピングします。
3. 複数の script が存在する **または** 想定されていない場所（display name、domain、subject、URL など）に non-Latin script が現れた場合に alert を発生させます。<sup>[[3]](#references)</sup>

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
### 2. Punycode Normalisation（ドメイン）

国際化ドメイン名（IDN）には、Unicode形式と、`xn--`を接頭辞とするASCII互換の**Punycode**形式があります。許可リストへの登録や比較を行う前に、ホスト名をIDNA/Punycode形式へ変換し、表示用にはUnicode形式を保持します。<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph辞書 / アルゴリズム

**dnstwist**（`--fuzzers homoglyph`）や **urlcrazy** などのツールは、見た目が類似したドメインの候補を列挙でき、先回りした削除依頼 / 監視に役立ちます。<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* 厳格なDMARC/DKIM/SPFポリシーを適用する – 未認証ドメインからのspoofingを防止します。
* 上記の検出ロジックを **Secure Email Gateways** および **SIEM/XSOAR** のplaybookに実装します。
* display nameのドメインと送信者ドメインが一致しないメッセージにフラグを付けるか、隔離します。
* ユーザーを教育する: 疑わしいテキストをUnicode inspectorにコピー＆ペーストし、リンクにカーソルを合わせ、URL shortenerを決して信用しないようにします。

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt`（Cyrillicの`С`、`е`、`а`、Cherokeeの`Ꭲ`、Latin small capitalの`ꮯ`）。
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHAで保護された、`mlcorsftpsswddprotcct.approaches.it.com` の偽Microsoft login。
* Spotify impersonation: `redirects.ca` の背後に隠されたリンクを持つ `Sρօtifս` sender。

これらのサンプルはUnit 42のresearch（2025年7月）に由来し、homograph abuseがURL redirectionおよびCAPTCHA evasionと組み合わせられ、自動分析を回避する方法を示しています。<sup>[[1]](#references)</sup>

## References

- [1] [Homographの錯覚: すべてが見た目どおりとは限らない](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode文字コードチャート](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [4] [dnstwist – ドメイン順列エンジン](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – ドメインのtypoおよびバリエーション生成ツール](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): 定義および文書フレームワーク](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
