# Phishing における Homograph / Homoglyph Attacks

{{#include ../../banners/hacktricks-training.md}}

## 概要

Homograph（別名 Homoglyph）攻撃は、多くの **非Latin scriptのUnicode code pointがASCII文字と視覚的に同一、または極めて類似している** という事実を悪用します。1つ以上のLatin文字を見た目が似た文字に置き換えることで、攻撃者は次のようなものを作成できます。

* 人間の目には正規に見える一方、keywordベースの検知を回避する表示名、件名、またはメッセージ本文。
* 被害者に信頼できるサイトへアクセスしていると思い込ませるドメイン、サブドメイン、またはURLパス。

各グリフは内部的に **Unicode code point** で識別されるため、1文字を置き換えるだけで、単純な文字列比較（例: `"Παypal.com"` と `"Paypal.com"`）を回避できます。

## 典型的なPhishingワークフロー

1. **メッセージ内容を作成する** – なりすますブランド名 / keyword内の特定のLatin文字を、別のscript（Greek、Cyrillic、Armenian、Cherokeeなど）の視覚的に区別できない文字へ置き換えます。
2. **補助インフラを登録する** – 必要に応じてHomoglyphドメインを登録し、TLS certificateを取得します（ほとんどのCAは視覚的類似性のチェックを行いません）。
3. **email / SMSを送信する** – メッセージには、次のいずれか1つ以上の場所にHomoglyphが含まれます。
* 送信者の表示名（例: `Ηеlрdеѕk`）
* 件名（`Urgеnt Аctіon Rеquіrеd`）
* ハイパーリンクのテキスト、または完全修飾ドメイン名
4. **Redirect chain** – 被害者を、一見無害なWebサイトやURL shortenerを経由させてから、credentialを窃取 / malwareを配布する悪意のあるhostへ誘導します。

## 悪用されることの多いUnicode範囲

| Script | 範囲 | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: 完全なUnicode chartsは[unicode.org](https://home.unicode.org/)で利用できます。<sup>[[2]](#references)</sup>

## 検知技術

### 1. Mixed-Script Inspection

英語圏の組織を狙うPhishing emailでは、複数のscriptの文字が混在することはほとんどありません。単純ですが効果的なheuristicは次のとおりです。

1. 検査対象のstringの各文字を反復処理します。
2. code pointをUnicode blockにマッピングします。
3. 複数のscriptが存在する **または** 期待されていない場所（表示名、ドメイン、件名、URLなど）に非Latin scriptが現れた場合にalertを発生させます。

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
### 2. Punycode Normalisation（Domains）

Internationalised Domain Names（IDNs）は **punycode**（`xn--`）でエンコードされます。すべてのホスト名を punycode に変換してから Unicode に戻すことで、文字列を正規化した**後**に、whitelist との照合や類似性チェック（例：Levenshtein distance）を実行できます。
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Dictionary / Algorithms

**dnstwist**（`--homoglyph`）や **urlcrazy** などのツールは、視覚的に類似したドメインの組み合わせを列挙でき、事前の takedown / monitoring に役立ちます。<sup>[[3]](#references)</sup>

## Prevention & Mitigation

* 厳格な DMARC/DKIM/SPF ポリシーを適用し、未承認ドメインからの spoofing を防止する。
* 上記の検出ロジックを **Secure Email Gateways** および **SIEM/XSOAR** playbooks に実装する。
* display name の domain ≠ sender domain となっているメッセージにフラグを付けるか、quarantine する。
* ユーザーを教育する：不審なテキストを Unicode inspector に copy-paste し、リンクに hover し、URL shorteners を決して信用しない。

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt`（Cyrillic の `С`、`е`、`а`、Cherokee の `Ꭲ`、Latin small capital の `ꮯ`）。
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA で保護された、偽の Microsoft login（`mlcorsftpsswddprotcct.approaches.it.com`）。
* Spotify impersonation: `redirects.ca` の背後にリンクを隠した `Sρօtifս` sender。

これらのサンプルは Unit 42 の research（2025年7月）に由来し、automated analysis を bypass するために、homograph abuse が URL redirection および CAPTCHA evasion とどのように組み合わされるかを示しています。<sup>[[1]](#references)</sup>

## References

- [1] [Homograph の錯覚：すべてが見た目どおりとは限らない](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
