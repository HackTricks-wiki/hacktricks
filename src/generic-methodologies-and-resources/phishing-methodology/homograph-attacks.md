# ホモグラフ / ホモグリフ攻撃におけるフィッシング

{{#include ../../banners/hacktricks-training.md}}

## 概要

ホモグラフ（別名ホモグリフ）攻撃は、多くの**非ラテン文字スクリプトのUnicodeコードポイントがASCII文字と視覚的に同一または非常に似ている**という事実を悪用します。攻撃者は、1つ以上のラテン文字をそれに似た文字に置き換えることで、次のようなものを作成できます：

* 人間の目には正当なものに見えるが、キーワードベースの検出を回避する表示名、件名、またはメッセージ本文。
* 被害者を信頼できるサイトに訪れていると錯覚させるドメイン、サブドメイン、またはURLパス。

すべてのグリフはその**Unicodeコードポイント**によって内部的に識別されるため、1つの置き換えられた文字だけで単純な文字列比較を打破することができます（例：`"Παypal.com"` vs. `"Paypal.com"`）。

## 一般的なフィッシングワークフロー

1. **メッセージ内容を作成** – 偽装されたブランド/キーワードの特定のラテン文字を、他のスクリプト（ギリシャ語、キリル文字、アルメニア語、チェロキー語など）の視覚的に区別がつかない文字に置き換えます。
2. **サポートインフラを登録** – 必要に応じてホモグリフドメインを登録し、TLS証明書を取得します（ほとんどのCAは視覚的類似性チェックを行いません）。
3. **メール/SMSを送信** – メッセージには、以下のいずれかの場所にホモグリフが含まれています：
* 送信者表示名（例：`Ηеlрdеѕk`）
* 件名行（`Urgеnt Аctіon Rеquіrеd`）
* ハイパーリンクテキストまたは完全修飾ドメイン名
4. **リダイレクトチェーン** – 被害者は、悪意のあるホストに到達する前に、一見無害なウェブサイトやURL短縮サービスを経由します。

## 一般的に悪用されるUnicode範囲

| スクリプト | 範囲 | 例のグリフ | 見た目 |
|--------|-------|---------------|------------|
| ギリシャ語  | U+0370-03FF | `Η` (U+0397) | ラテン `H` |
| ギリシャ語  | U+0370-03FF | `ρ` (U+03C1) | ラテン `p` |
| キリル文字 | U+0400-04FF | `а` (U+0430) | ラテン `a` |
| キリル文字 | U+0400-04FF | `е` (U+0435) | ラテン `e` |
| アルメニア語 | U+0530-058F | `օ` (U+0585) | ラテン `o` |
| チェロキー語 | U+13A0-13FF | `Ꭲ` (U+13A2) | ラテン `T` |

> ヒント：完全なUnicodeチャートは[unicode.org](https://home.unicode.org/)で入手できます。

## 検出技術

### 1. 混合スクリプト検査

英語を話す組織を対象としたフィッシングメールは、複数のスクリプトからの文字を混合することはほとんどありません。シンプルですが効果的なヒューリスティックは次のとおりです：

1. 検査対象の文字列の各文字を反復処理します。
2. コードポイントをそのUnicodeブロックにマッピングします。
3. 1つ以上のスクリプトが存在する場合**または**予期しない場所（表示名、ドメイン、件名、URLなど）に非ラテン文字スクリプトが現れた場合は警告を発します。

Pythonの概念実証：
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
### 2. Punycode 正規化 (ドメイン)

国際化ドメイン名 (IDN) は **punycode** (`xn--`) でエンコードされています。すべてのホスト名を punycode に変換し、その後 Unicode に戻すことで、ホワイトリストに対する照合や類似性チェック (例: レーベンシュタイン距離) を **正規化**された文字列に対して行うことができます。
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. ホモグリフ辞書 / アルゴリズム

**dnstwist** (`--homoglyph`) や **urlcrazy** のようなツールは、視覚的に類似したドメインの順列を列挙でき、積極的な削除 / 監視に役立ちます。

## 予防と緩和

* 厳格な DMARC/DKIM/SPF ポリシーを施行 – 不正なドメインからのなりすましを防止します。
* 上記の検出ロジックを **Secure Email Gateways** と **SIEM/XSOAR** プレイブックに実装します。
* 表示名のドメイン ≠ 送信者のドメイン のメッセージをフラグ付けまたは隔離します。
* ユーザーを教育します: 疑わしいテキストを Unicode インスペクターにコピー＆ペーストし、リンクにカーソルを合わせ、URL 短縮サービスを決して信頼しないようにします。

## 実世界の例

* 表示名: `Сonfidеntiаl Ꭲiꮯkеt` (キリル文字 `С`, `е`, `а`; チェロキー `Ꭲ`; ラテン小文字 `ꮯ`)。
* ドメインチェーン: `bestseoservices.com` ➜ municipal `/templates` ディレクトリ ➜ `kig.skyvaulyt.ru` ➜ カスタム OTP CAPTCHA で保護された偽の Microsoft ログイン `mlcorsftpsswddprotcct.approaches.it.com`。
* Spotify なりすまし: `Sρօtifւ` 送信者が `redirects.ca` の背後に隠されたリンクを持っています。

これらのサンプルは Unit 42 の研究（2025年7月）に由来し、ホモグリフの悪用が URL リダイレクションと CAPTCHA 回避と組み合わされて自動分析を回避する方法を示しています。

## 参考文献

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
