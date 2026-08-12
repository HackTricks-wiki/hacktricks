# macOS シリアル番号

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

すべての Mac に解読可能な 12 文字のシリアル番号があるとは限りません。Apple の旧形式では製造情報と構成情報がエンコードされていましたが、Apple は 2021 年に新製品でランダム化されたシリアル番号の導入を開始しました。ランダム化された形式からは、製造情報や構成情報を確認できません。<sup>[[1]](#references)</sup>

### 旧式の 12 文字形式

2010 年からランダム化への移行までに製造された多くのデバイスでは、12 文字形式から現在でも有用なインベントリ情報を得られます。<sup>[[3]](#references)</sup>

- 1～3 文字目は製造場所を識別します。
- 4～5 文字目は製造された年の前半または後半と週をエンコードします。
- 6～8 文字目は、同じ場所と時期に製造されたユニットを区別します。
- 9～12 文字目はモデルまたは構成コードを識別します。

たとえば、`C02L13ECF8J2` はこの旧式の構造に従っています。コミュニティが管理する工場の対応表では、米国の拠点として `FC`、`F`、`XA`、`XB`、`QP`、`G8` などのプレフィックス、メキシコとして `RN`、Cork として `CK`、チェコ共和国の Foxconn 拠点として `VM`、Singapore として `SG` または `E`、Malaysia として `MB`、Korea として `PT` または `CY`、Taiwan として `EE`、`QT`、`UV` などが挙げられています。`FK`、`F1`、`F2`、`W8`、`DL`、`DM`、`DN`、`YM`、`7J`、`1C`、`4H`、`WQ`、`F7`、`C0`、`C3`、`C7` など多数のプレフィックスは中国の施設に関連付けられており、`RM` は整備済みデバイスに関連付けられています。<sup>[[3]](#references)</sup>

4 文字目の日付コードは、`C`（2010 年前半）から `Z`（2019 年後半）まで続き、その後は同じシーケンスが再利用されます。5 文字目では、数字 `1`～`9` が第 1～9 週を表し、母音と `S` を除く `C`～`Y` の文字が第 10～27 週を表します。4 文字目がその年の後半を示す場合は、26 を加算します。<sup>[[3]](#references)</sup>

これらの対応表は旧式デバイスの triage には役立ちますが、出所、製造時期、真正性を証明する決定的な情報ではありません。Apple のインベントリデータを通じて結果を確認してください。

確実に識別するには、デバイスからシリアル番号を取得し、文字位置からモデルを推測するのではなく、Apple の coverage または technical-specification lookup を使用してください。<sup>[[2]](#references)</sup>

### シリアル番号の取得

グラフィカルインターフェースでは、**Apple menu > About This Mac** の下に表示されます。<sup>[[2]](#references)</sup> shell からは、次のいずれかのコマンドで platform のシリアル番号を読み取れます。
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
シリアル番号は認証情報ではなく識別子として扱い、登録または所有権に関する判断を行う前に、該当する Apple または MDM のインベントリワークフローを通じてデバイスを確認してください。

## References

- [1] [MacRumors - Apple がランダム化されたシリアル番号への移行を開始](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Mac のモデル名とシリアル番号を確認する](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Apple のシリアル番号に隠された意味を解読する](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
