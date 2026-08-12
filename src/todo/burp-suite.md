# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruderには、以下の組み込みpayload generatorsおよびtransformationsが含まれています:<sup>[[1]](#references)</sup>

- **Simple list:** 設定した文字列のリストをpayloadとして使用します。
- **Runtime file:** 実行時に1行につき1つのpayloadを読み込みます。Burpがファイル全体をメモリに読み込まないため、大規模なリストに便利です。
- **Case modification:** 変更前の値、lowercaseおよびuppercase形式、`Propername`（最初の文字をuppercaseにし、残りをlowercaseにした形式）、または`ProperName`（最初の文字をuppercaseにし、残りの文字は変更しない形式）を生成します。Burpは重複する結果を破棄します。
- **Numbers:** 設定した範囲内で、連続した数値またはランダムな数値を生成します。
- **Brute forcer:** 選択した文字セットと最小/最大長に対するすべての順列を生成します。

## Extensions and companion tools

- **Collabfiltrator**は、コマンドを実行し、その出力をBurp CollaboratorへのDNSクエリ経由でexfiltrateするpayloadsを生成します。<sup>[[2]](#references)</sup>
- **Burp Suite Exporter**は、他のreporting workflowsで使用するためにBurpのfindingsをexportします。<sup>[[3]](#references)</sup>
- **HTTP Script Generator**は、HTTP requestsを複数の言語のscriptsに変換します。<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
