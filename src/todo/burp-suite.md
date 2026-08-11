# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

- **Simple list:** 設定済みの文字列リストを payload として使用します。
- **Runtime file:** 実行時に1行につき1つの payload を読み込みます。Burp はファイル全体をメモリに読み込まないため、大規模なリストに適しています。
- **Case modification:** 入力文字列の大文字・小文字を変更します。小文字、大文字、sentence case、title case などに変更できます。
- **Numbers:** 設定した範囲内で、連続またはランダムな数値を生成します。
- **Brute forcer:** 選択した文字セットと最小・最大長に基づき、すべての組み合わせを生成します。<sup>[[1]](#references)</sup>

## Extensions and companion tools

- **Collabfiltrator** は、コマンドを実行し、その出力を DNS クエリ経由で Burp Collaborator に exfiltrate する payloads を生成します。<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** は、他のレポート作成ワークフローで使用できるように Burp の findings をエクスポートします。<sup>[[3]](#references)</sup>
- **HTTP Script Generator** は、HTTP requests を複数の言語の scripts に変換します。<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
