{{#include ../../banners/hacktricks-training.md}}

# ベースライン

ベースラインは、システムの特定の部分のスナップショットを取得し、**将来の状態と比較して変更を強調表示する**ことから成ります。

例えば、ファイルシステムの各ファイルのハッシュを計算して保存することで、どのファイルが変更されたかを特定できます。\
これは、作成されたユーザーアカウント、実行中のプロセス、実行中のサービス、およびあまり変更されるべきでないその他のものにも適用できます。

## ファイル整合性監視

ファイル整合性監視 (FIM) は、ファイルの変更を追跡することによってIT環境とデータを保護する重要なセキュリティ技術です。これには2つの主要なステップが含まれます：

1. **ベースライン比較：** 将来の比較のためにファイル属性または暗号学的チェックサム（MD5やSHA-2など）を使用してベースラインを確立し、変更を検出します。
2. **リアルタイム変更通知：** ファイルがアクセスまたは変更されたときに即座にアラートを受け取ります。通常、OSカーネル拡張を通じて行われます。

## ツール

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## 参考文献

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
