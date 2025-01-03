# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

**Apple Events** は、アプリケーションが互いに通信することを可能にする、Apple の macOS の機能です。これは、プロセス間通信を処理する macOS オペレーティングシステムのコンポーネントである **Apple Event Manager** の一部です。このシステムにより、あるアプリケーションが別のアプリケーションにメッセージを送信し、ファイルを開く、データを取得する、またはコマンドを実行するなどの特定の操作を実行するよう要求できます。

mina デーモンは `/System/Library/CoreServices/appleeventsd` で、サービス `com.apple.coreservices.appleevents` を登録します。

イベントを受信できるすべてのアプリケーションは、このデーモンに自分の Apple Event Mach Port を提供して確認します。そして、アプリがイベントを送信したい場合、アプリはデーモンからこのポートを要求します。

サンドボックス化されたアプリケーションは、イベントを送信できるようにするために `allow appleevent-send` や `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` のような権限が必要です。`com.apple.security.temporary-exception.apple-events` のような権限は、イベントを送信するアクセスを制限する可能性があり、`com.apple.private.appleevents` のような権限が必要になります。

> [!TIP]
> 送信されたメッセージに関する情報をログに記録するために、env 変数 **`AEDebugSends`** を使用することが可能です：
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
