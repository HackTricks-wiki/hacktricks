# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

**Apple Events** は、アプリケーション同士の通信を可能にする Apple の macOS の機能です。これは、プロセス間通信の処理を担う macOS オペレーティングシステムのコンポーネントである **Apple Event Manager** の一部です。このシステムにより、あるアプリケーションから別のアプリケーションへメッセージを送信し、ファイルを開く、データを取得する、コマンドを実行するなど、特定の操作を要求できます。

mina daemon は `/System/Library/CoreServices/appleeventsd` であり、`com.apple.coreservices.appleevents` サービスを登録します。

イベントを受信できるすべてのアプリケーションは、Apple Event Mach Port をこの daemon に提供して登録します。そして、あるアプリがそのアプリケーションへイベントを送信したい場合、daemon にこのポートを要求します。

Sandboxed applications がイベントを送信できるようにするには、`allow appleevent-send` や `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` などの privileges が必要です。`com.apple.security.temporary-exception.apple-events` のような entitlements によって、イベント送信へのアクセス権を持つ対象を制限できる場合があり、その場合は `com.apple.private.appleevents` のような entitlements が必要になります。

> [!TIP]
> 送信されたメッセージに関する情報をログに記録するには、環境変数 **`AEDebugSends`** を使用できます。
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
