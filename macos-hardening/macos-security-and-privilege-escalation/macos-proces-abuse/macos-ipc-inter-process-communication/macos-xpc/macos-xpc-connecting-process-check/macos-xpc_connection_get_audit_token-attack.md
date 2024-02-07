# macOS xpc\_connection\_get\_audit\_token 攻撃

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェック！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)を入手
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする。

</details>

**詳細は元の投稿をご確認ください: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**。これは要約です:


## Machメッセージの基本情報

Machメッセージが何かわからない場合は、このページをチェックしてください:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

今のところ、([ここからの定義](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing))：\
Machメッセージは_machポート_を介して送信され、これは**単一の受信者、複数の送信者通信**チャネルで、machカーネルに組み込まれています。**複数のプロセスが**machポートにメッセージを送信できますが、いつでも**単一のプロセスだけがそれを読むことができます**。ファイルディスクリプタやソケットと同様に、machポートはカーネルによって割り当てられ管理され、プロセスは整数しか見ず、それを使用してカーネルに自分のmachポートのどれを使用するかを示すことができます。

## XPC接続

XPC接続がどのように確立されるかわからない場合は、次をチェックしてください:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 脆弱性の要約

あなたが知っておくべき興味深い点は、**XPCの抽象化は1対1の接続**であるが、**複数の送信者を持つ技術**に基づいていることです:

* Machポートは単一の受信者、**複数の送信者**です。
* XPC接続の監査トークンは、**最後に受信したメッセージからコピーされた監査トークン**です。
* XPC接続の監査トークンを取得することは、多くの**セキュリティチェック**にとって重要です。

前述の状況は有望に聞こえますが、問題を引き起こさないシナリオもあります ([ここから](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* 監査トークンは、接続を受け入れるかどうかを決定するための認可チェックによく使用されます。これはサービスポートへのメッセージを使用して行われるため、**まだ接続が確立されていません**。このポートへの追加のメッセージは追加の接続要求として処理されます。したがって、**接続を受け入れる前のチェックは脆弱ではありません**（これは、`-listener:shouldAcceptNewConnection:`内での監査トークンが安全であることを意味します）。したがって、**特定のアクションを検証するXPC接続を探しています**。
* XPCイベントハンドラは同期的に処理されます。つまり、1つのメッセージのイベントハンドラが次のメッセージのイベントハンドラを呼び出す前に完了する必要があります。そのため、**XPCイベントハンドラ内では、監査トークンは他の通常の（返信でない！）メッセージによって上書きされることはありません**。

これが悪用される可能性がある2つの異なる方法:

1. Variant1:
* **Exploit** がサービス **A** とサービス **B** に**接続**
* サービス **B** は、ユーザーができない**サービス A の特権機能**を呼び出すことができます
* サービス **A** が **`dispatch_async`** 内で**イベントハンドラ**にいない状態で **`xpc_connection_get_audit_token`** を呼び出します。
* したがって、**異なる**メッセージが**監査トークンを上書き**する可能性があります。なぜなら、イベントハンドラの外部で非同期にディスパッチされているからです。
* 攻撃は、**サービス A に対して SEND 権限をサービス B に渡します**。
* したがって、svc **B** は実際にはサービス **A** に**メッセージを送信**します。
* **Exploit** は**特権アクションを呼び出そうとします**。RC svc **A** はこの**アクション**の認可を**チェック**し、**svc B が監査トークンを上書き**したため（攻撃が特権アクションを呼び出す権限を与えられる）、攻撃がアクションを呼び出す権限を与えられます。
2. Variant 2:
* サービス **B** は、ユーザーができない**サービス A の特権機能**を呼び出すことができます
* Exploit は、**サービス A** に接続し、特定の**リプライポート**で**応答を期待するメッセージを送信**します。
* Exploit は、**サービス B** に**そのリプライポート**を渡すメッセージを送信します。
* サービス **B が応答する**と、**サービス A にメッセージを送信**し、**Exploit** は**サービス A に異なるメッセージを送信**し、特権機能に到達しようとし、サービス B からの返信が監査トークンを完璧なタイミングで上書きすることを期待します（競合状態）。

## Variant 1: イベントハンドラ外で xpc\_connection\_get\_audit\_token を呼び出す <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

シナリオ:

* 両方に接続できる2つのmachサービス **`A`** と **`B`**（サンドボックスプロファイルと接続を受け入れる前の認可チェックに基づく）。
* _**A**_ は、**`B`** が通過できる特定のアクションの**認可チェック**を持っている必要があります（ただし、アプリケーションはできません）。
* たとえば、Bには**エンタイトルメント**があるか**root**として実行されている場合、Aに特権アクションを実行するように依頼できるかもしれません。
* この認可チェックのために、**`A`** は非同期で監査トークンを取得します。たとえば、`dispatch_async` から **`xpc_connection_get_audit_token`** を呼び出すことで。

{% hint style="danger" %}
この場合、攻撃者は**Race Condition**をトリガーし、**`Aにアクションを実行するように依頼するExploit**を作成し、**BがAにメッセージを送信**するようにします。RCが**成功する**と、**Bの監査トークン**が**メモリにコピー**され、**Exploit**のリクエストが**Aによって処理**される間に、特権アクションにのみBがリクエストできる**アクセス**が与えられます。
{% endhint %}

これは、**`A`** が `smd` として、**`B`** が `diagnosticd` として発生しました。 smb の [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 関数は、新しい特権ヘルパーツール（**root**として）をインストールするために使用できます。**root**として実行されているプロセスが **smd** に連絡すると、他のチェックは実行されません。

したがって、サービス **B** は **`diagnosticd`** であり、**root**として実行されているため、プロセスを監視するために使用できます。したがって、監視が開始されると、1秒あたりに**複数のメッセージ**が送信されます。

攻撃を実行するには:

1. 標準のXPCプロトコルを使用して、サービス名が `smd` のサービスに**接続**を開始します。
2. `diagnosticd` に2次の**接続**を形成します。通常の手順とは異なり、2つの新しいmachポートを作成して送信するのではなく、クライアントポートの送信権限は `smd` 接続に関連付けられた**送信権限**の複製で置き換えられます。
3. その結果、XPCメッセージを `diagnosticd` にディスパッチできますが、`diagnosticd` からの応答は `smd` にリダイレクトされます。`smd` にとっては、ユーザーと `diagnosticd` からのメッセージが同じ接続から発信されているように見えます。

![攻撃プロセスを描いた画像](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 次のステップは、`diagnosticd` に選択したプロセス（おそらくユーザー自身のプロセス）の監視を開始するよう指示することです。同時に、`smd` にはルーチンの1004メッセージの洪水が送信されます。ここでの目的は、特権を持つツールをインストールすることです。
5. このアクションは、`handle_bless` 関数内で競合状態を引き起こします。タイミングが重要です：`xpc_connection_get_pid` 関数呼び出しは、特権ツールがユーザーのアプリバンドルに存在するため、ユーザーのプロセスのPIDを返さなければなりません。ただし、`xpc_connection_get_audit_token` 関数は、特に `connection_is_authorized` サブルーチン内で、`diagnosticd` に属する監査トークンを参照する必要があります。

## Variant 2: リプライの転送

XPC（クロスプロセス通信）環境では、イベントハンドラは同時に実行されませんが、リプライメッセージの処理には独自の動作があります。具体的には、リプライを期待するメッセージを送信するための2つの異なる方法が存在します:

1. **`xpc_connection_send_message_with_reply`**: ここでは、XPCメッセージが指定されたキューで受信および処理されます。
2. **`xpc_connection_send_message_with_reply_sync`**: 逆に、この方法では、XPCメッセージが現在のディスパッチキューで受信および処理されます。

この違いは重要です。なぜなら、**リプライパケットがXPCイベントハンドラの実行と同時に解析される可能性**があるからです。特に、`_xpc_connection_set_creds` は、監査トークンの部分的な上書きを防ぐためにロックを実装していますが、この保護を接続オブジェクト全体に拡張していません。その結果、パケットの解析とそのイベントハンドラの実行の間に監査トークンが置き換えられる脆弱性が生じます。

この脆弱性を悪用するには、次のセットアップが必要です:

- **`A`** と **`B`** と呼ばれる2つのmachサービスが、どちらも接続を確立で
