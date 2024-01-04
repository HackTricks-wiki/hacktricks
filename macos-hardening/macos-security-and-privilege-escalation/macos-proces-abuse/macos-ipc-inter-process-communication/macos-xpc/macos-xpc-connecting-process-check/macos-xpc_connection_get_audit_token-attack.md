# macOS xpc\_connection\_get\_audit\_token 攻撃

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出してハッキングのコツを共有する。

</details>

**この技術は** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/) **からコピーされました**

## Mach Messages 基本情報

Mach Messagesについて知らない場合は、このページを確認してください:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

覚えておくべきことは:
Machメッセージは_machポート_を介して送信され、これはmachカーネルに組み込まれた**シングルレシーバー、マルチプルセンダー通信**チャネルです。**複数のプロセスが**メッセージをmachポートに送信できますが、任意の時点で**シングルプロセスのみがそれを読むことができます**。ファイルディスクリプターやソケットと同様に、machポートはカーネルによって割り当てられ管理され、プロセスは整数を見ることができます。これを使用して、どのmachポートを使用したいかをカーネルに指示できます。

## XPC接続

XPC接続がどのように確立されるかわからない場合は、以下を確認してください:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 脆弱性の概要

あなたが知っておくべき興味深い点は、**XPCの抽象化は一対一の接続ですが**、これは**複数の送信者を持つことができる技術の上に構築されていることです**。

* Machポートはシングルレシーバー、_**マルチプルセンダー**_です。
* XPC接続の監査トークンは、_**最も最近に受信したメッセージからコピーされた**_監査トークンです。
* XPC接続の**監査トークン**を取得することは、多くの**セキュリティチェック**にとって重要です。

前述の状況は有望に聞こえますが、問題を引き起こさないシナリオもあります:

* 監査トークンは、接続を受け入れるかどうかを決定するための認証チェックによく使用されます。これはサービスポートへのメッセージを使用して行われるため、**まだ接続が確立されていません**。このポートでの追加のメッセージは、追加の接続要求として処理されるだけです。したがって、**接続を受け入れる前のチェックは脆弱ではありません**（これはまた、`-listener:shouldAcceptNewConnection:`内の監査トークンが安全であることを意味します）。したがって、私たちは**特定のアクションを検証するXPC接続を探しています**。
* XPCイベントハンドラーは同期的に処理されます。これは、イベントハンドラーが次のメッセージに対して呼び出される前に、1つのメッセージのイベントハンドラーが完了しなければならないことを意味します。たとえ並行ディスパッチキュー上であってもです。したがって、**XPCイベントハンドラー内では監査トークンは他の通常の（返信以外の！）メッセージによって上書きされることはありません**。

これにより、可能性がある2つの異なる方法が考えられました:

1. Variant1:
* **エクスプロイト**はサービス**A**とサービス**B**に**接続します**
* サービス**B**は、ユーザーができないサービス**A**で**特権機能**を呼び出すことができます
* サービス**A**は、接続の**イベントハンドラー**内で_**ない**_状態で**`xpc_connection_get_audit_token`**を呼び出します。これは**`dispatch_async`**を使用して非同期に行われます。
* したがって、異なるメッセージが**監査トークンを上書き**する可能性があります。なぜなら、イベントハンドラーの外で非同期にディスパッチされているからです。
* エクスプロイトは、**サービスBにサービスAへのSEND権限を渡します**。
* そのため、svc **B**は実際に**メッセージ**をサービス**A**に**送信します**。
* **エクスプロイト**は**特権アクションを呼び出そうとします**。RCではsvc **A**がこの**アクション**の認証を**チェック**しますが、**svc Bが監査トークンを上書き**しています（エクスプロイトが特権アクションを呼び出すアクセスを与える）。
2. Variant 2:
* サービス**B**は、ユーザーができないサービス**A**で**特権機能**を呼び出すことができます
* エクスプロイトは**サービスA**に接続し、特定の**返信** **ポート**で応答を期待する**メッセージ**をエクスプロイトに**送信します**。
* エクスプロイトはその返信ポートを使用して**サービスB**にメッセージを送信します。
* サービス**Bが返信**するとき、**エクスプロイト**は異なる**メッセージをサービスA**に送信し、特権機能に**到達しようとします**。そして、サービスBからの返信が完璧な瞬間に監査トークンを上書きすることを期待します（Race Condition）。

## Variant 1: イベントハンドラーの外でxpc\_connection\_get\_audit\_tokenを呼び出す <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

シナリオ:

* 二つのmach **サービス**_**A**_**と**_**B**_**に接続できます**（サンドボックスプロファイルと接続を受け入れる前の認証チェックに基づいて）。
* _**A**_は、_**B**_**が通過できる**（しかし私たちのアプリではできない）特定の**アクションのための**認証チェック**を持っていなければなりません。
* たとえば、Bがいくつかの**権限**を持っていたり、**root**として実行されていたりする場合、それは彼にAに特権アクションを実行させるように依頼することを許可するかもしれません。
* この認証チェックのために、_**A**_**は監査トークンを非同期で取得します**。例えば、**`dispatch_async`**から`xpc_connection_get_audit_token`を呼び出すことによって。

{% hint style="danger" %}
この場合、攻撃者は**Race Condition**を引き起こす**エクスプロイト**を作成し、**Aにアクションを実行するように何度も依頼することができます**。RCが**成功する**と、**B**の**監査トークン**がメモリにコピーされ、私たちの**エクスプロイト**のリクエストがAによって**処理されている間に、それは**Bだけが要求できる特権アクションへのアクセスを与えます**。
{% endhint %}

これは_**A**_**が`smd`**で、_**B**_**が`diagnosticd`**であった場合に起こりました。関数[`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)からsmbは、新しい特権ヘルパーツールをインストールするために使用できます（**root**として）。**rootとして実行されるプロセスが** **smd**に連絡する場合、他のチェックは実行されません。

したがって、サービス**B**は**`diagnosticd`**です。なぜなら、それは**root**として実行され、プロセスを**監視**するために使用できるからです。一度監視が開始されると、それは**秒間に複数のメッセージを送信します**。

攻撃を実行するには:

1. 通常のXPCプロトコルに従って**`smd`**への**接続**を確立します。
2. 次に、**`diagnosticd`**への**接続**を確立しますが、新しいmachポートを二つ生成して送信する代わりに、クライアントポートの送信権を**`smd`**への接続のための送信権のコピーに置き換えます。
3. これは、私たちが`diagnosticd`にXPCメッセージを送信できることを意味しますが、**`diagnosticd`が送信するメッセージは`smd`に行きます**。&#x20;
* `smd`にとって、私たちと`diagnosticd`のメッセージは同じ接続で到着するように見えます。

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

4. **`diagnosticd`**に私たちの（または任意のアクティブな）プロセスの**監視を開始するように依頼し**、**`smd`**に特権ツールをインストールするためのルーチン1004メッセージを**スパムします**。
5. これにより、`handle_bless`で非常に特定のウィンドウをヒットする必要があるレースコンディションが作成されます。私たちのプロセスのPIDを`xpc_connection_get_pid`が返す必要があります。なぜなら、特権ヘルパーツールは私たちのアプリバンドルにあるからです。しかし、`connection_is_authorized`関数内の`xpc_connection_get_audit_token`の呼び出しは、`diganosticd`の監査トークンを使用しなければなりません。

## Variant 2: 返信転送

前述のように、XPC接続のイベントに対するハンドラーは、同時に複数回実行されることはありません。しかし、**XPC **_**返信**_**メッセージは異なる方法で処理されます**。返信を期待するメッセージを送信するための2つの関数があります:

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`、この場合、XPCメッセージは指定されたキューで受信および解析されます。
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`、この場合、XPCメッセージは現在のディスパッチキューで受信および解析されます。

したがって、**XPC返信パケットは、XPCイベントハンドラーが実行されている間に解析される可能性があります**。`_xpc_connection_set_creds`はロックを使用していますが、これは監査トークンの部分的な上書きを防ぐだけであり、接続オブジェクト全体をロックするわけではありません。これにより、パケットの解析とそのイベントハンドラーの実行の間に**監査トークンを置き換える**ことが可能になります。

このシナリオには以下が必要です:

* 前と同じように、私たちが両方に接続できる二つのmachサービス
