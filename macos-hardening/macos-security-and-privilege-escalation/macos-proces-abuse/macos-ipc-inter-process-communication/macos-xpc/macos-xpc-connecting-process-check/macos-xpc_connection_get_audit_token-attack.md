# macOS xpc\_connection\_get\_audit\_token 攻撃

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)を手に入れましょう。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手しましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。
* **ハッキングのコツを共有するために、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

**この技術は** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/) **からコピーされました。**

## Machメッセージの基本情報

Machメッセージについて知らない場合は、このページを確認してください：

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

覚えておくべきことは：
Machメッセージは_machポート_を介して送信され、これはmachカーネルに組み込まれた**シングルレシーバー、マルチプルセンダーの通信チャネル**です。**複数のプロセスがメッセージを送信**できますが、任意の時点で**単一のプロセスのみがそれを読むことができます**。ファイルディスクリプターやソケットと同様に、machポートはカーネルによって割り当てられ管理され、プロセスは整数を見ることができます。これを使用して、どのmachポートを使用したいかをカーネルに指示できます。

## XPC接続

XPC接続がどのように確立されるかわからない場合は、確認してください：

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 脆弱性の概要

あなたが知っておくべき興味深い点は、**XPCの抽象化は一対一の接続ですが**、これは**複数の送信者を持つことができる技術**に基づいているということです：

* Machポートはシングルレシーバー、_**マルチプルセンダー**_です。
* XPC接続の監査トークンは、_**最も最近に受信したメッセージからコピーされた**_監査トークンです。
* XPC接続の**監査トークン**を取得することは、多くの**セキュリティチェック**にとって重要です。

前述の状況は有望に聞こえますが、これが問題を引き起こさないシナリオもあります：

* 監査トークンは、接続を受け入れるかどうかを決定するための認証チェックによく使用されます。これはサービスポートへのメッセージを使用して行われるため、**まだ接続が確立されていません**。このポートでのさらなるメッセージは、追加の接続要求として処理されるだけです。したがって、**接続を受け入れる前のチェックは脆弱ではありません**（これはまた、`-listener:shouldAcceptNewConnection:`内の監査トークンが安全であることを意味します）。したがって、私たちは**特定のアクションを検証するXPC接続を探しています**。
* XPCイベントハンドラーは同期的に処理されます。これは、イベントハンドラーが次のメッセージに対して呼び出される前に、1つのメッセージのイベントハンドラーが完了しなければならないことを意味します。たとえ並行ディスパッチキュー上であっても、**XPCイベントハンドラー内では監査トークンは他の通常の（返信ではない！）メッセージによって上書きされることはありません**。

これにより、2つの異なる方法が可能であるというアイデアが生まれました：

1. Variant1:
* **エクスプロイト**はサービス**A**とサービス**B**に**接続します**
* サービス**B**は、ユーザーができないサービスAで**特権機能を呼び出す**ことができます
* サービス**A**は、接続の**イベントハンドラー**内で_**ない**_状態で**`xpc_connection_get_audit_token`**を呼び出します。これは**`dispatch_async`**で行われます。
* したがって、**異なる**メッセージが**監査トークンを上書き**する可能性があります。なぜなら、イベントハンドラーの外で非同期にディスパッチされているからです。
* エクスプロイトは、**サービスBにサービスAへのSEND権限を渡します**。
* したがって、svc **B**は実際に**メッセージをサービスAに送信します**。
* **エクスプロイト**は**特権アクションを呼び出そうとします**。RC svc **A**は、**svc Bが監査トークンを上書きした**間にこの**アクション**の認証を**チェック**します（エクスプロイトが特権アクションを呼び出すアクセスを与えます）。
2. Variant 2:
* サービス**B**は、ユーザーができないサービスAで**特権機能を呼び出す**ことができます
* エクスプロイトは**サービスA**に接続し、特定の**返信** **ポート**で応答を期待する**メッセージをエクスプロイトに送信します**。
* エクスプロイトは、**その返信ポートを渡すメッセージをサービスBに送信します**。
* サービス**Bが返信するとき**、**エクスプロイト**は異なる**メッセージをサービスAに送信**し、特権機能に**到達しようとします**。そして、サービスBからの返信が完璧な瞬間に監査トークンを上書きすることを期待します（レースコンディション）。

## Variant 1: イベントハンドラーの外でxpc\_connection\_get\_audit\_tokenを呼び出す <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

シナリオ：

* 二つのmach **サービス**_**A**_**と**_**B**_**に接続できます**（サンドボックスプロファイルと接続を受け入れる前の認証チェックに基づいています）。
* _**A**_は、_**B**_**が通過できる**特定の**アクションのための認証チェックを持っていなければなりません**（しかし私たちのアプリではできません）。
* 例えば、Bがいくつかの**権限**を持っていたり、**root**として実行されている場合、それは彼にAに特権アクションを実行させることを許可するかもしれません。
* この認証チェックのために、_**A**_**は監査トークンを非同期で取得します**。例えば、**`dispatch_async`**から`xpc_connection_get_audit_token`を呼び出すことによって。

{% hint style="danger" %}
この場合、攻撃者は**レースコンディション**を引き起こす**エクスプロイト**を作成し、**Aにアクションを実行するように何度も要求することができます**。同時に、**BがAにメッセージを送信します**。RCが**成功すると**、**Bの監査トークン**がメモリにコピーされ、私たちの**エクスプロイト**のリクエストがAによって**処理されている間に**、それは**Bだけが要求できる特権アクションへのアクセスを与えます**。
{% endhint %}

これは_**A**_**が`smd`**で、_**B**_**が`diagnosticd`**であった場合に起こりました。関数[`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)からsmbは、新しい特権ヘルパーツールをインストールするために使用できます（**root**として）。**rootとして実行されているプロセスが** **smdに連絡する**場合、他のチェックは実行されません。

したがって、サービス**B**は**`diagnosticd`**です。なぜなら、それは**root**として実行され、プロセスを**監視**するために使用できるからです。監視が開始されると、1秒に複数のメッセージを**送信します**。

攻撃を実行するには：

1. 通常のXPCプロトコルに従って**`smd`**への**接続**を確立します。
2. 次に、**`diagnosticd`**への**接続**を確立しますが、2つの新しいmachポートを生成して送信する代わりに、クライアントポートの送信権を**`smd`**への接続のための送信権のコピーに置き換えます。
3. これは、私たちが`diagnosticd`にXPCメッセージを送信できることを意味しますが、**`diagnosticd`が送信するメッセージは`smd`に行きます**。&#x20;
* `smd`にとって、私たちと`diagnosticd`のメッセージは同じ接続で到着するように見えます。

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

4. **`diagnosticd`**に私たちの（または任意のアクティブな）プロセスの**監視を開始するように依頼し**、**`smd`**に特権ツールをインストールするためのルーチン1004メッセージを**スパムします**。
5. これにより、`handle_bless`で非常に特定のウィンドウをヒットする必要があるレースコンディションが作成されます。私たちのプロセスのPIDを`xpc_connection_get_pid`が返す必要があります。なぜなら、特権ヘルパーツールは私たちのアプリバンドルにあるからです。しかし、`connection_is_authorized`関数内の`xpc_connection_get_audit_token`の呼び出しは、`diganosticd`の監査トークンを使用しなければなりません。

## Variant 2: 返信転送

前述のように、XPC接続のイベントハンドラーは、同時に複数回実行されることはありません。しかし、**XPC**_**返信**_**メッセージは異なる方法で処理されます**。返信を期待するメッセージを送信するための2つの関数があります：

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`、この場合、XPCメッセージは指定されたキューで受信および解析されます。
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`、この場合、XPCメッセージは現在のディスパッチキューで受信および解析されます。

したがって、**XPC返信パケット
