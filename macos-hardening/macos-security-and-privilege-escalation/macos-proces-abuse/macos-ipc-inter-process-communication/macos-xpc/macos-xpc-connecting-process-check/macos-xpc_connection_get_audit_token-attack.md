# macOS xpc\_connection\_get\_audit\_token 攻撃

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有**するには、[**hacktricks repo**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)に**PRを提出**してください。

</details>

**この技術は**[**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/) **からコピーされました**

## Machメッセージの基本情報

Machメッセージが何であるかわからない場合は、次のページをチェックしてください：

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

当面は、次のことを覚えておいてください：\
Machメッセージは、machカーネルに組み込まれた**単一の受信者、複数の送信者の通信**チャネルである_machポート_を介して送信されます。**複数のプロセスがmachポートにメッセージを送信**できますが、いつでも**単一のプロセスがそれを読み取る**ことができます。ファイルディスクリプタやソケットと同様に、machポートはカーネルによって割り当てられ、管理され、プロセスは整数しか見えず、それを使用してカーネルに使用するmachポートを示すことができます。

## XPC接続

XPC接続の確立方法を知らない場合は、次を確認してください：

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 脆弱性の概要

あなたが知るべき興味深いことは、**XPCの抽象化は1対1の接続**であるが、**複数の送信者を持つことができる技術**に基づいているということです。

* Machポートは単一の受信者、_**複数の送信者**_です。
* XPC接続の監査トークンは、_**最後に受信したメッセージからコピーされた監査トークン**_です。
* XPC接続の監査トークンを取得することは、多くの**セキュリティチェック**にとって重要です。

前述の状況は有望に聞こえますが、問題が発生しないシナリオもあります：

* 監査トークンは、接続を受け入れるかどうかを決定するための認可チェックによく使用されます。これはサービスポートへのメッセージを使用して行われるため、**まだ接続が確立されていません**。このポートへの追加のメッセージは、追加の接続要求として処理されます。したがって、**接続を受け入れる前のチェックは脆弱ではありません**（これは、`-listener:shouldAcceptNewConnection:`内では監査トークンが安全であることを意味します）。したがって、**特定のアクションを検証するXPC接続を探しています**。
* XPCイベントハンドラは同期的に処理されます。つまり、1つのメッセージのイベントハンドラが完了する前に、次のメッセージのイベントハンドラを呼び出す必要があります。したがって、**XPCイベントハンドラ内では、監査トークンは他の通常の（非応答！）メッセージによって上書きされることはありません**。

これに基づいて、2つの異なる方法が考えられます：

1. Variant1:
* **Exploit**はサービス**A**とサービス**B**に**接続**します。
* サービス**B**は、ユーザーができない**特権機能**をサービス**A**で呼び出すことができます。
* サービス**A**は、**イベントハンドラ**内ではない状態で**`xpc_connection_get_audit_token`**を呼び出します。
* したがって、**異なるメッセージが監査トークンを上書き**する可能性があります。なぜなら、イベントハンドラの外部で非同期にディスパッチされるからです。
* Exploitは、サービス**A**への**SEND権限をサービスBに渡します**。
* したがって、svc **B**は実際にはサービス**A**に**メッセージを送信**します。
* Exploitは**特権アクションを呼び出そうとします**。RC svc **A**は、この**アクション**の認可を**チェック**しますが、**svc Bは監査トークンを上書き**しているため（Exploitが特権アクションを呼び出すためのアクセスを提供する）、Exploitは特権アクションを呼び出すことができます。
2. Variant 2:
* サービス**B**は、ユーザーができない**特権機能**をサービス**A**で呼び出すことができます。
* Exploitは、**サービスA**に接続し、特定の**リプライポート**で**応答を期待するメッセージ**を送信します。
* Exploitは、**サービスB**にメッセージを送信し、**そのリプライポート**を渡します。
* サービス**Bが応答すると、メッセージをサービス**Aに送信**しますが、同時に**Exploit**は別の**メッセージをサービスAに送信**し、特権機能に到達しようとし、サービスBからの応答が監査トークンを完璧なタイミングで上書きすることを期待します（競合状態）。
## Variant 1: イベントハンドラの外でxpc_connection_get_audit_tokenを呼び出す <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

シナリオ：

* 2つのmach **サービス**_**A**_**と**_**B**_**に接続できる**（サンドボックスプロファイルと接続を受け入れる前の認証チェックに基づく）。
* _**A**_**は、**_**B**_**が渡すことができる特定の**アクションの****認証チェック**を持っている必要があります（ただし、私たちのアプリはできません）。
* たとえば、Bにはいくつかの**エンタイトルメント**があるか、**root**として実行されている場合、特権アクションを実行するようにAに要求することができます。
* この認証チェックでは、_**A**_**は非同期に監査トークンを取得します**。たとえば、`dispatch_async`から`xpc_connection_get_audit_token`を呼び出すことによって。

{% hint style="danger" %}
この場合、攻撃者は**レースコンディション**をトリガーし、**BがAにアクションを実行する**ように**exploit**を複数回要求します。RCが**成功すると**、**Bの監査トークン**が**メモリにコピー**されます**exploit**のリクエストがAによって**処理**される**間に**、それによって**Bだけが要求できる特権アクションにアクセス**できます。
{% endhint %}

これは、_**A**_**が`smd`**として、_**B**_**が`diagnosticd`**として発生しました。[`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)関数は、特権ヘルパーツール（**root**として）をインストールするために使用できます。**root**として実行される**プロセスが**`smd`**に連絡する場合、他のチェックは実行されません。

したがって、サービス**B**は**`diagnosticd`**であり、**root**として実行されるため、プロセスの**モニタリング**に使用できます。モニタリングが開始されると、**1秒に複数のメッセージを送信**します。

攻撃を実行するには：

1. 通常のXPCプロトコルに従って、**`smd`**への**接続**を確立します。
2. 次に、**`diagnosticd`**への**接続**を確立しますが、新しいmachポートを2つ生成してそれらを送信する代わりに、クライアントポートの送信権を**`smd`**への接続に対して持っている**送信権のコピー**で置き換えます。
3. これは、**`diagnosticd`**にXPCメッセージを送信できるが、**`diagnosticd`**が送信するメッセージは**`smd`**に送信されることを意味します。&#x20;
* `smd`にとって、私たちと`diagnosticd`の両方のメッセージは同じ接続に到着します。

<figure><img src="../../../../../../.gitbook/assets/image (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

4. **`diagnosticd`**に私たち（またはアクティブな任意の）プロセスの**モニタリングを開始**するように依頼し、**`smd`**に対して**ルーチン1004のメッセージをスパム**します（特権ツールをインストールするため）。
5. これにより、`handle_bless`で非常に特定のウィンドウに到達する必要があるレースコンディションが作成されます。特権ヘルパーツールはアプリのバンドルにありますので、`xpc_connection_get_pid`への呼び出しが自分自身のプロセスのPIDを返す必要があります。ただし、`connection_is_authorized`関数内の`xpc_connection_get_audit_token`への呼び出しは、`diganosticd`の監査トークンを使用する必要があります。

## Variant 2: 返信の転送

前述のように、XPC接続のイベントハンドラは複数回同時に実行されません。ただし、**XPC返信メッセージは異なる方法で処理されます**。返信が期待されるメッセージを送信するための2つの関数が存在します。

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`は、XPCメッセージが指定されたキューで受信および解析される場合です。
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`は、XPCメッセージが現在のディスパッチキューで受信および解析される場合です。

したがって、**XPC返信パケットはXPCイベントハンドラの実行中に解析**される可能性があります。`_xpc_connection_set_creds`はロックを使用していますが、これは監査トークンの一部の上書きを防ぐだけであり、接続オブジェクト全体をロックしません。そのため、パケットの解析とイベントハンドラの実行の間に監査トークンを置き換えることが可能です。

このシナリオでは、次のものが必要です：

* 先ほどと同様に、私たちが両方に接続できる2つのmachサービス_A_と_B_が必要です。
* 再び、_A_は_B_が渡すことができる特定のアクションの認証チェックを持っている必要があります（ただし、私たちのアプリはできません）。
* _A_は返信を期待するメッセージを私たちに送信します。
* _B_に返信するメッセージを送信できます。

_A_が返信を期待するメッセージを送信するのを待ちます（1）、返信せずに返信ポートを取得し、_B_に送信するメッセージに使用します（2）。その後、禁止されたアクションを使用するメッセージを送信し、_B_からの返信と同時に到着することを期待します（3）。

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 発見の問題

他のインスタンスを見つけるために長い時間を費やしましたが、条件が静的または動的に検索するのが難しかったです。`xpc_connection_get_audit_token`への非同期呼び出しを検索するために、Fridaを使用してこの関数にフックし、バックトレースに`_xpc_connection_mach_event`が含まれているかどうかをチェックしました（これはイベントハンドラから呼び出されていないことを意味します）。ただし、これは現在フックしているプロセスとアクティブに使用されているアクションからの呼び出しのみを検出します。IDA/Ghidraで到達可能なすべてのmachサービスを分析することは非常に時間がかかりましたが、特にdyld共有キャッシュが関与する呼び出しの場合です。`dispatch_async`を使用して提出されたブロックから到達可能な`xpc_connection_get_audit_token`への呼び出しを検索するためにスクリプトを試しましたが、ブロックとdyld共有キャッシュへのパースが困難でした。これにしばらく時間を費やした後、私たちは持っているものを提出する方が良いと判断しました。
## 修正策 <a href="#the-fix" id="the-fix"></a>

最終的に、私たちは`smd`の一般的な問題と具体的な問題を報告しました。Appleは`smd`のみ修正し、`xpc_connection_get_audit_token`の呼び出しを`xpc_dictionary_get_audit_token`に置き換えました。

関数`xpc_dictionary_get_audit_token`は、このXPCメッセージが受信されたマッハメッセージから監査トークンをコピーします。つまり、脆弱性はありません。ただし、`xpc_dictionary_get_audit_token`と同様に、これは公開APIの一部ではありません。より高レベルの`NSXPCConnection` APIでは、現在のメッセージの監査トークンを取得する明確な方法は存在しません。なぜなら、これはすべてのメッセージをメソッド呼び出しに抽象化しているからです。

なぜAppleがより一般的な修正を適用しなかったのかは不明です。たとえば、接続の保存された監査トークンと一致しないメッセージを破棄するという方法が考えられます。プロセスの監査トークンが正当に変更されるが、接続は開いたままにする必要があるシナリオがあるかもしれません（たとえば、`setuid`を呼び出すとUIDフィールドが変更されます）。ただし、異なるPIDやPIDバージョンのような変更は意図されていない可能性が高いです。

いずれにせよ、この問題はiOS 17とmacOS 14でもまだ残っているため、見つけるために頑張ってください！

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
