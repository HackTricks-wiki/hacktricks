# macOS xpc\_connection\_get\_audit\_token 攻撃

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする。
* **ハッキングトリックを共有する**ために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>

**詳細については、元の投稿を確認してください:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。これは要約です:

## Machメッセージの基本情報

Machメッセージが何かわからない場合は、このページをチェックしてください:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

今のところ、([ここからの定義](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

Machメッセージは _mach port_ を介して送信され、これは machカーネルに組み込まれた **単一の受信者、複数の送信者通信** チャネルです。 **複数のプロセスが mach port にメッセージを送信**できますが、いつでも **単一のプロセスだけがそれを読む**ことができます。 ファイルディスクリプタやソケットと同様に、mach port はカーネルによって割り当てられ管理され、プロセスは整数しか見ません。これを使用して、カーネルに使用する mach port を示すことができます。

## XPC接続

XPC接続がどのように確立されるかわからない場合は、次を確認してください:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 脆弱性の要約

あなたが知っておくべき興味深い点は、**XPCの抽象化は1対1の接続**であるが、**複数の送信者を持つ技術**に基づいているということです:

* Machポートは単一の受信者、**複数の送信者**です。
* XPC接続の監査トークンは、**最後に受信したメッセージからコピー**されます。
* XPC接続の **監査トークン** を取得することは、多くの **セキュリティチェック** にとって重要です。

前述の状況は有望に聞こえますが、問題を引き起こさないシナリオもいくつかあります ([ここから](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* 監査トークンは、接続を受け入れるかどうかを決定するための認可チェックによく使用されます。これはサービスポートへのメッセージを使用して行われるため、**接続はまだ確立されていません**。このポートへの追加のメッセージは、追加の接続要求として処理されます。したがって、**接続を受け入れる前のチェックは脆弱ではありません**（これは `-listener:shouldAcceptNewConnection:` 内でも監査トークンが安全であることを意味します）。したがって、**特定のアクションを検証する XPC 接続を探しています**。
* XPCイベントハンドラは同期的に処理されます。つまり、1つのメッセージのイベントハンドラが完了する前に、次のメッセージのためにそれを呼び出す必要があります。したがって、**XPCイベントハンドラ内では、他の通常の（非応答）メッセージによって監査トークンを上書きすることはできません**。

これが悪用される可能性がある2つの異なる方法:

1. Variant1:
* **Exploit** がサービス **A** とサービス **B** に **接続**します
* サービス **B** は、ユーザーができない **サービス A の特権機能** を呼び出すことができます
* サービス **A** が **`dispatch_async`** 内で **`xpc_connection_get_audit_token`** を呼び出すとき、**イベントハンドラ内にいない**。
* したがって、**異なる**メッセージが **監査トークンを上書き** する可能性があります。なぜなら、イベントハンドラの外部で非同期にディスパッチされているからです。
* 悪用は **サービス A に対して SEND 権限をサービス B に渡します**。
* したがって、svc **B** は実際にはサービス **A** に **メッセージを送信**します。
* **悪用**は **特権アクションを呼び出そうとします**。RC svc **A** はこの **アクション** の認可をチェックし、**svc B が監査トークンを上書き** したため（悪用が特権アクションを呼び出す権限を与えられる）、アクセスできるようになります。
2. Variant 2:
* サービス **B** は、ユーザーができない **サービス A の特権機能** を呼び出すことができます
* 悪用は、**サービス A** に接続し、特定の **リプライポート** で **応答を期待するメッセージ** を送信します。
* 悪用は **サービス B** に **リプライポート** を渡すメッセージを送信します。
* サービス **B が応答する**と、**悪用** は **サービス A に異なるメッセージを送信** し、特権機能に到達しようとし、サービス B からの応答が監査トークンを完璧なタイミングで上書きすることを期待します（競合状態）。

## Variant 1: イベントハンドラ外で xpc\_connection\_get\_audit\_token を呼び出す <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

シナリオ:

* サンドボックスプロファイルと接続を受け入れる前の認可チェックに基づいて、両方に接続できる2つの mach サービス **`A`** と **`B`**。
* _**A**_ は、**`B`** が通過できる特定のアクションの **認可チェック** を持っている必要があります（ただし、アプリはできません）。
* たとえば、Bにはいくつかの **権限** があるか **root** として実行されている場合、Aに特権アクションを実行するように要求することができます。
* この認可チェックでは、**`A`** は、例えば `dispatch_async` から `xpc_connection_get_audit_token` を呼び出すことによって、監査トークンを非同期で取得します。

{% hint style="danger" %}
この場合、攻撃者は **Race Condition** をトリガーし、**B が A にアクションを実行するように要求**する **悪用** を複数回実行し、**B が A にメッセージを送信**するようにします。RCが **成功する** と、**B** の **監査トークン** が **メモリにコピー** され、**悪用** のリクエストが **A によって処理される間** に、特権アクションにアクセスできるようになります。これは **B だけが要求できる特権アクション** にアクセスできるようになります。
{% endhint %}

これは、**`A`** が `smd` として、**`B`** が `diagnosticd` として発生しました。 smb の関数 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) は、新しい特権ヘルパーツール（**root** として）をインストールするために使用できます。 **root** として実行されているプロセスが **smd** に連絡を取ると、他のチェックは実行されません。

したがって、サービス **B** は **`diagnosticd`** であり、**root** として実行されているため、プロセスを監視するために使用できます。したがって、監視が開始されると、1秒あたり **複数のメッセージを送信** します。

攻撃を実行するには:

1. 標準の XPC プロトコルを使用して、`smd` という名前のサービスに **接続** を開始します。
2. `diagnosticd` に二次 **接続** を形成します。通常の手順とは異なり、2つの新しい mach ポートを作成して送信するのではなく、クライアントポートの送信権限は、`smd` 接続に関連付けられた **送信権限** の複製で置き換えられます。
3. その結果、XPC メッセージを `diagnosticd` にディスパッチできますが、`diagnosticd` からの応答は `smd` にリダイレクトされます。`smd` にとっては、ユーザーと `diagnosticd` からのメッセージが同じ接続から発信されているように見えます。

![攻撃プロセスを描いた画像](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)
4. 次のステップでは、`diagnosticd`に選択したプロセス（おそらくユーザー自身のプロセス）の監視を開始するよう指示します。同時に、`smd`にルーチンの1004メッセージの洪水を送信します。ここでの意図は、特権を持つツールをインストールすることです。
5. このアクションにより、`handle_bless`関数内で競合状態が発生します。タイミングが重要です：`xpc_connection_get_pid`関数呼び出しは、ユーザーのプロセスのPIDを返さなければなりません（特権を持つツールはユーザーのアプリバンドルに存在します）。ただし、`xpc_connection_get_audit_token`関数、特に`connection_is_authorized`サブルーチン内で、`diagnosticd`に属する監査トークンを参照する必要があります。

## 変種2: 返信の転送

XPC（クロスプロセス通信）環境では、イベントハンドラは同時に実行されませんが、返信メッセージの処理には独自の動作があります。具体的には、返信を期待するメッセージを送信するために2つの異なるメソッドが存在します。

1. **`xpc_connection_send_message_with_reply`**: ここでは、XPCメッセージは指定されたキューで受信および処理されます。
2. **`xpc_connection_send_message_with_reply_sync`**: これに対して、このメソッドでは、XPCメッセージは現在のディスパッチキューで受信および処理されます。

この違いは重要です。これにより、**返信パケットがXPCイベントハンドラの実行と同時に解析される可能性**が生じます。特に、`_xpc_connection_set_creds`は監査トークンの部分的な上書きを防ぐためにロックを実装していますが、この保護を接続オブジェクト全体には拡張していません。その結果、パケットの解析とそのイベントハンドラの実行の間に監査トークンが置換される脆弱性が生じます。

この脆弱性を悪用するには、次のセットアップが必要です：

* **`A`** と **`B`** という名前の2つのマッハサービスが、どちらも接続を確立できる必要があります。
* サービス **`A`** は、**`B`** のみが実行できる特定のアクションの認証チェックを含める必要があります（ユーザーのアプリケーションはできません）。
* サービス **`A`** は、返信を期待するメッセージを送信する必要があります。
* ユーザーは、**`B`** に返信するメッセージを送信できます。

悪用プロセスは以下の手順を含みます：

1. サービス **`A`** が返信を期待するメッセージを送信するのを待ちます。
2. 直接 **`A`** に返信する代わりに、返信ポートを乗っ取り、サービス **`B`** にメッセージを送信します。
3. その後、禁止されたアクションを含むメッセージが送信され、**`B`** からの返信と同時に処理されることが期待されます。

以下は、説明された攻撃シナリオの視覚的表現です：

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 発見の問題

* **インスタンスの特定の難しさ**: `xpc_connection_get_audit_token`の使用例を静的および動的に検索することは困難でした。
* **方法論**: `xpc_connection_get_audit_token`関数をフックするためにFridaを使用し、イベントハンドラから発信されない呼び出しをフィルタリングしました。ただし、この方法はフックされたプロセスに限定され、アクティブな使用が必要でした。
* **分析ツール**: IDA/Ghidraなどのツールを使用して到達可能なマッハサービスを調査しましたが、dyld共有キャッシュを含む呼び出しによって時間がかかり、複雑になりました。
* **スクリプトの制限**: `dispatch_async`ブロックからの`xpc_connection_get_audit_token`への呼び出しを解析する試みは、ブロックの解析とdyld共有キャッシュとの相互作用の複雑さによって妨げられました。

## 修正 <a href="#the-fix" id="the-fix"></a>

* **報告された問題**: `smd`内で見つかった一般的および特定の問題について、Appleに報告が提出されました。
* **Appleの対応**: Appleは、`smd`内の問題を解決するために、`xpc_connection_get_audit_token`を`xpc_dictionary_get_audit_token`で置き換えました。
* **修正の性質**: `xpc_dictionary_get_audit_token`関数は、受信したXPCメッセージに関連付けられたマッハメッセージから監査トークンを直接取得するため、安全であると見なされます。ただし、これは`xpc_connection_get_audit_token`と同様に公開APIの一部ではありません。
* **より包括的な修正の不在**: Appleが接続の保存された監査トークンと一致しないメッセージを破棄するなど、より包括的な修正を実装しなかった理由は明確ではありません。特定のシナリオ（たとえば、`setuid`の使用）で正当な監査トークンの変更が可能である可能性があることが要因かもしれません。
* **現在の状況**: 問題はiOS 17およびmacOS 14で依然として存在し、それを特定し理解しようとする人々にとって課題となっています。
