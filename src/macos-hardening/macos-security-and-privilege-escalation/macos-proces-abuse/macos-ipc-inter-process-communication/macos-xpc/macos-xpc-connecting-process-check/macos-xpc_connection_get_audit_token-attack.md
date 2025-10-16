# macOS xpc_connection_get_audit_token 攻撃

{{#include ../../../../../../banners/hacktricks-training.md}}

**詳しくは元の投稿を参照してください：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下は要約です：

## Mach Messages 基本情報

Mach Messages が何か分からない場合はまずこのページを確認してください：


{{#ref}}
../../
{{#endref}}

ここで覚えておくべきこと（[ここからの定義](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：\
Mach messages は _mach port_ を通じて送られます。これは mach カーネルに組み込まれた **single receiver, multiple sender communication** チャネルです。**複数のプロセスが mach port にメッセージを送ることができます**が、任意の時点で**読み取れるのは単一のプロセスのみ**です。file descriptors や sockets と同様に、mach ports はカーネルによって割り当て・管理され、プロセスは整数だけを見て、それを使ってカーネルにどの mach port を使いたいかを示します。

## XPC Connection

XPC 接続がどのように確立されるか分からない場合は次を確認してください：


{{#ref}}
../
{{#endref}}

## Vuln Summary

知っておくべき興味深い点は、**XPC の抽象化は one-to-one の接続**である一方、それが基づいている技術は**複数の送信元を持てる**ということです。したがって：

- Mach ports は単一の受信者、**複数の送信者**です。
- XPC 接続の audit token は **最も最近受信したメッセージからコピーされた audit token** です。
- XPC 接続の **audit token を取得することは** 多くの **セキュリティチェック** にとって重要です。

ただし前述の状況が常に問題を引き起こすわけではありません（[出典](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：

- Audit tokens はしばしば接続を受け入れるかどうかを決定するための認可チェックに使われます。これはサービスポートへのメッセージを使って行われるため、**まだ接続が確立されていない**段階です。このポートへの追加メッセージは単に追加の接続要求として扱われます。したがって、接続の受け入れ前に行われるチェックは**脆弱ではありません**（これは `-listener:shouldAcceptNewConnection:` 内では audit token が安全であることを意味します）。我々が探しているのは**特定のアクションを検証する XPC 接続**です。
- XPC のイベントハンドラは同期的に処理されます。これは、あるメッセージのイベントハンドラが完了するまで次のメッセージのハンドラは呼ばれないことを意味し、並列の dispatch queue 上でも同様です。したがって **XPC イベントハンドラ内では audit token は他の通常の（返信ではない！）メッセージによって上書きされません**。

これが悪用可能となる2つの異なる方法：

1. Variant1:
- **Exploit** がサービス **A** とサービス **B** に **接続** する
- サービス **B** はユーザが行えない **privileged functionality** をサービス A に要求できる
- サービス **A** は **event handler 内ではなく**、例えば **`dispatch_async`** 内から `xpc_connection_get_audit_token` を呼ぶ
- そのため **別の** メッセージが **Audit Token を上書き** する可能性がある（イベントハンドラ外で非同期にディスパッチされるため）
- エクスプロイトはサービス A に対する **SEND 権限を service B に渡す**
- したがって svc **B** が実際にサービス **A** に **メッセージを送る**
- **Exploit** は **privileged action** を **呼び出そうとする**。A の RC（race condition）により svc **A** がこの **action** の認可をチェックする際に **svc B が Audit token を上書きしてしまえば**（これによりエクスプロイトは B のみが要求できる特権アクションにアクセスできる）

2. Variant 2:
- サービス **B** はユーザが行えない **privileged functionality** をサービス A に要求できる
- エクスプロイトは **service A** に接続し、service A は特定の **reply port** を使った **レスポンスを期待するメッセージ** をエクスプロイトに送る
- エクスプロイトはその **reply port** を使って service **B** にメッセージを送る
- service **B** が返信すると、それは **service A にメッセージを送る** が、同時に **エクスプロイト** は service A に別のメッセージを送り、service B の返信が完璧なタイミングで Audit token を上書きすることを期待する（Race Condition）

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

シナリオ：

- サンドボックスプロファイルや接続受け入れ前の認可チェックに基づき、我々が両方に接続できる2つの mach サービス **`A`** と **`B`**。
- _**A**_ は特定のアクションに対して **認可チェック** を持っており、そのチェックを **`B`** は通過できる（我々のアプリは通過できない）。
- たとえば、B がいくつかの **entitlements** を持っているか root として動作していれば、A に対して特権アクションを要求できるかもしれない。
- その認可チェックのために、**`A`** は非同期に audit token を取得する。例えば `dispatch_async` から `xpc_connection_get_audit_token` を呼ぶ、といった形。

> [!CAUTION]
> この場合、攻撃者は **Race Condition** を引き起こすことで、**A に対してアクションを複数回要求** しつつ **B に A へメッセージを送らせる** エクスプロイトを作れます。RC が成功すると、A が我々の要求を処理している間に **B の audit token** がメモリにコピーされ、B のみが要求できる特権アクションへのアクセスが与えられます。

これは **`A`** を `smd`、**`B`** を `diagnosticd` としたケースで実際に発生しました。smb の関数である [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) は新しい privileged helper tool を（**root** として）インストールするために使われます。root として動作しているプロセスが `smd` に連絡すると、他のチェックは行われません。

したがって、サービス **B** は `diagnosticd` であり、これは **root** として動作し、プロセスの監視に使えるため、一度監視が始まると **秒間複数のメッセージを送信** します。

攻撃の実行手順：

1. 標準の XPC プロトコルを使って、名前が `smd` のサービスに **接続** を開始する。
2. `diagnosticd` に対して二次的な **接続** を形成する。通常の手順とは異なり、クライアントポートの send 権は新しく作成・送信されるのではなく、`smd` 接続に関連する **send right** の複製に置き換えられる。
3. 結果として、XPC メッセージは `diagnosticd` にディスパッチされるが、`diagnosticd` からの応答は `smd` にリルートされる。`smd` から見ると、ユーザおよび `diagnosticd` からのメッセージが同じ接続から来ているように見える。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 次に `diagnosticd` に特定のプロセス（たとえばユーザ自身のプロセス）の監視を開始させるよう指示する。同時に通常の 1004 メッセージを `smd` に大量送信する。目的は特権を持ったツールをインストールすることにある。
5. これにより `handle_bless` 関数内でレースコンディションが発生する。タイミングが重要で、`xpc_connection_get_pid` の呼び出しはユーザのプロセスの PID を返す必要がある（特権ツールはユーザのアプリバンドル内にあるため）。一方で `xpc_connection_get_audit_token`（具体的には `connection_is_authorized` サブルーチン内）は `diagnosticd` に属する audit token を参照する必要がある。

## Variant 2: reply forwarding

XPC（Cross-Process Communication）の環境では、イベントハンドラが同時に実行されない一方で、返信メッセージの処理には独特の挙動があります。具体的には、返信を期待するメッセージを送る方法は2種類あります：

1. **`xpc_connection_send_message_with_reply`**: この場合、XPC メッセージは指定されたキュー上で受信・処理されます。
2. **`xpc_connection_send_message_with_reply_sync`**: 逆にこの方法では、XPC メッセージは現在の dispatch queue 上で受信・処理されます。

この違いは重要で、**返信パケットの解析が XPC イベントハンドラの実行と同時に行われ得る**ことを可能にします。注目すべき点として、`_xpc_connection_set_creds` は audit token の部分的な上書きを防ぐためのロックを実装していますが、接続オブジェクト全体に対する保護は行っていません。結果として、パケットの解析とそのイベントハンドラの実行の間の短い期間に audit token が置き換えられる脆弱性が生じます。

この脆弱性を悪用するためには、次のセットアップが必要です：

- サービス **A** と **B** という名前の2つの mach サービス。どちらにも接続できること。
- サービス **A** は特定のアクションに対して認可チェックを持ち、そのアクションは **B** のみが実行可能（ユーザのアプリケーションはできない）。
- サービス **A** は返信を期待するメッセージを送ること。
- ユーザはサービス **B** に対して応答するメッセージを送れること。

悪用の流れは次の通り：

1. まずサービス **A** が返信を期待するメッセージを送るのを待つ。
2. その返信先ポートを直接 A に返答するのではなくハイジャックし、それを使って service **B** にメッセージを送る。
3. その後、禁止されたアクションに関するメッセージを送信し、これが **B** からの返信と同時に処理されることを期待する。

以下は説明した攻撃シナリオの視覚的表現です：

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **インスタンスの発見が困難**：`xpc_connection_get_audit_token` の使用箇所を静的・動的に探すのが難しかった。
- **手法**：Frida を使って `xpc_connection_get_audit_token` をフックし、event handler から呼ばれていない呼び出しをフィルタした。ただしこの方法はフックしたプロセスに限定され、かつそのプロセスが実際に使用されている必要がある。
- **解析ツール**：IDA/Ghidra で到達可能な mach サービスを調べたが時間がかかり、dyld shared cache を介した呼び出しにより複雑だった。
- **スクリプト化の限界**：`dispatch_async` ブロックからの `xpc_connection_get_audit_token` 呼び出しを解析するスクリプト化は、blocks の解析や dyld shared cache との相互作用の複雑さにより妨げられた。

## The fix <a href="#the-fix" id="the-fix"></a>

- **報告**：smd 内で見つかった一般的・具体的な問題を Apple に報告した。
- **Apple の対応**：Apple は `smd` 内で `xpc_connection_get_audit_token` を `xpc_dictionary_get_audit_token` に置き換えることで対処した。
- **修正の性質**：`xpc_dictionary_get_audit_token` は受信した XPC メッセージに紐づく mach message から直接 audit token を取得するため安全と見なされる。ただしこれは `xpc_connection_get_audit_token` と同様に public API の一部ではない。
- **より広範な修正の欠如**：なぜ Apple が接続に保存された audit token と一致しないメッセージを破棄するような包括的な修正を行わなかったのかは不明のまま。あるシナリオ（例えば `setuid` の使用）では audit token が合法的に変化し得る可能性があることが理由かもしれない。
- **現状**：この問題は iOS 17 および macOS 14 に残存しており、発見と理解が困難なままである。

## Finding vulnerable code paths in practice (2024–2025)

このバグクラスの XPC サービスを監査する際は、メッセージのイベントハンドラ外で行われる認可、または返信処理と同時に行われる認可に注目してください。

静的トリアージのヒント：
- `xpc_connection_get_audit_token` への呼び出しを、`dispatch_async`/`dispatch_after` 経由でキューに入るブロックや、メッセージハンドラ外で動作する他のワーカーキューから到達可能か検索する。
- 接続ごとの状態とメッセージごとの状態を混在させる認可ヘルパーを探す（例：`xpc_connection_get_pid` で PID を取得しつつ、`xpc_connection_get_audit_token` で audit token を取得しているケース）。
- NSXPC コードでは、`-listener:shouldAcceptNewConnection:` 内でチェックが行われているか、またはメッセージごとのチェックの場合はメッセージごとの audit token を使っているか（例：lower-level のコードでメッセージの dictionary を `xpc_dictionary_get_audit_token` で使う）を確認する。

動的トリアージのコツ：
- `xpc_connection_get_audit_token` をフックし、そのユーザースタックにイベントデリバリパス（例：`_xpc_connection_mach_event`）が含まれていない呼び出しをフラグする。例：Frida フック：
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
注意:
- macOS上では、protected/Apple binariesへのinstrumentingはSIPを無効にするか開発環境が必要になる場合があります。自分でビルドしたものやuserland servicesでのテストを優先してください。
- reply-forwarding races (Variant 2) については、`xpc_connection_send_message_with_reply` と通常のリクエストのタイミングをファジングしてリプライパケットの同時解析を監視し、認可時に使用される effective audit token を操作できるか確認してください。

## 必要になる可能性のあるエクスプロイトプリミティブ

- Multi-sender setup (Variant 1): A と B に接続を作成し、A の client port の send right を複製して B の client port として使うことで、B の replies が A に配達されるようにする。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A の保留中のリクエスト（reply port）から send-once right を奪い取り、その reply port を使って B に細工したメッセージを送る。これにより B の返信が、あなたの特権リクエストが解析されている間に A に届くようにする。

These require low-level mach message crafting for the XPC bootstrap and message formats; review the mach/XPC primer pages in this section for the exact packet layouts and flags.

## 有用なツール

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) は接続を列挙し、トラフィックを観察してマルチ送信者のセットアップやタイミングを検証するのに役立つ。例: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: `xpc_connection_send_message*` と `xpc_connection_get_audit_token` をインターポーズして、ブラックボックステスト中の呼び出し箇所とスタックをログに残す。



## References

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
