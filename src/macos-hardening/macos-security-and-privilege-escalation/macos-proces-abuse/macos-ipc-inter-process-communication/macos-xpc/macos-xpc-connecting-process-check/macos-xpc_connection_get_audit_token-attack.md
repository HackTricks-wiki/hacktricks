# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**詳細については原文を確認してください:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下はその要約です:<sup>[[1]](#references)</sup>

## Mach Messages の基本情報

Mach Messages について知らない場合は、まず以下のページを確認してください:


{{#ref}}
../../
{{#endref}}

現時点では、以下を覚えておいてください（[こちらの定義](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）:<sup>[[1]](#references)</sup>\
Mach messages は _mach port_ 経由で送信されます。これは mach kernel に組み込まれた、**単一の receiver と複数の sender による通信** channel です。**複数の process が** mach port に **messages を送信できます**が、どの時点でも、そこから **read できる process は1つだけ**です。file descriptors や sockets と同様に、mach ports は kernel によって割り当て・管理され、process から見えるのは integer だけです。process はこの integer を使用して、使用したい mach port を kernel に指定できます。

## XPC Connection

XPC connection の確立方法を知らない場合は、以下を確認してください:


{{#ref}}
../
{{#endref}}

## 脆弱性の概要

知っておくべき重要な点は、**XPC の abstraction は one-to-one connection である**一方で、**複数の sender を扱える technology の上に構築されている**ことです。そのため:

- Mach ports は single receiver、**multiple sender** です。
- XPC connection の audit token は、**最後に受信した message からコピーされた audit token** です。
- XPC connection の **audit token** を取得することは、多くの **security checks** にとって重要です。<sup>[[1]](#references)</sup>

前述の状況は有望に聞こえますが、問題を引き起こさないシナリオもあります（[こちらより](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）:<sup>[[1]](#references)</sup>

- Audit tokens は、connection を受け入れるかどうかを判断する authorization check によく使用されます。この処理は service port への message を使用して行われるため、**まだ connection は確立されていません**。この port への追加 messages は、単に追加の connection requests として処理されます。したがって、**connection を受け入れる前の checks は脆弱ではありません**（これは `-listener:shouldAcceptNewConnection:` 内の audit token も安全であることを意味します）。そのため、**特定の actions を検証する XPC connections** を探すことになります。
- XPC event handlers は同期的に処理されます。つまり、concurrent dispatch queues 上であっても、次の message の処理を開始する前に、1つの message の event handler を完了する必要があります。そのため、**XPC event handler 内では、他の通常の（reply ではない）messages によって audit token が上書きされることはありません**。<sup>[[1]](#references)</sup>

これが悪用される可能性のある方法は2つあります:

1. Variant1:
- **Exploit** が service **A** と service **B** に **connect** する。
- Service **B** は、user には実行できない **privileged functionality** を service A 内で呼び出せる。
- Service **A** は、**`dispatch_async`** 内の connection の **event handler** の外部で **`xpc_connection_get_audit_token`** を呼び出す。
- そのため、別の **message** によって **Audit Token** が **overwrite** される可能性がある。これは event handler の外部で非同期に dispatch されるためである。
- Exploit は **service A への SEND right** を **service B に渡す**。
- その結果、svc **B** が実際に **service A へ messages を送信**する。
- **Exploit** は **privileged action** の呼び出しを試みる。RC において svc **A** は、**svc B が Audit token を overwrite している間**に、この **action** の authorization を **check** する（これにより exploit が privileged action にアクセスできる）。
2. Variant 2:
- Service **B** は、user には実行できない **privileged functionality** を service A 内で呼び出せる。
- Exploit は **service A** に connect し、service A は exploit に、特定の **replay** **port** で response を期待する **message** を送信する。
- Exploit は、その **reply port** を渡す message を **service B** に送信する。
- Service **B** が reply すると、**exploit が privileged functionality に到達しようとして別の message を service A に送信している間に**、service B はその message を **service A に送信**する。このとき、service B からの reply によって Audit token が適切なタイミングで overwrite されることを期待する（Race Condition）。

## Variant 1: event handler の外部で xpc_connection_get_audit_token を呼び出す <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

シナリオ:

- 接続可能な2つの mach services **`A`** と **`B`**（sandbox profile と、connection を受け入れる前の authorization checks に基づく）。
- _**A**_ には、**`B` が通過できる（ただしアプリは通過できない）特定の action に対する authorization check** が必要です。
- 例えば、B が何らかの **entitlements** を持っている、または **root** として実行されている場合、A に privileged action の実行を要求できる可能性があります。
- この authorization check のために、_**A**_ は非同期に audit token を取得します。例えば、`dispatch_async` から `xpc_connection_get_audit_token` を呼び出します。

> [!CAUTION]
> この場合、attacker は **Race Condition** を発生させることができます。A に action の実行を要求する **exploit** を何度も実行する一方で、**B に `A` へ messages を送信させます**。RC が **成功**すると、**B** の **audit token** が memory にコピーされている間に、**exploit** の request が A によって **handled** されます。これにより、B だけが要求できる privileged action にアクセスできるようになります。

これは **`A` が `smd`、`B` が `diagnosticd`** の場合に発生しました。smb の [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function を使用すると、新しい privileged helper toot を（**root** として）install できます。**root として実行されている process が** **smd に contact** すると、他の checks は実行されません。

したがって、service **B** は **`diagnosticd`** です。これは root として実行され、process の **monitor** に使用できるため、monitoring が開始されると、**毎秒複数の messages を送信**します。

攻撃を実行するには:

1. 標準の XPC protocol を使用して、`smd` という名前の service への **connection** を開始します。
2. `diagnosticd` への secondary **connection** を作成します。通常の手順とは異なり、2つの新しい mach ports を作成して送信するのではなく、client port の send right を、`smd` connection に関連付けられた **send right** の duplicate に置き換えます。
3. その結果、XPC messages は `diagnosticd` に dispatch できますが、`diagnosticd` からの responses は `smd` に reroute されます。`smd` から見ると、user と `diagnosticd` の両方からの messages が同じ connection から送信されているように見えます。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 次の step では、選択した process（user 自身の process でも可能）の monitoring を開始するよう `diagnosticd` に指示します。同時に、通常の 1004 messages を `smd` に大量送信します。ここでの目的は、elevated privileges を持つ tool を install することです。
5. この action により、`handle_bless` function 内で race condition が発生します。タイミングが重要です。`xpc_connection_get_pid` function call は user の process の PID を返す必要があります（privileged tool は user の app bundle 内に存在するためです）。一方、`connection_is_authorized` subroutine 内の `xpc_connection_get_audit_token` function は、`diagnosticd` に属する audit token を参照する必要があります。<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

XPC（Cross-Process Communication）environment では、event handlers は concurrent に実行されませんが、reply messages の処理には独特の挙動があります。具体的には、reply を期待する messages の送信方法が2つあります:

1. **`xpc_connection_send_message_with_reply`**: ここでは、XPC message は指定された queue 上で受信・処理されます。
2. **`xpc_connection_send_message_with_reply_sync`**: これに対して、この method では XPC message が現在の dispatch queue 上で受信・処理されます。

この違いは重要です。reply packets が XPC event handler の実行と concurrent に parse される可能性があるためです。特に、`_xpc_connection_set_creds` は audit token の部分的な overwrite を防ぐための locking を実装していますが、この protection は connection object 全体には及びません。その結果、packet の parsing と event handler の実行の間に audit token を置き換えられるという vulnerability が発生します。

この vulnerability を exploit するには、以下の setup が必要です:

- どちらも connection を確立できる、**`A`** と **`B`** と呼ばれる2つの mach services。
- Service **`A`** には、**`B` だけが実行できる（user の application では実行できない）特定の action に対する authorization check** が含まれている。
- Service **`A`** は reply を予期する message を送信する。
- User は **`B`** に message を送信でき、B はそれに応答する。

Exploit の手順は以下のとおりです:

1. Service **`A`** が reply を期待する message を送信するまで待ちます。
2. **`A`** に直接 reply する代わりに、reply port を hijack し、それを使用して service **`B`** に message を送信します。
3. 次に forbidden action に関する message を dispatch し、**`B`** からの reply と concurrent に処理されることを期待します。<sup>[[1]](#references)</sup>

以下は、説明した attack scenario の visual representation です:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances の発見の難しさ**: `xpc_connection_get_audit_token` の使用箇所を static と dynamic の両方で検索するのは困難でした。
- **Methodology**: Frida を使用して `xpc_connection_get_audit_token` function を hook し、event handlers から呼び出されていない calls を filter しました。しかし、この method は hook した process に限定され、active usage も必要でした。
- **Analysis Tooling**: IDA/Ghidra などの tools を使用して到達可能な mach services を調査しましたが、dyld shared cache に関係する calls によって複雑化し、process は時間のかかるものでした。
- **Scripting Limitations**: `dispatch_async` blocks からの `xpc_connection_get_audit_token` calls を script で分析しようとしましたが、blocks の parsing と dyld shared cache との相互作用が複雑であったため、妨げられました。<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd` 内で発見された general および specific issues の詳細を記載した report が Apple に submit されました。
- **Apple's Response**: Apple は `xpc_connection_get_audit_token` を `xpc_dictionary_get_audit_token` に置き換えることで、`smd` の issue に対応しました。<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function は、受信した XPC message に紐づく mach message から audit token を直接取得するため、安全と考えられています。ただし、`xpc_connection_get_audit_token` と同様に、public API の一部ではありません。
- **Absence of a Broader Fix**: connection に保存された audit token と一致しない messages を破棄するなど、より包括的な fix を Apple が実装しなかった理由は不明です。特定のシナリオ（`setuid` の使用など）では正当な audit token の変更が発生する可能性があり、それが要因かもしれません。
- **Current Status**: この issue は iOS 17 と macOS 14 にも残っており、これを発見して理解しようとする人々にとって challenge となっています。<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

この bug class について XPC services を audit する際は、message の event handler の外部で、または reply processing と concurrent に実行される authorization に注目してください。

Static triage hints:
- `dispatch_async`/`dispatch_after` 経由で queue に追加された blocks、または message handler の外部で実行される他の worker queues から到達可能な `xpc_connection_get_audit_token` calls を検索します。
- per-connection state と per-message state を混在させる authorization helpers を探します（例えば、PID を `xpc_connection_get_pid` から取得し、audit token を `xpc_connection_get_audit_token` から取得するもの）。
- NSXPC code では、checks が `-listener:shouldAcceptNewConnection:` で実行されていることを確認します。または per-message checks の場合、implementation が per-message audit token を使用していることを確認します（例えば lower-level code で message の dictionary から `xpc_dictionary_get_audit_token` を使用するもの）。

Dynamic triage tips:
- `xpc_connection_get_audit_token` を hook し、user stack に event-delivery path（例: `_xpc_connection_mach_event`）が含まれていない invocations に flag を立てます。Example Frida hook:
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
Notes:
- macOSでは、保護された/AppleのバイナリへのinstrumentingにはSIPの無効化またはdevelopment environmentが必要になる場合があります。自身でビルドしたもの、またはuserland servicesでのテストを優先してください。
- reply-forwarding races（Variant 2）では、`xpc_connection_send_message_with_reply`と通常のリクエストのタイミングをfuzzingしながら、reply packetsのconcurrent parsingを監視し、authorizationで使用されるeffective audit tokenに影響を与えられるか確認してください。

## Exploitation primitives you will likely need

- Multi-sender setup（Variant 1）：AおよびBへのconnectionsを作成し、Aのclient portのsend rightをduplicateしてBのclient portとして使用します。これにより、BのrepliesがAへdeliveryされます。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A の pending request（reply port）から send-once right を取得し、その reply port を使って B に crafted message を送信する。これにより、privileged request の解析中に B の reply が A に届く。

これらには、XPC bootstrap および message format の low-level な mach message crafting が必要です。正確な packet layout と flag については、このセクションの mach/XPC primer pages を確認してください。

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc（open-source XPC sniffer）は、connections の列挙や traffic の観察に役立ち、multi-sender setup と timing の検証に利用できます。例: `gxpc -p <PID> --whitelist <service-name>`。
- libxpc に対する Classic dyld interposing: `xpc_connection_send_message*` と `xpc_connection_get_audit_token` に interpose して、black-box testing 中の call site と stack をログに記録します。



## References

- [1] [Sector 7 – 全員が一度に話さないように！Audit Token Spoofing による macOS の Privileges Elevation](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – macOS Ventura 13.4 の security content について（CVE‑2023‑32405）](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
