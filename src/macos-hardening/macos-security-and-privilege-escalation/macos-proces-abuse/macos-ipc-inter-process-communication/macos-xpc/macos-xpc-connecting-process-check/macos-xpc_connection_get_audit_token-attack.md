# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**詳細については original post を確認してください:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下はその概要です:

## Mach Messages Basic Info

Mach Messages が何か知らない場合は、まずこのページを確認してください:


{{#ref}}
../../
{{#endref}}

ここでは、次の点を覚えておいてください（[こちらの定義](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)より）:\
Mach messages は _mach port_ 上で送信されます。これは mach kernel に組み込まれた **single receiver, multiple sender communication** channel です。**複数の process が mach port に messages を送信できます**が、どの時点でも**そこから読み取れる process は 1 つだけ**です。file descriptors や sockets と同様に、mach ports は kernel によって割り当て・管理され、process からは integer としてのみ見えます。この integer を使って、使用したい mach ports を kernel に指定できます。

## XPC Connection

XPC connection がどのように確立されるか知らない場合は、こちらを確認してください:


{{#ref}}
../
{{#endref}}

## Vuln Summary

知っておくべき重要な点は、**XPC の abstraction は one-to-one connection である**一方、**multiple senders を持つ可能性がある technology の上に構築されているため、次のようになることです:**

- Mach ports は single receiver、**multiple sender** です。
- XPC connection の audit token は、**最後に受信した message からコピーされた audit token** です。
- XPC connection の **audit token** を取得することは、多くの **security checks** にとって重要です。<sup>[1]</sup>

この状況は有望に聞こえますが、問題を引き起こさないシナリオもあります（[こちら](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)より）:

- Audit tokens は、connection を受け入れるかどうかを決定する authorization check によく使用されます。この処理は service port への message を使って行われるため、**connection はまだ確立されていません**。この port 上の追加 messages は、追加の connection requests として処理されるだけです。そのため、**connection を受け入れる前の checks は脆弱ではありません**（これは `-listener:shouldAcceptNewConnection:` 内では audit token が安全であることも意味します）。したがって、**specific actions を検証する XPC connections** を探すことになります。
- XPC event handlers は同期的に処理されます。つまり、concurrent dispatch queues 上であっても、次の message の処理を開始する前に、ある message の event handler を完了する必要があります。そのため、**XPC event handler 内では、audit token が他の通常の（reply ではない）messages によって上書きされることはありません**。<sup>[1]</sup>

これが exploitable になる可能性のある 2 つの異なる methods:

1. Variant1:
- **Exploit** は service **A** と service **B** に **connect** します。
- Service **B** は、user が実行できない **privileged functionality** を service A で呼び出せます。
- Service **A** は、connection の **`dispatch_async`** 用 **event handler** の _**外部**_ で **`xpc_connection_get_audit_token`** を呼び出します。
- そのため、別の message が **Audit Token** を **overwrite** できる可能性があります。これは event handler の外部で非同期に dispatch されているためです。
- Exploit は **service A への SEND right** を **service B** に渡します。
- そのため、svc **B** が実際に **service A** へ **messages** を **sending** することになります。
- **Exploit** は **privileged action** の呼び出しを試みます。RC では、**svc B が Audit token を overwrite している間に**、svc **A** がこの **action** の authorization を **checks** するため、exploit が privileged action を呼び出せるようになります。
2. Variant 2:
- Service **B** は、user が実行できない **privileged functionality** を service A で呼び出せます。
- Exploit は **service A** に connect し、service A は exploit に、特定の **replay** **port** で response を期待する message を送信します。
- Exploit は、その **reply port** を渡す message を **service** B に送信します。
- Service **B** が reply すると、**exploit** が別の **message を service A に送信している間に**、その message を **service A に s**ends** します。exploit は privileged functionality に到達しようとし、service B からの reply が最適なタイミングで Audit token を overwrite することを期待します（Race Condition）。

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- 接続可能な 2 つの mach services **`A`** と **`B`**（sandbox profile と connection を受け入れる前の authorization checks に基づく）。
- _**A**_ には、**authorization check** が必要です。これは、**B** は通過できますが、こちらの app は通過できない specific action に対するものです。
- 例えば、B が何らかの **entitlements** を持っている、または **root** として実行されている場合、A に privileged action の実行を要求できる可能性があります。
- この authorization check のため、**A** は audit token を非同期で取得します。例えば、`dispatch_async` から `xpc_connection_get_audit_token` を呼び出します。

> [!CAUTION]
> この場合、attacker は **Race Condition** を trigger し、**exploit** が A に action の実行を複数回要求する一方で、**B に `A` への messages を送信させる**ことができます。RC が **successful** になると、**B** の **audit token** が memory にコピーされ、こちらの **exploit** の request が A によって **handled** されている間に参照されるため、B だけが要求できる privileged action への **access** が得られます。

これは **`A`** が `smd`、**`B`** が `diagnosticd` の場合に発生しました。smb の [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function を使用すると、新しい privileged helper toot を（**root** として）install できます。**root として実行されている process が** **smd に contact** すると、他の checks は実行されません。

したがって、service **B** は **`diagnosticd`** です。これは root として実行され、process の **monitor** に使用できるため、monitoring が開始されると **1 秒あたり複数の messages を送信します。**

Attack を実行するには:

1. Standard XPC protocol を使用して、`smd` という名前の service への **connection** を開始します。
2. `diagnosticd` への secondary **connection** を確立します。通常の手順とは異なり、2 つの新しい mach ports を作成して送信する代わりに、client port send right を `smd` connection に関連付けられた **send right** の duplicate に置き換えます。
3. その結果、XPC messages は `diagnosticd` に dispatch できますが、`diagnosticd` からの responses は `smd` に reroute されます。`smd` から見ると、user と `diagnosticd` の両方からの messages が同じ connection から送信されているように見えます。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 次の step では、選択した process（user 自身の process でも可能）の monitoring を開始するよう `diagnosticd` に指示します。同時に、通常の 1004 messages を `smd` に大量送信します。ここでの目的は、elevated privileges を持つ tool を install することです。
5. この action により、`handle_bless` function 内で race condition が発生します。タイミングが重要です。`xpc_connection_get_pid` function call は user の process の PID を返す必要があります（privileged tool が user の app bundle に存在するため）。一方、`connection_is_authorized` subroutine 内の `xpc_connection_get_audit_token` function は、`diagnosticd` に属する audit token を参照する必要があります。<sup>[1]</sup>

## Variant 2: reply forwarding

XPC（Cross-Process Communication）environment では、event handlers は concurrent に実行されませんが、reply messages の handling には独自の挙動があります。具体的には、reply を期待する messages の送信方法が 2 つあります:

1. **`xpc_connection_send_message_with_reply`**: ここでは、XPC message は指定された queue 上で受信・処理されます。
2. **`xpc_connection_send_message_with_reply_sync`**: 一方、この method では、XPC message は current dispatch queue 上で受信・処理されます。

この違いは重要です。reply packets が、XPC event handler の execution と concurrent に parse される可能性が生じるためです。特に、`_xpc_connection_set_creds` は audit token の partial overwrite を保護するための locking を実装していますが、この保護は connection object 全体には及びません。その結果、packet の parsing と event handler の execution の間に audit token を replace できる vulnerability が発生します。

この vulnerability を exploit するには、次の setup が必要です:

- **`A`** および **`B`** と呼ばれる 2 つの mach services。どちらも connection を確立できます。
- Service **`A`** には、**`B`** だけが実行できる specific action（user の application は実行できない）に対する authorization check が必要です。
- Service **`A`** は reply を予期する message を送信する必要があります。
- User は **`B`** に message を送信でき、B はそれに response します。

Exploitation process は次の steps で構成されます:

1. Service **`A`** が reply を期待する message を送信するまで待ちます。
2. **`A`** に直接 reply する代わりに、reply port を hijack し、service **`B`** に message を送信するために使用します。
3. その後、forbidden action を含む message を dispatch します。この message が **`B`** からの reply と concurrent に処理されることを期待します。<sup>[1]</sup>

以下は、説明した attack scenario の visual representation です:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances の locating における difficulties**: `xpc_connection_get_audit_token` の usage instances を、static と dynamic の両方で検索するのは困難でした。
- **Methodology**: Frida を使用して `xpc_connection_get_audit_token` function を hook し、event handlers から発生していない calls を filter しました。しかし、この method は hooked process に限定され、active usage も必要でした。
- **Analysis Tooling**: IDA/Ghidra などの tools を、reachable mach services の調査に使用しましたが、処理には時間がかかりました。また、dyld shared cache を伴う calls により複雑になりました。
- **Scripting Limitations**: `dispatch_async` blocks からの `xpc_connection_get_audit_token` calls を script で分析する試みは、blocks の parsing と dyld shared cache との interactions が複雑なため妨げられました。<sup>[1]</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd` 内で発見された general および specific issues の詳細を Apple に report しました。
- **Apple's Response**: Apple は `xpc_connection_get_audit_token` を `xpc_dictionary_get_audit_token` に置き換えることで、`smd` の issue に対処しました。<sup>[1][2]</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function は、受信した XPC message に紐付けられた mach message から audit token を直接取得するため、secure と考えられています。ただし、`xpc_connection_get_audit_token` と同様に public API の一部ではありません。
- **Absence of a Broader Fix**: connection に保存された audit token と一致しない messages を discard するなど、より comprehensive な fix を Apple が実装しなかった理由は不明です。特定の scenarios（`setuid` usage など）では audit token の正当な変更が発生する可能性があり、それが要因かもしれません。
- **Current Status**: この issue は iOS 17 と macOS 14 にも残っており、特定して理解しようとする人々にとって challenge となっています。<sup>[1]</sup>

## Finding vulnerable code paths in practice (2024–2025)

この bug class について XPC services を audit する場合は、message の event handler の外部、または reply processing と concurrent に実行される authorization に注目してください。

Static triage hints:
- `dispatch_async`/`dispatch_after` 経由で queue された blocks、または message handler の外部で実行される他の worker queues から到達可能な `xpc_connection_get_audit_token` calls を検索します。
- per-connection state と per-message state を混在させる authorization helpers を探します（例: `xpc_connection_get_pid` から PID を取得し、`xpc_connection_get_audit_token` から audit token を取得する）。
- NSXPC code では、checks が `-listener:shouldAcceptNewConnection:` で実行されているか確認します。per-message checks については、implementation が per-message audit token を使用しているか確認します（例: lower-level code で message の dictionary を介して `xpc_dictionary_get_audit_token` を使用する）。

Dynamic triage tips:
- `xpc_connection_get_audit_token` を hook し、user stack に event-delivery path（例: `_xpc_connection_mach_event`）が含まれていない invocations に flag を付けます。Example Frida hook:
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
注記:
- macOS では、protected/Apple binaries の instrumenting に SIP の無効化または development environment が必要になる場合があります。自分で build したもの、または userland services のテストを優先してください。
- reply-forwarding races (Variant 2) では、`xpc_connection_send_message_with_reply` と通常のリクエストのタイミングを fuzzing しながら、reply packets の concurrent parsing を監視し、authorization で使用される effective audit token に影響を与えられるか確認してください。

## 必要になる可能性が高い Exploitation primitives

- Multi-sender setup (Variant 1): A と B への connections を作成し、A の client port の send right を duplicate して B の client port として使用します。これにより、B の replies が A に delivery されます。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A の pending request（reply port）から send-once right を取得し、その reply port を使って B に crafted message を送信します。これにより、privileged request が解析されている間に、B の reply が A に到達します。

これらには、XPC bootstrap と message formats のための低レベルな mach message crafting が必要です。正確な packet layouts と flags については、このセクションの mach/XPC primer pages を確認してください。

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc（open-source XPC sniffer）は、connections の列挙や traffic の観察に役立ち、multi-sender setups と timing の検証に利用できます。例: `gxpc -p <PID> --whitelist <service-name>`。
- libxpc 用の Classic dyld interposing: `xpc_connection_send_message*` と `xpc_connection_get_audit_token` に interpose して、black-box testing 中の call sites と stacks をログに記録します。



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
