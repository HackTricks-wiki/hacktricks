# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**詳細については、原著を確認してください:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下はその概要です:

## Mach Messages Basic Info

Mach Messagesについて知らない場合は、まず次のページを確認してください:


{{#ref}}
../../
{{#endref}}

ここでは、次の点を覚えておいてください（[こちらの定義](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)より）:\
Mach messagesは、mach kernelに組み込まれた**single receiver, multiple sender communication** channelである_mach port_を介して送信されます。**複数のprocessがmach portにmessagesを送信できます**が、どの時点でも**そこから読み取れるprocessは1つだけ**です。file descriptorsやsocketsと同様に、mach portsはkernelによって割り当ておよび管理され、processからはintegerとしてのみ見えます。processはこのintegerを使用して、使用したいmach portsをkernelに示します。

## XPC Connection

XPC connectionの確立方法を知らない場合は、次を確認してください:


{{#ref}}
../
{{#endref}}

## Vuln Summary

ここで重要なのは、**XPCの抽象化はone-to-one connection**ですが、**multiple sendersを持つ可能性のあるtechnologyの上に構築されている**という点です。つまり:

- Mach portsはsingle receiver、**multiple sender**です。
- XPC connectionのaudit tokenは、**最後に受信したmessageからコピーされたaudit token**です。
- XPC connectionの**audit token**の取得は、多くの**security checks**にとって重要です。<sup>[[1]](#references)</sup>

この状況は有望に見えますが、問題を引き起こさないシナリオもあります（[こちらより](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）:

- Audit tokensは、connectionを受け入れるかどうかを決定するauthorization checkによく使用されます。この処理はservice portへのmessageを使用して行われるため、**この時点ではconnectionはまだ確立されていません**。このport上の追加のmessagesは、追加のconnection requestsとして処理されるだけです。そのため、**connectionを受け入れる前のchecksはvulnerableではありません**（つまり、`-listener:shouldAcceptNewConnection:`内のaudit tokenは安全です）。したがって、**specific actionsを検証するXPC connections**を探す必要があります。
- XPC event handlersはsynchronously処理されます。つまり、concurrent dispatch queues上であっても、あるmessageのevent handlerは次のmessageのhandlerが呼び出される前に完了しなければなりません。そのため、**XPC event handler内では、audit tokenが他の通常の（replyではない）messagesによって上書きされることはありません**。<sup>[[1]](#references)</sup>

これがexploit可能になる方法は2つあります:

1. Variant1:
- **Exploit**がservice **A**とservice **B**に**connect**する。
- Service **B**は、userには実行できない**privileged functionality**をservice Aで呼び出せる。
- Service **A**は、connectionの**event handler**内ではない状態で、**`dispatch_async`**から**`xpc_connection_get_audit_token`**を呼び出す。
- そのため、**different message**が**Audit Tokenを上書き**できる。これはevent handlerの外部でasynchronously dispatchされるためである。
- Exploitは、**service AへのSEND right**を**service Bに渡す**。
- これにより、svc **B**が実際に**service Aへ** **messages**を**送信**する。
- **Exploit**は**privileged action**を呼び出そうとする。RCのタイミングで、svc **A**が**svc BによってAudit tokenが上書きされている間**にこの**actionのauthorizationをcheck**すると、exploitにprivileged actionへのアクセスが与えられる。
2. Variant 2:
- Service **B**は、userには実行できない**privileged functionality**をservice Aで呼び出せる。
- Exploitは**service A**にconnectし、service Aはexploitに、特定の**reply** portでresponseを期待する**message**を送信する。
- Exploitは、その**reply port**を渡すmessageをservice Bに送信する。
- Service **B**がreplyすると、そのmessageをservice Aに**送信**する。一方、**exploit**はprivileged functionalityに到達しようとしてservice Aに別の**message**を送信し、service Bからのreplyが適切なタイミングでAudit tokenを上書きすることを期待する（Race Condition）。

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- 接続可能な2つのmach services、**`A`**と**`B`**（sandbox profileおよびconnectionを受け入れる前のauthorization checksに基づく）。
- _**A**_には、**specific action**に対する**authorization check**があり、**`B`**はそれをpassできるが、our appはpassできない。
- 例えば、Bが何らかの**entitlements**を持っている、または`root`として実行されている場合、Aにprivileged actionの実行を要求できる。
- このauthorization checkのために、**`A`**はaudit tokenをasynchronously取得する。例えば、`dispatch_async`から`xpc_connection_get_audit_token`を呼び出す。

> [!CAUTION]
> この場合、attackerは**Race Condition**をtriggerできる。つまり、**exploit**がAにactionの実行を何度も要求する一方で、**Bに`A`へmessagesを送信させる**。RCが**成功**すると、**B**の**audit token**がmemoryにコピーされ、その間にAがour **exploit**のrequestを処理するため、Bだけがrequestできるprivilege actionへのアクセスが得られる。

これは、**`A`**が`smd`で、**`B`**が`diagnosticd`だった場合に発生しました。smbの[`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) functionを使用すると、新しいprivileged helper tootを（**root**として）installできます。**rootとして実行されているprocessが** **smdにcontact**すると、他のchecksは実行されません。

したがって、service **B**は**`diagnosticd`**です。これは`root`として実行され、processの**monitor**に使用できるため、monitoringが開始されると、**1秒あたり複数のmessagesを送信**します。

Attackを実行するには:

1. 標準のXPC protocolを使用して、`smd`という名前のserviceへの**connection**を開始します。
2. `diagnosticd`へのsecondary **connection**を確立します。通常の手順とは異なり、2つの新しいmach portsを作成して送信するのではなく、client port send rightを、`smd` connectionに関連付けられた**send right**のduplicateに置き換えます。
3. その結果、XPC messagesは`diagnosticd`へdispatchできますが、`diagnosticd`からのresponsesは`smd`へrerouteされます。`smd`から見ると、userと`diagnosticd`の両方からのmessagesが同じconnectionから送信されているように見えます。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 次のstepでは、選択したprocess（user自身のprocessでもよい）のmonitoringを開始するよう`diagnosticd`に指示します。同時に、通常の1004 messagesを`smd`へ大量に送信します。ここでの目的は、elevated privilegesを持つtoolをinstallすることです。
5. このactionにより、`handle_bless` function内でrace conditionがtriggerされます。タイミングが重要です。`xpc_connection_get_pid` function callはuserのprocessのPIDを返す必要があります（privileged toolがuserのapp bundle内にあるためです）。しかし、`connection_is_authorized` subroutine内の`xpc_connection_get_audit_token` functionは、`diagnosticd`に属するaudit tokenを参照する必要があります。<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

XPC（Cross-Process Communication）environmentでは、event handlersはconcurrently実行されませんが、reply messagesのhandlingには独自の動作があります。具体的には、replyを期待するmessagesを送信する方法が2つあります:

1. **`xpc_connection_send_message_with_reply`**: この場合、XPC messageは指定されたqueue上で受信および処理されます。
2. **`xpc_connection_send_message_with_reply_sync`**: 一方、このmethodでは、XPC messageはcurrent dispatch queue上で受信および処理されます。

この違いは重要です。reply packetsがXPC event handlerの実行とconcurrentlyにparseされる可能性があるためです。特に、`_xpc_connection_set_creds`はaudit tokenのpartial overwriteを防ぐためのlockingを実装していますが、この保護はconnection object全体には及びません。そのため、packetのparsingとevent handlerの実行の間にaudit tokenを置き換えられるvulnerabilityが発生します。

このvulnerabilityをexploitするには、次のsetupが必要です:

- どちらもconnectionを確立できる、**`A`**および**`B`**と呼ばれる2つのmach services。
- Service **`A`**には、userのapplicationでは実行できず、**`B`**だけが実行できるspecific actionに対するauthorization checkがある。
- Service **`A`**はreplyを予期するmessageを送信する。
- Userは、responseを返す**`B`**にmessageを送信できる。

Exploitation processは次のとおりです:

1. Service **`A`**がreplyを期待するmessageを送信するまで待機します。
2. **`A`**に直接replyする代わりに、reply portをhijackし、それを使用してservice **`B`**にmessageを送信します。
3. 次に、forbidden actionを含むmessageをdispatchします。このmessageが**`B`**からのreplyとconcurrentlyに処理されることを期待します。<sup>[[1]](#references)</sup>

以下は、説明したattack scenarioのvisual representationです:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instancesの発見の難しさ**: `xpc_connection_get_audit_token`のusage instancesを、staticにもdynamicにも探すのは困難でした。
- **Methodology**: Fridaを使用して`xpc_connection_get_audit_token` functionをhookし、event handlersから発生していないcallsをfilterしました。しかし、このmethodはhookしたprocessに限定され、active usageも必要でした。
- **Analysis Tooling**: IDA/Ghidraなどのtoolsを使用してreachable mach servicesを調査しましたが、dyld shared cacheに関係するcallsによってさらに複雑になり、processには時間がかかりました。
- **Scripting Limitations**: `dispatch_async` blocksからの`xpc_connection_get_audit_token` callsをscriptで分析しようとしましたが、blocksのparsingおよびdyld shared cacheとのinteractionが複雑なため妨げられました。<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd`内で発見されたgeneralおよびspecific issuesについて、Appleにreportを提出しました。
- **Apple's Response**: Appleは`smd`内のissueに対処するため、`xpc_connection_get_audit_token`を`xpc_dictionary_get_audit_token`に置き換えました。<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` functionは、received XPC messageに関連付けられたmach messageからaudit tokenを直接取得するため、secureと考えられています。ただし、`xpc_connection_get_audit_token`と同様にpublic APIの一部ではありません。
- **Absence of a Broader Fix**: connectionに保存されたaudit tokenと一致しないmessagesをdiscardするなど、よりcomprehensiveなfixをAppleが実装しなかった理由は不明です。特定のscenario（`setuid`の使用など）では正当なaudit token changesが発生する可能性があり、それが要因かもしれません。
- **Current Status**: このissueはiOS 17およびmacOS 14でも継続しており、これを特定して理解しようとする人にとってchallengeとなっています。<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

このbug classについてXPC servicesをauditする場合は、messageのevent handler外部で実行されるauthorization、またはreply processingとconcurrentlyに実行されるauthorizationに注目してください。

Static triage hints:
- `dispatch_async`/`dispatch_after`またはmessage handler外部で実行される他のworker queues経由でqueueされたblocksから到達可能な、`xpc_connection_get_audit_token`へのcallsを検索します。
- per-connection stateとper-message stateを混在させるauthorization helpersを探します（例: `xpc_connection_get_pid`からPIDを取得し、`xpc_connection_get_audit_token`からaudit tokenを取得する）。
- NSXPC codeでは、checksが`-listener:shouldAcceptNewConnection:`で実行されていることを確認します。per-message checksの場合は、implementationがper-message audit tokenを使用していることを確認します（例: lower-level codeでmessageのdictionary経由で`xpc_dictionary_get_audit_token`を使用する）。

Dynamic triage tips:
- `xpc_connection_get_audit_token`をhookし、user stackにevent-delivery path（例: `_xpc_connection_mach_event`）が含まれていないinvocationsをflagします。Frida hookの例:
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
- macOS では、保護された/Apple バイナリの instrumenting に SIP の無効化または development environment が必要になる場合があります。自身の build または userland services でのテストを優先してください。
- reply-forwarding races（Variant 2）では、`xpc_connection_send_message_with_reply` と通常のリクエストのタイミングを fuzzing し、reply packets の concurrent parsing を監視します。そのうえで、authorization で使用される effective audit token に影響を与えられるか確認してください。

## Exploitation primitives you will likely need

- Multi-sender setup（Variant 1）: A と B への connections を作成し、A の client port の send right を duplicate して B の client port として使用します。これにより、B の replies が A に delivery されます。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A の pending request（reply port）から send-once right を捕捉し、その reply port を使って B に crafted message を送信することで、privileged request の解析中に B の reply を A に到達させる。

これらには、XPC bootstrap と message formats のための low-level mach message crafting が必要です。正確な packet layouts と flags については、このセクションの mach/XPC primer pages を確認してください。

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc（open-source XPC sniffer）は、connections の列挙や traffic の観測に役立ち、multi-sender setups と timing の検証に使用できます。例: `gxpc -p <PID> --whitelist <service-name>`。
- Classic dyld interposing for libxpc: `xpc_connection_send_message*` と `xpc_connection_get_audit_token` に interpose して、black-box testing 中の call sites と stacks をログに記録します。



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
