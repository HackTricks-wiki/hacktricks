# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Weitere Informationen finden Sie im Originalbeitrag:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dies ist eine Zusammenfassung:

## Grundlegende Informationen zu Mach Messages

Wenn Sie nicht wissen, was Mach Messages sind, beginnen Sie mit dieser Seite:


{{#ref}}
../../
{{#endref}}

Merken Sie sich zunächst Folgendes ([Definition von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages werden über einen _mach port_ gesendet, einen in den mach kernel integrierten Kommunikationskanal mit **einem Empfänger und mehreren Sendern**. **Mehrere Prozesse können messages** an einen mach port senden, aber zu jedem Zeitpunkt kann **nur ein einzelner Prozess daraus lesen**. Wie file descriptors und sockets werden mach ports vom kernel zugewiesen und verwaltet. Prozesse sehen lediglich eine Ganzzahl, mit der sie dem kernel angeben können, welchen ihrer mach ports sie verwenden möchten.

## XPC Connection

Wenn Sie nicht wissen, wie eine XPC connection hergestellt wird, sehen Sie hier nach:


{{#ref}}
../
{{#endref}}

## Zusammenfassung der Vulnerability

Wichtig ist, dass **XPCs Abstraktion eine Eins-zu-eins-Verbindung** darstellt, jedoch auf einer Technologie basiert, die **mehrere Sender haben kann. Daher gilt:**

- Mach ports haben einen einzelnen Empfänger und **mehrere Sender**.
- Das Audit token einer XPC connection ist das Audit token, das aus der **zuletzt empfangenen message kopiert** wurde.
- Das Abrufen des **Audit tokens** einer XPC connection ist für viele **Security checks** entscheidend.<sup>[1]</sup>

Obwohl die vorherige Situation vielversprechend klingt, gibt es einige Szenarien, in denen sie keine Probleme verursachen wird ([von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens werden häufig für einen Authorization check verwendet, um zu entscheiden, ob eine connection akzeptiert werden soll. Da dies über eine message an den service port geschieht, wurde **noch keine connection hergestellt**. Weitere messages an diesen port werden lediglich als zusätzliche connection requests behandelt. Daher sind **Checks vor dem Akzeptieren einer connection nicht vulnerable** (das bedeutet auch, dass das Audit token innerhalb von `-listener:shouldAcceptNewConnection:` sicher ist). Wir **suchen daher nach XPC connections, die bestimmte Aktionen überprüfen**.
- XPC event handlers werden synchron verarbeitet. Das bedeutet, dass der event handler für eine message abgeschlossen sein muss, bevor er für die nächste message aufgerufen wird, selbst bei concurrent dispatch queues. Daher kann das Audit token **innerhalb eines XPC event handlers nicht** durch andere normale (nicht reply!) messages überschrieben werden.<sup>[1]</sup>

Dies könnte auf zwei verschiedene Arten exploitable sein:

1. Variant1:
- Der **Exploit** **verbindet** sich mit service **A** und service **B**.
- Service **B** kann eine **privileged functionality** in service A aufrufen, die der Benutzer nicht aufrufen kann.
- Service **A** ruft **`xpc_connection_get_audit_token`** auf, während es sich _**nicht**_ im **event handler** für eine connection innerhalb eines **`dispatch_async`** befindet.
- Daher könnte eine **andere** message das **Audit Token** überschreiben, da sie außerhalb des event handlers asynchron verarbeitet wird.
- Der Exploit übergibt **service B das SEND-Recht für service A**.
- Dadurch wird svc **B** tatsächlich die **messages** an service **A** **senden**.
- Der **Exploit** versucht, die **privileged action** aufzurufen. In einer RC **überprüft** svc **A** die Authorization dieser **action**, während **svc B das Audit token überschrieben hat** (wodurch der Exploit Zugriff auf die privileged action erhält).
2. Variant 2:
- Service **B** kann eine **privileged functionality** in service A aufrufen, die der Benutzer nicht aufrufen kann.
- Der Exploit verbindet sich mit **service A**, der dem Exploit eine **message sendet, die eine Antwort erwartet**, und zwar an einen bestimmten **reply**-**port**.
- Der Exploit sendet service B eine message, die **diesen reply port** übergibt.
- Wenn service **B antwortet**, **sendet es die message an service A**, während der **Exploit eine andere message an service A sendet**, um eine privileged functionality zu erreichen, und darauf setzt, dass die Antwort von service B das Audit token im richtigen Moment überschreibt (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Szenario:

- Zwei mach services **`A`** und **`B`**, mit denen wir uns beide verbinden können (abhängig vom sandbox profile und den Authorization checks vor dem Akzeptieren der connection).
- _**A**_ muss über einen **Authorization check** für eine bestimmte action verfügen, den **`B`** bestehen kann (unsere App jedoch nicht).
- Wenn B beispielsweise über bestimmte **entitlements** verfügt oder als **root** ausgeführt wird, kann es A möglicherweise auffordern, eine privileged action auszuführen.
- Für diesen Authorization check ruft **`A`** das Audit token asynchron ab, beispielsweise durch den Aufruf von `xpc_connection_get_audit_token` aus `dispatch_async`.

> [!CAUTION]
> In diesem Fall könnte ein Angreifer eine **Race Condition** auslösen, indem er einen **Exploit** erstellt, der A mehrmals auffordert, eine action auszuführen, während **B messages an `A` sendet**. Wenn die RC **erfolgreich** ist, wird das **Audit token** von **B** in den Speicher kopiert, während die Anfrage unseres **Exploits** von A verarbeitet wird. Dadurch erhält der Exploit Zugriff auf die privileged action, die nur B anfordern konnte.

Dies geschah mit **`A`** als `smd` und **`B`** als `diagnosticd`. Die Funktion [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) aus smb kann verwendet werden, um ein neues privileged helper tool (als **root**) zu installieren. Wenn ein **als root ausgeführter Prozess `smd` kontaktiert**, werden keine weiteren Checks durchgeführt.

Daher ist service **B** **`diagnosticd`**, da es als **root** ausgeführt wird und zum **Überwachen** eines Prozesses verwendet werden kann. Sobald die Überwachung gestartet wurde, wird es **mehrere messages pro Sekunde senden**.

So wird der Angriff ausgeführt:

1. Stellen Sie über das standardmäßige XPC protocol eine **connection** zum service namens `smd` her.
2. Stellen Sie eine zweite **connection** zu `diagnosticd` her. Anders als beim normalen Verfahren werden nicht zwei neue mach ports erstellt und gesendet. Stattdessen wird der client port send right durch ein Duplikat des mit der `smd` connection verbundenen **send right** ersetzt.
3. Dadurch können XPC messages an `diagnosticd` gesendet werden, Antworten von `diagnosticd` werden jedoch an `smd` umgeleitet. Für `smd` sieht es so aus, als würden die messages sowohl des Benutzers als auch von `diagnosticd` aus derselben connection stammen.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Im nächsten Schritt wird `diagnosticd` angewiesen, die Überwachung eines ausgewählten Prozesses zu starten (möglicherweise des eigenen Prozesses des Benutzers). Gleichzeitig wird eine Flut routinemäßiger 1004-messages an `smd` gesendet. Ziel ist die Installation eines Tools mit erhöhten Privilegien.
5. Diese action löst eine Race Condition innerhalb der Funktion `handle_bless` aus. Das Timing ist entscheidend: Der Aufruf der Funktion `xpc_connection_get_pid` muss die PID des Prozesses des Benutzers zurückgeben (da sich das privileged tool im app bundle des Benutzers befindet). Die Funktion `xpc_connection_get_audit_token`, insbesondere innerhalb der Subroutine `connection_is_authorized`, muss jedoch auf das Audit token von `diagnosticd` verweisen.<sup>[1]</sup>

## Variant 2: reply forwarding

In einer XPC-Umgebung (Cross-Process Communication) werden event handlers zwar nicht gleichzeitig ausgeführt, die Verarbeitung von reply messages weist jedoch ein besonderes Verhalten auf. Es gibt insbesondere zwei verschiedene Methoden zum Senden von messages, die eine Antwort erwarten:

1. **`xpc_connection_send_message_with_reply`**: Hier wird die XPC message empfangen und auf einer bestimmten queue verarbeitet.
2. **`xpc_connection_send_message_with_reply_sync`**: Bei dieser Methode wird die XPC message dagegen auf der aktuellen dispatch queue empfangen und verarbeitet.

Diese Unterscheidung ist entscheidend, da sie ermöglicht, dass **reply packets gleichzeitig mit der Ausführung eines XPC event handlers geparst werden**. Zwar implementiert `_xpc_connection_set_creds` ein Locking, um das teilweise Überschreiben des Audit tokens zu verhindern, doch dieser Schutz erstreckt sich nicht auf das gesamte connection object. Dadurch entsteht eine Vulnerability, bei der das Audit token in dem Zeitraum zwischen dem Parsen eines packets und der Ausführung seines event handlers ersetzt werden kann.

Um diese Vulnerability auszunutzen, ist folgende Konfiguration erforderlich:

- Zwei mach services, bezeichnet als **`A`** und **`B`**, die beide eine connection herstellen können.
- Service **`A`** sollte einen Authorization check für eine bestimmte action enthalten, die nur **`B`** ausführen kann (die App des Benutzers jedoch nicht).
- Service **`A`** sollte eine message senden, die eine Antwort erwartet.
- Der Benutzer kann eine message an **`B`** senden, auf die B antworten wird.

Der Exploit läuft in folgenden Schritten ab:

1. Warten Sie, bis service **`A`** eine message sendet, die eine Antwort erwartet.
2. Anstatt direkt an **`A`** zu antworten, wird der reply port übernommen und zum Senden einer message an service **`B`** verwendet.
3. Anschließend wird eine message mit der verbotenen action gesendet, in der Erwartung, dass sie gleichzeitig mit der Antwort von **`B`** verarbeitet wird.<sup>[1]</sup>

Nachfolgend ist eine visuelle Darstellung des beschriebenen Angriffsszenarios:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Probleme bei der Entdeckung

- **Schwierigkeiten beim Auffinden von Instanzen**: Das Suchen nach Verwendungen von `xpc_connection_get_audit_token` war sowohl statisch als auch dynamisch schwierig.
- **Methodik**: Frida wurde verwendet, um die Funktion `xpc_connection_get_audit_token` zu hooken und Aufrufe herauszufiltern, die nicht aus event handlers stammen. Diese Methode war jedoch auf den gehookten Prozess beschränkt und erforderte eine aktive Nutzung.
- **Analysis Tooling**: Tools wie IDA/Ghidra wurden zur Untersuchung erreichbarer mach services verwendet. Der Prozess war jedoch zeitaufwendig und wurde durch Aufrufe erschwert, die den dyld shared cache betrafen.
- **Einschränkungen beim Scripting**: Versuche, die Analyse für Aufrufe von `xpc_connection_get_audit_token` aus `dispatch_async`-Blöcken zu skripten, wurden durch die Komplexität beim Parsen von Blöcken und durch Interaktionen mit dem dyld shared cache behindert.<sup>[1]</sup>

## Der Fix <a href="#the-fix" id="the-fix"></a>

- **Gemeldete Issues**: Apple wurde ein Report mit einer Beschreibung der allgemeinen und spezifischen Issues in `smd` übermittelt.
- **Antwort von Apple**: Apple behob das Problem in `smd`, indem `xpc_connection_get_audit_token` durch `xpc_dictionary_get_audit_token` ersetzt wurde.<sup>[1][2]</sup>
- **Art des Fixes**: Die Funktion `xpc_dictionary_get_audit_token` gilt als sicher, da sie das Audit token direkt aus der mit der empfangenen XPC message verbundenen mach message abruft. Sie ist jedoch ebenso wie `xpc_connection_get_audit_token` nicht Teil der öffentlichen API.
- **Fehlender umfassenderer Fix**: Es bleibt unklar, warum Apple keinen umfassenderen Fix implementiert hat, beispielsweise das Verwerfen von messages, die nicht mit dem gespeicherten Audit token der connection übereinstimmen. Die Möglichkeit legitimer Änderungen des Audit tokens in bestimmten Szenarien (z. B. bei der Verwendung von `setuid`) könnte ein Faktor sein.
- **Aktueller Status**: Das Problem besteht in iOS 17 und macOS 14 weiterhin und stellt eine Herausforderung für diejenigen dar, die es identifizieren und verstehen möchten.<sup>[1]</sup>

## Finding vulnerable code paths in practice (2024–2025)

Bei der Prüfung von XPC services auf diese Bug-Klasse sollten Sie sich auf Authorization konzentrieren, die außerhalb des event handlers der message oder gleichzeitig mit der reply-Verarbeitung durchgeführt wird.

Hinweise zur statischen Triage:
- Suchen Sie nach Aufrufen von `xpc_connection_get_audit_token`, die von Blöcken aus erreichbar sind, die über `dispatch_async`/`dispatch_after` oder andere worker queues eingereiht werden und außerhalb des message handlers ausgeführt werden.
- Suchen Sie nach Authorization helpers, die den Zustand pro connection und pro message vermischen (z. B. die PID über `xpc_connection_get_pid`, das Audit token jedoch über `xpc_connection_get_audit_token` abrufen).
- Prüfen Sie bei NSXPC-Code, ob die Checks in `-listener:shouldAcceptNewConnection:` durchgeführt werden oder ob die Implementierung bei Checks pro message ein Audit token pro message verwendet (z. B. das dictionary der message über `xpc_dictionary_get_audit_token` in lower-level code).

Hinweise zur dynamischen Triage:
- Hooken Sie `xpc_connection_get_audit_token` und markieren Sie Aufrufe, deren user stack nicht den event-delivery-Pfad enthält (z. B. `_xpc_connection_mach_event`). Beispiel für einen Frida hook:
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
Hinweise:
- Unter macOS kann das Instrumentieren geschützter/Apple-Binaries ein deaktiviertes SIP oder eine Entwicklungsumgebung erfordern. Bevorzugt sollten eigene Builds oder Userland-Services getestet werden.
- Für Reply-forwarding-Races (Variant 2) sollte die gleichzeitige Verarbeitung von Reply-Paketen überwacht werden, indem die Zeitabläufe von `xpc_connection_send_message_with_reply` gegenüber normalen Requests per Fuzzing variiert werden. Anschließend sollte geprüft werden, ob der bei der Autorisierung verwendete effektive Audit-Token beeinflusst werden kann.

## Exploitation primitives, die du wahrscheinlich benötigen wirst

- Multi-sender setup (Variant 1): Verbindungen zu A und B erstellen; das Send-Recht des Client-Ports von A duplizieren und es als Client-Port von B verwenden, sodass die Replies von B an A zugestellt werden.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): Das send-once-Recht aus A’s ausstehender Anfrage (Reply-Port) abfangen und anschließend eine manipulierte Nachricht an B über diesen Reply-Port senden, sodass B’s Antwort bei A landet, während deine privilegierte Anfrage geparst wird.

Dafür ist das Erstellen von Mach-Nachrichten auf niedriger Ebene für die XPC-bootstrap- und Nachrichtenformate erforderlich. Siehe die Mach/XPC-Primer-Seiten in diesem Abschnitt für die exakten Packet-Layouts und Flags.

## Nützliche Tools

- XPC-Sniffing/dynamische Inspektion: gxpc (Open-Source-XPC-Sniffer) kann dabei helfen, Verbindungen aufzulisten und den Traffic zu beobachten, um Setups mit mehreren Sendern und das Timing zu validieren. Beispiel: `gxpc -p <PID> --whitelist <service-name>`.
- Klassisches dyld-Interposing für libxpc: Interpose auf `xpc_connection_send_message*` und `xpc_connection_get_audit_token`, um Call-Sites und Stacks während Black-Box-Tests zu protokollieren.



## Referenzen

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
