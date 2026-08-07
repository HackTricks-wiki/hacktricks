# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Weitere Informationen findest du im Originalbeitrag:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dies ist eine Zusammenfassung:<sup>[[1]](#references)</sup>

## Grundlegende Informationen zu Mach Messages

Wenn du nicht weißt, was Mach Messages sind, sieh dir zunächst diese Seite an:


{{#ref}}
../../
{{#endref}}

Merke dir zunächst Folgendes ([Definition von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages werden über einen _mach port_ gesendet. Dabei handelt es sich um einen in den Mach-Kernel integrierten Kommunikationskanal mit **einem Empfänger und mehreren Sendern**. **Mehrere Prozesse können Nachrichten an einen Mach port senden**, aber zu jedem Zeitpunkt **kann nur ein einzelner Prozess daraus lesen**. Wie bei File Descriptors und Sockets werden Mach ports vom Kernel angelegt und verwaltet. Prozesse sehen lediglich eine Ganzzahl, mit der sie dem Kernel angeben können, welchen ihrer Mach ports sie verwenden möchten.

## XPC Connection

Wenn du nicht weißt, wie eine XPC connection aufgebaut wird, sieh dir Folgendes an:


{{#ref}}
../
{{#endref}}

## Zusammenfassung der Schwachstelle

Wichtig ist, dass **die Abstraktion von XPC eine Eins-zu-eins-Verbindung darstellt**, aber auf einer Technologie basiert, die **mehrere Sender zulassen kann. Daher gilt:**

- Mach ports haben einen einzelnen Empfänger und **mehrere Sender**.
- Das Audit Token einer XPC connection ist das Audit Token, das aus der **zuletzt empfangenen Nachricht kopiert** wurde.
- Das Abrufen des **Audit Tokens** einer XPC connection ist für viele **Security Checks** entscheidend.<sup>[[1]](#references)</sup>

Obwohl die vorherige Situation vielversprechend klingt, gibt es einige Szenarien, in denen sie keine Probleme verursachen wird ([von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit Tokens werden häufig für einen Authorization Check verwendet, um zu entscheiden, ob eine connection akzeptiert werden soll. Da dies über eine Nachricht an den Service-Port geschieht, wurde **noch keine connection hergestellt**. Weitere Nachrichten an diesen Port werden lediglich als zusätzliche Verbindungsanfragen behandelt. Daher sind **Checks vor dem Akzeptieren einer connection nicht verwundbar** (das bedeutet auch, dass das Audit Token innerhalb von `-listener:shouldAcceptNewConnection:` sicher ist). Wir **suchen daher nach XPC connections, die bestimmte Aktionen überprüfen**.
- XPC event handlers werden synchron verarbeitet. Das bedeutet, dass der event handler für eine Nachricht abgeschlossen sein muss, bevor er für die nächste Nachricht aufgerufen wird, selbst bei concurrent dispatch queues. Innerhalb eines **XPC event handlers kann das Audit Token daher nicht** durch andere normale Nachrichten (keine Reply-Nachrichten!) überschrieben werden.<sup>[[1]](#references)</sup>

Es gibt zwei unterschiedliche Methoden, wie dies ausgenutzt werden könnte:

1. Variante 1:
- Der **Exploit** **verbindet** sich mit Service **A** und Service **B**.
- Service **B** kann eine **privilegierte Funktionalität** in Service A aufrufen, die der Benutzer nicht aufrufen kann.
- Service **A** ruft **`xpc_connection_get_audit_token`** auf, während es sich **nicht** innerhalb des **event handlers** für eine connection in einem **`dispatch_async`** befindet.
- Daher könnte eine **andere** Nachricht das **Audit Token überschreiben**, weil sie außerhalb des event handlers asynchron verarbeitet wird.
- Der Exploit übergibt **Service B das SEND-Recht für Service A**.
- Dadurch wird svc **B** tatsächlich die **Nachrichten** an Service **A** **senden**.
- Der **Exploit** versucht, die **privilegierte Aktion aufzurufen**. Bei einer Race Condition **überprüft** svc **A** die Berechtigung für diese **Aktion**, während **svc B das Audit Token überschrieben hat** (wodurch der Exploit Zugriff auf die privilegierte Aktion erhält).
2. Variante 2:
- Service **B** kann eine **privilegierte Funktionalität** in Service A aufrufen, die der Benutzer nicht aufrufen kann.
- Der Exploit verbindet sich mit **Service A**, der dem Exploit eine **Nachricht sendet, die eine Antwort auf einem bestimmten Replay-Port erwartet**.
- Der Exploit sendet Service **B** eine Nachricht und übergibt diesen **Reply-Port**.
- Wenn Service **B** antwortet, **sendet** es die Nachricht an Service **A**, **während** der **Exploit** eine andere **Nachricht an Service A** sendet, um eine privilegierte Funktionalität zu erreichen. Dabei wird darauf gehofft, dass die Antwort von Service B das Audit Token im richtigen Moment überschreibt (Race Condition).

## Variante 1: Aufruf von xpc_connection_get_audit_token außerhalb eines event handlers <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Szenario:

- Zwei Mach-Services **`A`** und **`B`**, mit denen wir uns beide verbinden können (abhängig vom Sandbox-Profil und den Authorization Checks vor dem Akzeptieren der connection).
- _**A**_ muss einen **Authorization Check** für eine bestimmte Aktion besitzen, den **B** passieren kann, unsere App jedoch nicht.
- Wenn B beispielsweise bestimmte **Entitlements** besitzt oder als **root** läuft, könnte es ihm erlaubt sein, A aufzufordern, eine privilegierte Aktion auszuführen.
- Für diesen Authorization Check ruft **A** das Audit Token asynchron ab, beispielsweise durch den Aufruf von `xpc_connection_get_audit_token` aus `dispatch_async`.

> [!CAUTION]
> In diesem Fall könnte ein Angreifer eine **Race Condition** auslösen und einen **Exploit** erstellen, der A mehrmals auffordert, eine Aktion auszuführen, während **B Nachrichten an `A` sendet**. Wenn die RC **erfolgreich** ist, wird das **Audit Token** von **B** in den Speicher kopiert, während die Anfrage unseres **Exploits** von A verarbeitet wird. Dadurch erhält der Exploit Zugriff auf die privilegierte Aktion, die nur B anfordern könnte.

Dies geschah mit **`A`** als `smd` und **`B`** als `diagnosticd`. Die Funktion [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) aus smb kann verwendet werden, um ein neues privilegiertes Helper-Tool als **root** zu installieren. Wenn ein **als root laufender Prozess `smd` kontaktiert**, werden keine weiteren Checks durchgeführt.

Daher ist Service **B** **`diagnosticd`**, da es als **root** läuft und zum **Überwachen** eines Prozesses verwendet werden kann. Sobald die Überwachung gestartet wurde, **sendet es mehrere Nachrichten pro Sekunde**.

So wird der Angriff durchgeführt:

1. Eine **Connection** zum Service namens `smd` über das standardmäßige XPC-Protokoll initiieren.
2. Eine sekundäre **Connection** zu `diagnosticd` herstellen. Entgegen dem normalen Vorgehen werden nicht zwei neue Mach ports erstellt und gesendet. Stattdessen wird der Client-Port-Send-Right durch ein Duplikat des **Send-Rights** ersetzt, das mit der `smd`-Connection verbunden ist.
3. Dadurch können XPC-Nachrichten an `diagnosticd` weitergeleitet werden, Antworten von `diagnosticd` werden jedoch zu `smd` umgeleitet. Für `smd` sieht es so aus, als würden die Nachrichten sowohl des Benutzers als auch von `diagnosticd` aus derselben Connection stammen.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Im nächsten Schritt wird `diagnosticd` angewiesen, die Überwachung eines ausgewählten Prozesses zu starten (möglicherweise des Prozesses des Benutzers selbst). Gleichzeitig wird eine Flut gewöhnlicher 1004-Nachrichten an `smd` gesendet. Ziel ist es, ein Tool mit erhöhten Rechten zu installieren.
5. Diese Aktion löst eine Race Condition innerhalb der Funktion `handle_bless` aus. Das Timing ist entscheidend: Der Aufruf der Funktion `xpc_connection_get_pid` muss die PID des Benutzerprozesses zurückgeben (da sich das privilegierte Tool im App Bundle des Benutzers befindet). Der Aufruf der Funktion `xpc_connection_get_audit_token`, insbesondere innerhalb der Subroutine `connection_is_authorized`, muss jedoch auf das Audit Token von `diagnosticd` verweisen.<sup>[[1]](#references)</sup>

## Variante 2: Weiterleitung von Replies

In einer XPC-Umgebung werden event handlers zwar nicht gleichzeitig ausgeführt, die Verarbeitung von Reply-Nachrichten weist jedoch ein besonderes Verhalten auf. Konkret gibt es zwei unterschiedliche Methoden zum Senden von Nachrichten, die eine Antwort erwarten:

1. **`xpc_connection_send_message_with_reply`**: Hier wird die XPC-Nachricht in einer bestimmten Queue empfangen und verarbeitet.
2. **`xpc_connection_send_message_with_reply_sync`**: Bei dieser Methode wird die XPC-Nachricht dagegen in der aktuellen Dispatch-Queue empfangen und verarbeitet.

Dieser Unterschied ist entscheidend, da dadurch **Reply-Pakete gleichzeitig mit der Ausführung eines XPC event handlers geparst werden können**. Obwohl `_xpc_connection_set_creds` Locking implementiert, um das teilweise Überschreiben des Audit Tokens zu verhindern, erstreckt sich dieser Schutz nicht auf das gesamte Connection-Objekt. Dadurch entsteht eine Schwachstelle, bei der das Audit Token in dem Zeitraum zwischen dem Parsen eines Pakets und der Ausführung seines event handlers ersetzt werden kann.

Für die Ausnutzung dieser Schwachstelle ist folgende Konfiguration erforderlich:

- Zwei Mach-Services namens **`A`** und **`B`**, mit denen jeweils eine connection hergestellt werden kann.
- Service **`A`** sollte einen Authorization Check für eine bestimmte Aktion enthalten, die nur **`B`** ausführen kann (die Anwendung des Benutzers jedoch nicht).
- Service **`A`** sollte eine Nachricht senden, die eine Antwort erwartet.
- Der Benutzer muss eine Nachricht an **`B`** senden können, auf die B antworten wird.

Der Exploit läuft in folgenden Schritten ab:

1. Warten, bis Service **`A`** eine Nachricht sendet, die eine Antwort erwartet.
2. Statt direkt an **`A`** zu antworten, wird der Reply-Port übernommen und verwendet, um eine Nachricht an Service **`B`** zu senden.
3. Anschließend wird eine Nachricht mit der nicht erlaubten Aktion gesendet. Dabei wird erwartet, dass sie gleichzeitig mit der Antwort von **`B`** verarbeitet wird.<sup>[[1]](#references)</sup>

Nachfolgend ist eine visuelle Darstellung des beschriebenen Angriffsszenarios:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Probleme bei der Entdeckung

- **Schwierigkeiten beim Auffinden von Instanzen**: Das Suchen nach Verwendungen von `xpc_connection_get_audit_token` war sowohl statisch als auch dynamisch schwierig.
- **Methodik**: Frida wurde verwendet, um die Funktion `xpc_connection_get_audit_token` zu hooken und Aufrufe herauszufiltern, die nicht aus event handlers stammen. Diese Methode war jedoch auf den gehookten Prozess beschränkt und erforderte eine aktive Nutzung.
- **Analyse-Tools**: Tools wie IDA/Ghidra wurden zur Untersuchung erreichbarer Mach-Services verwendet. Der Prozess war jedoch zeitaufwendig und wurde durch Aufrufe erschwert, die den dyld shared cache einbezogen.
- **Einschränkungen beim Scripting**: Versuche, die Analyse für Aufrufe von `xpc_connection_get_audit_token` aus `dispatch_async`-Blöcken zu skripten, wurden durch die Komplexität beim Parsen von Blöcken und die Interaktion mit dem dyld shared cache behindert.<sup>[[1]](#references)</sup>

## Der Fix <a href="#the-fix" id="the-fix"></a>

- **Gemeldete Probleme**: Apple wurde ein Report mit einer Beschreibung der allgemeinen und der spezifischen in `smd` gefundenen Probleme übermittelt.
- **Antwort von Apple**: Apple behob das Problem in `smd`, indem `xpc_connection_get_audit_token` durch `xpc_dictionary_get_audit_token` ersetzt wurde.<sup>[[1]](#references)[[2]](#references)</sup>
- **Art des Fixes**: Die Funktion `xpc_dictionary_get_audit_token` gilt als sicher, da sie das Audit Token direkt aus der Mach Message abruft, die mit der empfangenen XPC-Nachricht verbunden ist. Sie ist jedoch, ebenso wie `xpc_connection_get_audit_token`, nicht Teil der öffentlichen API.
- **Kein umfassenderer Fix**: Es bleibt unklar, warum Apple keinen umfassenderen Fix implementiert hat, beispielsweise das Verwerfen von Nachrichten, die nicht mit dem gespeicherten Audit Token der Connection übereinstimmen. Die Möglichkeit legitimer Änderungen des Audit Tokens in bestimmten Szenarien (z. B. bei der Verwendung von `setuid`) könnte dabei eine Rolle spielen.
- **Aktueller Status**: Das Problem besteht in iOS 17 und macOS 14 weiterhin und stellt eine Herausforderung für diejenigen dar, die es identifizieren und verstehen möchten.<sup>[[1]](#references)</sup>

## Verwundbare Codepfade in der Praxis finden (2024–2025)

Bei der Prüfung von XPC-Services auf diese Bug-Klasse solltest du dich auf Authorization konzentrieren, die außerhalb des event handlers der Nachricht oder gleichzeitig mit der Reply-Verarbeitung durchgeführt wird.

Hinweise zur statischen Triage:
- Suche nach Aufrufen von `xpc_connection_get_audit_token`, die aus Blöcken erreichbar sind, die über `dispatch_async`/`dispatch_after` oder andere Worker-Queues eingereiht werden und außerhalb des Message Handlers ausgeführt werden.
- Suche nach Authorization-Helpern, die per-connection- und per-message-Status vermischen (z. B. die PID über `xpc_connection_get_pid`, das Audit Token jedoch über `xpc_connection_get_audit_token` abrufen).
- Überprüfe bei NSXPC-Code, dass die Checks in `-listener:shouldAcceptNewConnection:` erfolgen oder dass die Implementierung bei per-message Checks ein per-message Audit Token verwendet (z. B. das Dictionary der Nachricht über `xpc_dictionary_get_audit_token` in Code auf niedrigerer Ebene).

Hinweise zur dynamischen Triage:
- Hooke `xpc_connection_get_audit_token` und markiere Aufrufe, deren User-Stack nicht den Event-Delivery-Pfad enthält (z. B. `_xpc_connection_mach_event`). Beispiel für einen Frida-Hook:
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
- Unter macOS kann das Instrumentieren geschützter/Apple-Binaries deaktiviertes SIP oder eine Entwicklungsumgebung erfordern; bevorzuge Tests mit eigenen Builds oder Userland-Services.
- Für Reply-Forwarding-Races (Variante 2) überwache die gleichzeitige Verarbeitung von Reply-Paketen, indem du die Timings von `xpc_connection_send_message_with_reply` gegenüber normalen Requests fuzzst und überprüfst, ob der bei der Autorisierung verwendete effektive Audit-Token beeinflusst werden kann.

## Exploitation-Primitives, die du wahrscheinlich benötigen wirst

- Multi-Sender-Setup (Variante 1): Erstelle Verbindungen zu A und B; dupliziere das Senderecht des Client-Ports von A und verwende es als Client-Port von B, sodass die Replies von B an A zugestellt werden.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): Das send-once right aus A’s ausstehender Anfrage (reply port) abfangen und anschließend eine präparierte Nachricht an B über diesen reply port senden, sodass B’s Antwort bei A eintrifft, während deine privilegierte Anfrage geparst wird.

Dafür ist das Erstellen von Mach-Nachrichten auf niedriger Ebene für das XPC-bootstrap und die Nachrichtenformate erforderlich. Lies die Mach/XPC-Primer-Seiten in diesem Abschnitt, um die exakten Paketlayouts und Flags zu prüfen.

## Nützliche Tools

- XPC-Sniffing/dynamische Inspektion: gxpc (open-source XPC sniffer) kann dabei helfen, Verbindungen aufzulisten und den Datenverkehr zu beobachten, um Setups mit mehreren Sendern und das Timing zu überprüfen. Beispiel: `gxpc -p <PID> --whitelist <service-name>`.
- Klassisches dyld interposing für libxpc: Interpose auf `xpc_connection_send_message*` und `xpc_connection_get_audit_token`, um Call-Sites und Stacks während Black-Box-Tests zu protokollieren.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
