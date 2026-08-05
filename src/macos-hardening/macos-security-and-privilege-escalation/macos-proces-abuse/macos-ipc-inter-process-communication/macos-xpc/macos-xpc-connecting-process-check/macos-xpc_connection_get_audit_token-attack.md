# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Weitere Informationen finden Sie im Originalbeitrag:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dies ist eine Zusammenfassung:

## Grundlegende Informationen zu Mach Messages

Wenn Sie nicht wissen, was Mach Messages sind, beginnen Sie mit dieser Seite:


{{#ref}}
../../
{{#endref}}

Merken Sie sich zunächst Folgendes ([Definition von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages werden über einen _mach port_ gesendet. Dabei handelt es sich um einen in den Mach-Kernel integrierten Kommunikationskanal mit **einem Empfänger und mehreren Sendern**. **Mehrere Prozesse können Nachrichten** an einen mach port senden, aber zu jedem Zeitpunkt kann **nur ein einzelner Prozess daraus lesen**. Genau wie file descriptors und sockets werden mach ports vom Kernel angelegt und verwaltet. Prozesse sehen lediglich eine Ganzzahl, mit der sie dem Kernel angeben können, welchen ihrer mach ports sie verwenden möchten.

## XPC Connection

Wenn Sie nicht wissen, wie eine XPC connection hergestellt wird, lesen Sie:


{{#ref}}
../
{{#endref}}

## Zusammenfassung der Schwachstelle

Wichtig ist, dass **die Abstraktion von XPC eine Eins-zu-eins-Verbindung darstellt**, jedoch auf einer Technologie basiert, die **mehrere Sender haben kann. Daher gilt:**

- Mach ports haben einen einzelnen Empfänger und **mehrere Sender**.
- Das Audit token einer XPC connection ist das Audit token, das **aus der zuletzt empfangenen Nachricht kopiert wurde**.
- Das Abrufen des **Audit tokens** einer XPC connection ist für viele **Security checks** entscheidend.<sup>[[1]](#references)</sup>

Obwohl die vorherige Situation vielversprechend klingt, gibt es einige Szenarien, in denen sie keine Probleme verursachen wird ([von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens werden häufig für einen Authorization check verwendet, um zu entscheiden, ob eine Connection akzeptiert werden soll. Da dies mithilfe einer Nachricht an den Service-Port geschieht, wurde **noch keine Connection hergestellt**. Weitere Nachrichten an diesen Port werden lediglich als zusätzliche Connection requests behandelt. Daher sind **Checks vor dem Akzeptieren einer Connection nicht verwundbar** (das bedeutet auch, dass das Audit token innerhalb von `-listener:shouldAcceptNewConnection:` sicher ist). Wir **suchen daher nach XPC connections, die bestimmte Aktionen überprüfen**.
- XPC event handlers werden synchron verarbeitet. Das bedeutet, dass der event handler für eine Nachricht abgeschlossen sein muss, bevor er für die nächste Nachricht aufgerufen wird, selbst bei concurrent dispatch queues. Daher kann das Audit token **innerhalb eines XPC event handlers nicht** durch andere normale (nicht als Antwort gesendete) Nachrichten **überschrieben werden**.<sup>[[1]](#references)</sup>

Es gibt zwei verschiedene Methoden, mit denen dies möglicherweise ausgenutzt werden kann:

1. Variante 1:
- **Exploit** **verbindet sich** mit Service **A** und Service **B**.
- Service **B** kann eine **privilegierte Funktionalität** in Service A aufrufen, die der Benutzer nicht aufrufen kann.
- Service **A** ruft **`xpc_connection_get_audit_token`** auf, während es sich _**nicht**_ innerhalb des **event handlers** für eine Connection in einem **`dispatch_async`** befindet.
- Daher könnte eine **andere** Nachricht das Audit Token **überschreiben**, da sie außerhalb des event handlers asynchron verarbeitet wird.
- Der Exploit übergibt **Service B das SEND-Recht für Service A**.
- Dadurch wird svc **B** tatsächlich die **Nachrichten** an Service **A** **senden**.
- Der **Exploit** versucht, die **privilegierte Aktion** aufzurufen. In einer Race Condition überprüft svc **A** die Berechtigung für diese **Aktion**, während **svc B das Audit token überschrieben hat** (wodurch der Exploit Zugriff auf den Aufruf der privilegierten Aktion erhält).
2. Variante 2:
- Service **B** kann eine **privilegierte Funktionalität** in Service A aufrufen, die der Benutzer nicht aufrufen kann.
- Der Exploit verbindet sich mit **Service A**, das dem Exploit eine **Nachricht sendet, die eine Antwort erwartet**, und zwar über einen bestimmten **reply**-Port.
- Der Exploit sendet Service **B** eine Nachricht, die **diesen reply port** übergibt.
- Wenn Service **B** antwortet, **sendet es die Nachricht an Service A**, während der **Exploit** eine andere **Nachricht an Service A** sendet, um eine privilegierte Funktionalität zu erreichen, wobei erwartet wird, dass die Antwort von Service B das Audit token im richtigen Moment überschreibt (Race Condition).

## Variante 1: Aufruf von xpc_connection_get_audit_token außerhalb eines event handlers <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Szenario:

- Zwei Mach services **`A`** und **`B`**, mit denen wir uns beide verbinden können (abhängig vom Sandbox-Profil und den Authorization checks vor dem Akzeptieren der Connection).
- _**A**_ muss einen **Authorization check** für eine bestimmte Aktion besitzen, den **B** passieren kann (unsere App jedoch nicht).
- Wenn B beispielsweise über bestimmte **Entitlements** verfügt oder als **root** ausgeführt wird, kann der Dienst ihm erlauben, A zur Ausführung einer privilegierten Aktion aufzufordern.
- Für diesen Authorization check ruft **A** das Audit token asynchron ab, beispielsweise durch den Aufruf von `xpc_connection_get_audit_token` aus `dispatch_async`.

> [!CAUTION]
> In diesem Fall könnte ein Angreifer eine **Race Condition** auslösen und einen **Exploit** erstellen, der **A mehrmals auffordert, eine Aktion auszuführen**, während **B Nachrichten an `A` sendet**. Wenn die RC **erfolgreich** ist, wird das **Audit token** von **B** in den Speicher kopiert, **während** die Anfrage des **Exploits** von A verarbeitet wird. Dadurch erhält er **Zugriff auf die privilegierte Aktion, die nur B anfordern konnte**.

Dies geschah mit **`A`** als `smd` und **`B`** als `diagnosticd`. Die Funktion [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) aus smb kann verwendet werden, um ein neues privilegiertes Helper-Tool (als **root**) zu installieren. Wenn ein **als root ausgeführter Prozess `smd` kontaktiert**, werden keine weiteren Checks durchgeführt.

Daher ist Service **B** **`diagnosticd`**, da er als **root** ausgeführt wird und zur **Überwachung** eines Prozesses verwendet werden kann. Sobald die Überwachung gestartet wurde, wird er **mehrere Nachrichten pro Sekunde senden**.

So wird der Angriff durchgeführt:

1. Stellen Sie mithilfe des standardmäßigen XPC-Protokolls eine **Connection** zum Service namens `smd` her.
2. Stellen Sie eine sekundäre **Connection** zu `diagnosticd` her. Entgegen dem normalen Verfahren werden nicht zwei neue mach ports erstellt und gesendet. Stattdessen wird der Client-Port-Senderecht durch ein Duplikat des mit der `smd`-Connection verbundenen **Senderechts** ersetzt.
3. Dadurch können XPC messages an `diagnosticd` gesendet werden, Antworten von `diagnosticd` werden jedoch zu `smd` umgeleitet. Für `smd` sieht es so aus, als würden die Nachrichten sowohl vom Benutzer als auch von `diagnosticd` aus derselben Connection stammen.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Im nächsten Schritt wird `diagnosticd` angewiesen, die Überwachung eines ausgewählten Prozesses zu starten, möglicherweise des eigenen Prozesses des Benutzers. Gleichzeitig wird eine Flut routinemäßiger 1004-Nachrichten an `smd` gesendet. Ziel ist es, ein Tool mit erhöhten Privilegien zu installieren.
5. Diese Aktion löst eine Race Condition innerhalb der Funktion `handle_bless` aus. Das Timing ist entscheidend: Der Aufruf der Funktion `xpc_connection_get_pid` muss die PID des Prozesses des Benutzers zurückgeben (da sich das privilegierte Tool im App-Bundle des Benutzers befindet). Die Funktion `xpc_connection_get_audit_token`, speziell innerhalb der Subroutine `connection_is_authorized`, muss jedoch auf das Audit token von `diagnosticd` verweisen.<sup>[[1]](#references)</sup>

## Variante 2: Weiterleitung von Antworten

In einer XPC-Umgebung werden event handlers zwar nicht gleichzeitig ausgeführt, die Verarbeitung von reply messages weist jedoch ein besonderes Verhalten auf. Insbesondere gibt es zwei verschiedene Methoden zum Senden von Nachrichten, die eine Antwort erwarten:

1. **`xpc_connection_send_message_with_reply`**: Hier wird die XPC message in einer dafür vorgesehenen Queue empfangen und verarbeitet.
2. **`xpc_connection_send_message_with_reply_sync`**: Bei dieser Methode wird die XPC message dagegen in der aktuellen dispatch queue empfangen und verarbeitet.

Diese Unterscheidung ist entscheidend, da sie die Möglichkeit eröffnet, dass **reply packets gleichzeitig mit der Ausführung eines XPC event handlers geparst werden**. Während `_xpc_connection_set_creds` zwar Locking implementiert, um das teilweise Überschreiben des Audit tokens zu verhindern, erstreckt sich dieser Schutz nicht auf das gesamte Connection-Objekt. Dadurch entsteht eine Schwachstelle, bei der das Audit token in dem Zeitraum zwischen dem Parsen eines Pakets und der Ausführung seines event handlers ersetzt werden kann.

Um diese Schwachstelle auszunutzen, ist folgende Konfiguration erforderlich:

- Zwei Mach services, die als **`A`** und **`B`** bezeichnet werden und beide eine Connection herstellen können.
- Service **`A`** sollte einen Authorization check für eine bestimmte Aktion enthalten, die nur **`B`** ausführen kann (die App des Benutzers jedoch nicht).
- Service **`A`** sollte eine Nachricht senden, die eine Antwort erwartet.
- Der Benutzer kann eine Nachricht an **`B`** senden, auf die dieser antwortet.

Der Exploit läuft in folgenden Schritten ab:

1. Warten Sie, bis Service **`A`** eine Nachricht sendet, die eine Antwort erwartet.
2. Anstatt direkt an **`A`** zu antworten, wird der reply port übernommen und verwendet, um eine Nachricht an Service **`B`** zu senden.
3. Anschließend wird eine Nachricht mit der verbotenen Aktion gesendet, wobei erwartet wird, dass sie gleichzeitig mit der Antwort von **`B`** verarbeitet wird.<sup>[[1]](#references)</sup>

Nachfolgend ist eine visuelle Darstellung des beschriebenen Angriffsszenarios:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Probleme bei der Entdeckung

- **Schwierigkeiten beim Auffinden von Instanzen**: Das Suchen nach Verwendungen von `xpc_connection_get_audit_token` war sowohl statisch als auch dynamisch schwierig.
- **Methodik**: Frida wurde verwendet, um die Funktion `xpc_connection_get_audit_token` zu hooken und Aufrufe herauszufiltern, die nicht aus event handlers stammen. Diese Methode war jedoch auf den gehookten Prozess beschränkt und erforderte eine aktive Nutzung.
- **Analysis Tooling**: Tools wie IDA/Ghidra wurden zur Untersuchung erreichbarer Mach services verwendet. Der Prozess war jedoch zeitaufwendig und wurde durch Aufrufe erschwert, die den dyld shared cache betrafen.
- **Einschränkungen beim Scripting**: Versuche, die Analyse für Aufrufe von `xpc_connection_get_audit_token` aus `dispatch_async`-Blöcken zu skripten, wurden durch die Komplexität beim Parsen von Blöcken und durch Interaktionen mit dem dyld shared cache behindert.<sup>[[1]](#references)</sup>

## Der Fix <a href="#the-fix" id="the-fix"></a>

- **Gemeldete Probleme**: Apple wurde ein Bericht mit einer Beschreibung der allgemeinen und spezifischen Probleme in `smd` übermittelt.
- **Antwort von Apple**: Apple behob das Problem in `smd`, indem `xpc_connection_get_audit_token` durch `xpc_dictionary_get_audit_token` ersetzt wurde.<sup>[[1]](#references)[[2]](#references)</sup>
- **Art des Fixes**: Die Funktion `xpc_dictionary_get_audit_token` gilt als sicher, da sie das Audit token direkt aus der Mach message abruft, die mit der empfangenen XPC message verbunden ist. Sie ist jedoch ebenso wie `xpc_connection_get_audit_token` nicht Teil der public API.
- **Fehlen eines umfassenderen Fixes**: Es bleibt unklar, warum Apple keinen umfassenderen Fix implementiert hat, etwa das Verwerfen von Nachrichten, die nicht mit dem gespeicherten Audit token der Connection übereinstimmen. Möglicherweise spielen legitime Änderungen des Audit tokens in bestimmten Szenarien, beispielsweise bei der Verwendung von `setuid`, eine Rolle.
- **Aktueller Status**: Das Problem besteht in iOS 17 und macOS 14 weiterhin und stellt eine Herausforderung für alle dar, die es identifizieren und verstehen möchten.<sup>[[1]](#references)</sup>

## Verwundbare Codepfade in der Praxis finden (2024–2025)

Bei der Prüfung von XPC services auf diese Bug-Klasse sollten Sie sich auf Authorization konzentrieren, die außerhalb des event handlers der Nachricht oder gleichzeitig mit der Verarbeitung von Antworten erfolgt.

Hinweise zur statischen Triage:
- Suchen Sie nach Aufrufen von `xpc_connection_get_audit_token`, die aus Blöcken erreichbar sind, die über `dispatch_async`/`dispatch_after` oder andere Worker-Queues eingeplant werden und außerhalb des Message handlers ausgeführt werden.
- Suchen Sie nach Authorization helpers, die zustandsbezogene Daten pro Connection und pro Message vermischen (z. B. die PID über `xpc_connection_get_pid`, das Audit token jedoch über `xpc_connection_get_audit_token` abrufen).
- Prüfen Sie in NSXPC-Code, ob die Checks in `-listener:shouldAcceptNewConnection:` durchgeführt werden oder ob die Implementierung bei Checks pro Nachricht ein Audit token pro Nachricht verwendet (z. B. das Dictionary der Nachricht über `xpc_dictionary_get_audit_token` in Code auf niedrigerer Ebene).

Hinweise zur dynamischen Triage:
- Hooken Sie `xpc_connection_get_audit_token` und markieren Sie Aufrufe, deren User-Stack nicht den Pfad der Event-Zustellung enthält (z. B. `_xpc_connection_mach_event`). Beispiel für einen Frida-Hook:
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
- Bei Reply-Forwarding-Races (Variant 2) überwache die nebenläufige Analyse von Reply-Paketen, indem du die Zeitabläufe von `xpc_connection_send_message_with_reply` gegenüber normalen Requests fuzzst und prüfst, ob das bei der Autorisierung verwendete effektive Audit-Token beeinflusst werden kann.

## Exploitation primitives, die du wahrscheinlich benötigen wirst

- Multi-Sender-Setup (Variant 1): Erstelle Verbindungen zu A und B; dupliziere das Send Right des Client-Ports von A und verwende es als Client-Port von B, sodass die Replies von B an A zugestellt werden.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): Erfasse das send-once right aus A's ausstehender Anfrage (reply port), und sende anschließend eine präparierte Nachricht an B unter Verwendung dieses reply port, sodass Bs Antwort bei A landet, während deine privilegierte Anfrage geparst wird.

Dafür ist das Erstellen von Mach-Nachrichten auf niedriger Ebene für die XPC-bootstrap- und Nachrichtenformate erforderlich. Siehe die Mach/XPC-Primer-Seiten in diesem Abschnitt für die genauen Paketlayouts und Flags.

## Nützliche Tools

- XPC-Sniffing/dynamische Inspektion: gxpc (Open-Source-XPC-sniffer) kann dabei helfen, Verbindungen aufzulisten und Datenverkehr zu beobachten, um Setups mit mehreren Sendern und das Timing zu validieren. Beispiel: `gxpc -p <PID> --whitelist <service-name>`.
- Klassisches dyld interposing für libxpc: Interpose auf `xpc_connection_send_message*` und `xpc_connection_get_audit_token`, um während Black-Box-Tests Aufrufstellen und Stacks zu protokollieren.



## Referenzen

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
