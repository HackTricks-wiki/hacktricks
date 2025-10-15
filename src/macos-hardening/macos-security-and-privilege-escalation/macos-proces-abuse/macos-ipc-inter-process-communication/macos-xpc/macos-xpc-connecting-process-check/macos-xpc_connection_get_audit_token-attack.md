# macOS xpc_connection_get_audit_token Angriff

{{#include ../../../../../../banners/hacktricks-training.md}}

**Für weitere Informationen sieh dir den Originalbeitrag an:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dies ist eine Zusammenfassung:

## Mach Messages - Grundlegende Informationen

Wenn du nicht weißt, was Mach Messages sind, sieh dir diese Seite an:


{{#ref}}
../../
{{#endref}}

Merke vorerst ([Definition von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages werden über einen _mach port_ gesendet, einem im mach kernel eingebetteten Kommunikationskanal mit **einem Empfänger, mehreren Sendern**. **Mehrere Prozesse können Nachrichten** an einen mach port senden, aber zu jedem Zeitpunkt **kann nur ein einziger Prozess daraus lesen**. Genau wie file descriptors und sockets werden mach ports vom Kernel alloziert und verwaltet, und Prozesse sehen nur eine Ganzzahl, die sie dem Kernel übergeben können, um anzugeben, welchen ihrer mach ports sie verwenden möchten.

## XPC Connection

Wenn du nicht weißt, wie eine XPC connection hergestellt wird, siehe:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Wichtig ist: Die XPC-Abstraktion ist eine One-to-One-Verbindung, basiert aber auf einer Technologie, die **mehrere Sender** erlauben kann. Daher:

- Mach ports sind Single-Receiver, **Multiple Sender**.
- Das Audit-Token einer XPC connection ist das Audit-Token, das **aus der zuletzt empfangenen Nachricht kopiert** wurde.
- Das Erhalten des **Audit-Tokens** einer XPC connection ist für viele **Sicherheitsprüfungen** kritisch.

Obwohl das vielversprechend klingt, gibt es Szenarien, in denen dies kein Problem verursacht ([Quelle](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit-Tokens werden oft für eine Autorisierungsprüfung verwendet, um zu entscheiden, ob eine Verbindung akzeptiert wird. Da dies mit einer Nachricht an den Service-Port geschieht, ist **noch keine Verbindung etabliert**. Weitere Nachrichten auf diesem Port werden einfach als zusätzliche Verbindungsanfragen behandelt. Daher sind **Prüfungen vor dem Akzeptieren einer Verbindung nicht verwundbar** (das bedeutet auch, dass innerhalb von `-listener:shouldAcceptNewConnection:` das Audit-Token sicher ist). Wir suchen also **nach XPC-Verbindungen, die spezifische Aktionen prüfen**.
- XPC Event-Handler werden synchron behandelt. Das bedeutet, der Event-Handler für eine Nachricht muss abgeschlossen sein, bevor er für die nächste Nachricht aufgerufen wird, selbst bei concurrent dispatch queues. Innerhalb eines **XPC event handler** kann das Audit-Token also **nicht** von anderen normalen (nicht-reply!) Nachrichten überschrieben werden.

Zwei verschiedene Methoden, wie das ausnutzbar sein könnte:

1. Variant1:
- Der **Exploit** **connectet** zu Service **A** und Service **B**.
- Service **B** kann eine **privilegierte Funktionalität** in Service A aufrufen, die der User nicht kann.
- Service **A** ruft **`xpc_connection_get_audit_token`** auf, **während es _nicht_ im Event-Handler** für eine Verbindung und **in einem `dispatch_async`** ist.
- Daher könnte eine **andere** Nachricht das Audit-Token **überschreiben**, weil sie asynchron außerhalb des Event-Handlers ausgeführt wird.
- Der Exploit übergibt **svc B das SEND right zu svc A**.
- Also wird svc **B** tatsächlich die **Nachrichten** an svc **A** **senden**.
- Der **Exploit** versucht die **privilegierte Aktion** aufzurufen. In einem RC prüft svc **A** die Autorisierung dieser **Aktion**, während **svc B das Audit-Token überschrieben hat** (was dem Exploit den Zugriff auf die privilegierte Aktion ermöglicht).
2. Variant 2:
- Service **B** kann eine **privilegierte Funktionalität** in Service A aufrufen, die der User nicht kann.
- Der Exploit verbindet sich mit **Service A**, welcher dem Exploit eine **Nachricht sendet, die eine Antwort erwartet** in einem spezifischen **reply port**.
- Der Exploit sendet **Service B** eine Nachricht und übergibt **diesen reply port**.
- Wenn Service **B** antwortet, **sendet es die Nachricht an Service A**, **während** der **Exploit** eine andere **Nachricht an Service A** schickt, die versucht, eine privilegierte Funktionalität aufzurufen und darauf hofft, dass die Antwort von Service B das Audit-Token im perfekten Moment überschreibt (Race Condition).

## Variant 1: Aufruf von xpc_connection_get_audit_token außerhalb eines Event-Handlers <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Szenario:

- Zwei Mach-Services **`A`** und **`B`**, mit denen wir uns verbinden können (basierend auf dem Sandbox-Profil und den Autorisierungsprüfungen vor dem Akzeptieren der Verbindung).
- _**A**_ muss eine **Autorisierungsprüfung** für eine bestimmte Aktion haben, die **`B`** passieren kann (aber unsere App nicht).
- Zum Beispiel, wenn B bestimmte **entitlements** hat oder als **root** läuft, könnte es ihm erlauben, A zu bitten, eine privilegierte Aktion auszuführen.
- Für diese Autorisierungsprüfung erhält **`A`** das Audit-Token asynchron, z. B. durch Aufruf von `xpc_connection_get_audit_token` aus einem **`dispatch_async`**.

> [!CAUTION]
> In diesem Fall könnte ein Angreifer eine **Race Condition** auslösen, indem ein **Exploit** A mehrfach auffordert, eine Aktion auszuführen, während gleichzeitig **B Nachrichten an `A`** sendet. Wenn die RC erfolgreich ist, wird das **Audit-Token** von **B** während der Bearbeitung der Anfrage unseres **Exploit** in A in den Speicher kopiert und erlaubt so den **Zugriff auf die privilegierte Aktion**, die sonst nur B anfordern könnte.

Dies trat mit **`A`** als `smd` und **`B`** als `diagnosticd` auf. Die Funktion [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) aus smb kann verwendet werden, um als root einen neuen privilegierten helper tool zu installieren. Wenn ein **Prozess, der als root läuft,** `smd` kontaktiert, werden keine weiteren Prüfungen durchgeführt.

Daher ist der Service **B** `diagnosticd`, weil er als **root** läuft und verwendet werden kann, um einen Prozess zu überwachen; sobald das Monitoring gestartet ist, wird er **mehrere Nachrichten pro Sekunde** senden.

Um den Angriff durchzuführen:

1. Stelle eine **Verbindung** zum Service `smd` mittels des Standard-XPC-Protokolls her.
2. Erzeuge eine sekundäre **Verbindung** zu `diagnosticd`. Entgegen dem normalen Vorgehen wird das client port send right durch ein Duplikat des **send right** ersetzt, das mit der `smd`-Verbindung assoziiert ist.
3. Dadurch können XPC-Nachrichten an `diagnosticd` gesendet werden, aber Antworten von `diagnosticd` werden an `smd` umgeleitet. Für `smd` sieht es so aus, als kämen die Nachrichten sowohl vom Benutzer als auch von `diagnosticd` aus derselben Verbindung.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Als Nächstes wird `diagnosticd` angewiesen, die Überwachung eines gewählten Prozesses zu starten (möglicherweise des Benutzerprozesses). Gleichzeitig wird ein Fluss routinemäßiger 1004-Nachrichten an `smd` gesendet. Ziel ist es, ein Tool mit erhöhten Rechten zu installieren.
5. Diese Aktion löst eine Race Condition innerhalb der Funktion `handle_bless` aus. Das Timing ist entscheidend: der Aufruf von `xpc_connection_get_pid` muss die PID des Benutzerprozesses zurückgeben (da das privilegierte Tool im Benutzer-App-Bundle liegt). Gleichzeitig muss `xpc_connection_get_audit_token`, speziell innerhalb der Unterroutine `connection_is_authorized`, auf das Audit-Token von `diagnosticd` verweisen.

## Variant 2: reply forwarding

In einer XPC-Umgebung, obwohl Event-Handler nicht gleichzeitig ausgeführt werden, verhält sich die Verarbeitung von Reply-Nachrichten speziell. Es gibt zwei verschiedene Methoden, Nachrichten zu senden, die eine Antwort erwarten:

1. **`xpc_connection_send_message_with_reply`**: Hier wird die XPC-Nachricht auf einer bestimmten Queue empfangen und verarbeitet.
2. **`xpc_connection_send_message_with_reply_sync`**: Bei dieser Methode wird die XPC-Nachricht auf der aktuellen dispatch queue empfangen und verarbeitet.

Diese Unterscheidung ist wichtig, weil sie die Möglichkeit eröffnet, dass **Reply-Pakete gleichzeitig mit der Ausführung eines XPC Event-Handlers geparst werden**. Bemerkenswert ist, dass `_xpc_connection_set_creds` zwar Locking verwendet, um eine partielle Überschreibung des Audit-Tokens zu verhindern, aber diese Schutzmaßnahme nicht auf das gesamte connection-Objekt ausgeweitet wurde. Folglich entsteht eine Verwundbarkeit, bei der das Audit-Token im Zeitraum zwischen dem Parsen eines Pakets und der Ausführung seines Event-Handlers ersetzt werden kann.

Für die Ausnutzung dieser Verwundbarkeit ist folgende Konstellation erforderlich:

- Zwei Mach-Services, genannt **`A`** und **`B`**, zu denen beide Verbindungen aufbauen können.
- Service **`A`** sollte eine Autorisierungsprüfung für eine bestimmte Aktion enthalten, die nur **`B`** ausführen kann (nicht die App des Nutzers).
- Service **`A`** sollte eine Nachricht senden, die eine Antwort erwartet.
- Der Nutzer kann eine Nachricht an **`B`** senden, auf die es antworten wird.

Der Exploit-Ablauf:

1. Warte, bis Service **`A`** eine Nachricht sendet, die eine Antwort erwartet.
2. Anstatt direkt an **`A`** zu antworten, wird der reply port gehijackt und verwendet, um eine Nachricht an Service **`B`** zu senden.
3. Anschließend wird eine Nachricht, die die verbotene Aktion beinhaltet, versendet, in der Erwartung, dass sie gleichzeitig mit der Antwort von **`B`** verarbeitet wird.

Unten ist eine visuelle Darstellung des beschriebenen Angriffszenarios:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Schwierigkeiten beim Auffinden von Instanzen**: Das Auffinden von Verwendungen von `xpc_connection_get_audit_token` war sowohl statisch als auch dynamisch schwierig.
- **Methodik**: Frida wurde verwendet, um die Funktion `xpc_connection_get_audit_token` zu hooken und Aufrufe zu filtern, die nicht aus Event-Handlern stammen. Diese Methode war jedoch auf den gehookten Prozess beschränkt und erforderte aktive Nutzung.
- **Analysetools**: Tools wie IDA/Ghidra wurden benutzt, um erreichbare mach services zu untersuchen, aber der Prozess war zeitaufwändig und wurde durch Aufrufe, die den dyld shared cache betreffen, verkompliziert.
- **Skript-Einschränkungen**: Versuche, die Analyse zu skripten, um Aufrufe von `xpc_connection_get_audit_token` aus `dispatch_async`-Blöcken zu finden, wurden durch die Komplexität beim Parsen von Blocks und Interaktionen mit dem dyld shared cache behindert.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Gemeldete Probleme**: Ein Bericht wurde an Apple gesendet, der die allgemeinen und spezifischen Probleme in `smd` beschreibt.
- **Apples Reaktion**: Apple hat das Problem in `smd` behoben, indem `xpc_connection_get_audit_token` durch `xpc_dictionary_get_audit_token` ersetzt wurde.
- **Art der Behebung**: Die Funktion `xpc_dictionary_get_audit_token` gilt als sicher, da sie das Audit-Token direkt aus der mach-Nachricht des empfangenen XPC-Objekts abruft. Allerdings ist sie, ähnlich wie `xpc_connection_get_audit_token`, nicht Teil der öffentlichen API.
- **Fehlende umfassendere Lösung**: Es ist unklar, warum Apple keine umfassendere Lösung implementiert hat, z. B. Nachrichten zu verwerfen, die nicht mit dem gespeicherten Audit-Token der connection übereinstimmen. Möglicherweise können legitime Audit-Token-Änderungen in bestimmten Szenarien (z. B. durch `setuid`) eine Rolle spielen.
- **Aktueller Status**: Das Problem besteht weiterhin in iOS 17 und macOS 14 und stellt eine Herausforderung für diejenigen dar, die es identifizieren und verstehen möchten.

## Finding vulnerable code paths in practice (2024–2025)

Beim Audit von XPC-Services für diese Bug-Klasse konzentriere dich auf Autorisierungen, die außerhalb des Event-Handlers der Nachricht oder gleichzeitig mit der Verarbeitung von Replies durchgeführt werden.

Statische Triage-Hinweise:
- Suche nach Aufrufen von `xpc_connection_get_audit_token`, die von Blöcken aus erreichbar sind, die via `dispatch_async`/`dispatch_after` oder anderen Worker-Queues eingeplant werden und außerhalb des Message-Handlers laufen.
- Achte auf Autorisierungs-Helper, die per-connection- und per-message-Status mischen (z. B. PID von `xpc_connection_get_pid` holen, aber das Audit-Token von `xpc_connection_get_audit_token`).
- In NSXPC-Code: Verifiziere, dass Prüfungen in `-listener:shouldAcceptNewConnection:` erfolgen oder, für per-message-Prüfungen, dass die Implementierung ein per-message Audit-Token verwendet (z. B. das Dictionary der Nachricht via `xpc_dictionary_get_audit_token` in Low-Level-Code).

Dynamische Triage-Tipps:
- Hook `xpc_connection_get_audit_token` und markiere Aufrufe, deren User-Stack nicht den Event-Delivery-Pfad enthält (z. B. `_xpc_connection_mach_event`). Beispiel Frida hook:
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
- Auf macOS kann das Instrumentieren geschützter/Apple-Binaries erfordern, dass SIP deaktiviert ist oder eine Entwicklungsumgebung vorhanden ist; bevorzuge das Testen eigener Builds oder Userland-Services.
- Für reply-forwarding races (Variant 2) überwache das gleichzeitige Parsen von Reply-Paketen, indem du die Timings von `xpc_connection_send_message_with_reply` gegenüber normalen Requests fuzzst und prüfst, ob der effektive audit token, der während der Autorisierung verwendet wird, beeinflusst werden kann.

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): Erstelle Verbindungen zu A und B; dupliziere das Senderecht des Client-Ports von A und verwende es als Client-Port von B, sodass die Antworten von B an A geliefert werden.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): Erfasse das send-once right aus A’s ausstehender Anfrage (reply port) und sende dann eine manipulierte Nachricht an B über diesen reply port, sodass Bs Antwort bei A ankommt, während deine privilegierte Anfrage geparst wird.

Diese Techniken erfordern low-level mach message crafting für den XPC bootstrap und die Nachrichtenformate; siehe die mach/XPC-Primerseiten in diesem Abschnitt für die exakten Paketlayouts und Flags.

## Nützliche Tools

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) kann helfen, Verbindungen aufzulisten und den Traffic zu beobachten, um Multi-Sender-Setups und das Timing zu validieren. Beispiel: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose auf `xpc_connection_send_message*` und `xpc_connection_get_audit_token`, um Aufrufstellen und Stacks während Black-Box-Tests zu protokollieren.



## Referenzen

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
