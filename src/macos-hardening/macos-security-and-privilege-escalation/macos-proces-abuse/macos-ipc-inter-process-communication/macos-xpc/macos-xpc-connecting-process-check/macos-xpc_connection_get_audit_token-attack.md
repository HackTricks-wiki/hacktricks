# macOS xpc_connection_get_audit_token Angriff

{{#include ../../../../../../banners/hacktricks-training.md}}

**Für weitere Informationen siehe den Originalbeitrag:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dies ist eine Zusammenfassung:

## Grundlegende Informationen zu Mach-Nachrichten

Wenn Sie nicht wissen, was Mach-Nachrichten sind, beginnen Sie mit dieser Seite:

{{#ref}}
../../
{{#endref}}

Für den Moment merken Sie sich, dass ([Definition von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach-Nachrichten werden über einen _mach port_ gesendet, der ein **einzelner Empfänger, mehrere Sender Kommunikationskanal** ist, der im Mach-Kernel eingebaut ist. **Mehrere Prozesse können Nachrichten** an einen Mach-Port senden, aber zu jedem Zeitpunkt **kann nur ein einzelner Prozess davon lesen**. Genau wie Dateideskriptoren und Sockets werden Mach-Ports vom Kernel zugewiesen und verwaltet, und Prozesse sehen nur eine Ganzzahl, die sie verwenden können, um dem Kernel anzuzeigen, welchen ihrer Mach-Ports sie verwenden möchten.

## XPC-Verbindung

Wenn Sie nicht wissen, wie eine XPC-Verbindung hergestellt wird, überprüfen Sie:

{{#ref}}
../
{{#endref}}

## Zusammenfassung der Schwachstelle

Was für Sie interessant zu wissen ist, dass **XPCs Abstraktion eine Eins-zu-Eins-Verbindung ist**, aber sie basiert auf einer Technologie, die **mehrere Sender haben kann, also:**

- Mach-Ports sind einzelner Empfänger, **mehrere Sender**.
- Das Audit-Token einer XPC-Verbindung ist das Audit-Token, das **aus der zuletzt empfangenen Nachricht kopiert wurde**.
- Das Erlangen des **Audit-Tokens** einer XPC-Verbindung ist entscheidend für viele **Sicherheitsprüfungen**.

Obwohl die vorherige Situation vielversprechend klingt, gibt es einige Szenarien, in denen dies keine Probleme verursachen wird ([von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit-Tokens werden oft für eine Autorisierungsprüfung verwendet, um zu entscheiden, ob eine Verbindung akzeptiert werden soll. Da dies über eine Nachricht an den Dienstport erfolgt, ist **noch keine Verbindung hergestellt**. Weitere Nachrichten auf diesem Port werden einfach als zusätzliche Verbindungsanfragen behandelt. Daher sind alle **Prüfungen vor der Annahme einer Verbindung nicht anfällig** (das bedeutet auch, dass innerhalb von `-listener:shouldAcceptNewConnection:` das Audit-Token sicher ist). Wir suchen daher **nach XPC-Verbindungen, die spezifische Aktionen überprüfen**.
- XPC-Ereignis-Handler werden synchron behandelt. Das bedeutet, dass der Ereignis-Handler für eine Nachricht abgeschlossen sein muss, bevor er für die nächste aufgerufen wird, selbst bei parallelen Dispatch-Warteschlangen. Daher kann innerhalb eines **XPC-Ereignis-Handlers das Audit-Token nicht von anderen normalen (nicht-Antwort!) Nachrichten überschrieben werden**.

Zwei verschiedene Methoden, wie dies ausgenutzt werden könnte:

1. Variante 1:
- **Exploit** **verbindet** sich mit Dienst **A** und Dienst **B**
- Dienst **B** kann eine **privilegierte Funktionalität** in Dienst A aufrufen, die der Benutzer nicht kann
- Dienst **A** ruft **`xpc_connection_get_audit_token`** auf, während er _**nicht**_ im **Ereignis-Handler** für eine Verbindung in einem **`dispatch_async`** ist.
- So könnte eine **andere** Nachricht das **Audit-Token überschreiben**, weil es asynchron außerhalb des Ereignis-Handlers dispatcht wird.
- Der Exploit übergibt an **Dienst B das SEND-Recht an Dienst A**.
- So wird Dienst **B** tatsächlich die **Nachrichten** an Dienst **A** **senden**.
- Der **Exploit** versucht, die **privilegierte Aktion** **aufzurufen**. In einem RC **prüft** Dienst **A** die Autorisierung dieser **Aktion**, während **Dienst B das Audit-Token überschreibt** (was dem Exploit Zugriff auf die privilegierte Aktion gibt).
2. Variante 2:
- Dienst **B** kann eine **privilegierte Funktionalität** in Dienst A aufrufen, die der Benutzer nicht kann
- Der Exploit verbindet sich mit **Dienst A**, der dem Exploit eine **Nachricht sendet, die eine Antwort erwartet** in einem bestimmten **Antwortport**.
- Der Exploit sendet **Dienst** B eine Nachricht, die **diesen Antwortport** übergibt.
- Wenn Dienst **B antwortet**, **sendet** er die Nachricht an Dienst A, **während** der **Exploit** eine andere **Nachricht an Dienst A** sendet, die versucht, eine **privilegierte Funktionalität** zu erreichen und erwartet, dass die Antwort von Dienst B das Audit-Token im perfekten Moment überschreibt (Race Condition).

## Variante 1: Aufruf von xpc_connection_get_audit_token außerhalb eines Ereignis-Handlers <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Szenario:

- Zwei Mach-Dienste **`A`** und **`B`**, zu denen wir beide eine Verbindung herstellen können (basierend auf dem Sandbox-Profil und den Autorisierungsprüfungen vor der Annahme der Verbindung).
- _**A**_ muss eine **Autorisierungsprüfung** für eine spezifische Aktion haben, die **`B`** übergeben kann (aber unsere App nicht).
- Zum Beispiel, wenn B einige **Befugnisse** hat oder als **root** läuft, könnte es ihm erlauben, A zu bitten, eine privilegierte Aktion auszuführen.
- Für diese Autorisierungsprüfung erhält **`A`** das Audit-Token asynchron, indem es beispielsweise `xpc_connection_get_audit_token` von **`dispatch_async`** aufruft.

> [!CAUTION]
> In diesem Fall könnte ein Angreifer eine **Race Condition** auslösen, indem er einen **Exploit** ausführt, der **A auffordert, eine Aktion** mehrmals auszuführen, während er **B Nachrichten an `A`** senden lässt. Wenn die RC **erfolgreich** ist, wird das **Audit-Token** von **B** im Speicher kopiert, **während** die Anfrage unseres **Exploits** von A **bearbeitet** wird, was ihm **Zugriff auf die privilegierte Aktion gibt, die nur B anfordern konnte**.

Dies geschah mit **`A`** als `smd` und **`B`** als `diagnosticd`. Die Funktion [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) von smb kann verwendet werden, um ein neues privilegiertes Hilfsprogramm (als **root**) zu installieren. Wenn ein **Prozess, der als root läuft,** **smd** kontaktiert, werden keine weiteren Prüfungen durchgeführt.

Daher ist der Dienst **B** **`diagnosticd`**, da er als **root** läuft und verwendet werden kann, um einen Prozess zu **überwachen**, sodass, sobald die Überwachung begonnen hat, er **mehrere Nachrichten pro Sekunde sendet.**

Um den Angriff durchzuführen:

1. Stellen Sie eine **Verbindung** zum Dienst mit dem Namen `smd` unter Verwendung des Standard-XPC-Protokolls her.
2. Bilden Sie eine sekundäre **Verbindung** zu `diagnosticd`. Im Gegensatz zum normalen Verfahren wird anstelle der Erstellung und des Sendens von zwei neuen Mach-Ports das Senderecht des Client-Ports durch eine Duplikation des **Senderechts** ersetzt, das mit der `smd`-Verbindung verbunden ist.
3. Infolgedessen können XPC-Nachrichten an `diagnosticd` gesendet werden, aber Antworten von `diagnosticd` werden an `smd` umgeleitet. Für `smd` scheint es, als ob die Nachrichten sowohl vom Benutzer als auch von `diagnosticd` aus derselben Verbindung stammen.

![Bild, das den Exploit-Prozess darstellt](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Der nächste Schritt besteht darin, `diagnosticd` anzuweisen, die Überwachung eines ausgewählten Prozesses (möglicherweise des eigenen Benutzers) zu starten. Gleichzeitig wird eine Flut von routinemäßigen 1004-Nachrichten an `smd` gesendet. Das Ziel hier ist es, ein Tool mit erhöhten Rechten zu installieren.
5. Diese Aktion löst eine Race Condition innerhalb der Funktion `handle_bless` aus. Das Timing ist entscheidend: Der Aufruf der Funktion `xpc_connection_get_pid` muss die PID des Benutzerprozesses zurückgeben (da sich das privilegierte Tool im App-Bundle des Benutzers befindet). Das Audit-Token muss jedoch in der Funktion `xpc_connection_get_audit_token`, insbesondere innerhalb der Unterroutine `connection_is_authorized`, auf das Audit-Token von `diagnosticd` verweisen.

## Variante 2: Antwortweiterleitung

In einer XPC (Cross-Process Communication)-Umgebung, obwohl Ereignis-Handler nicht gleichzeitig ausgeführt werden, hat die Behandlung von Antwortnachrichten ein einzigartiges Verhalten. Insbesondere gibt es zwei verschiedene Methoden zum Senden von Nachrichten, die eine Antwort erwarten:

1. **`xpc_connection_send_message_with_reply`**: Hier wird die XPC-Nachricht empfangen und auf einer bestimmten Warteschlange verarbeitet.
2. **`xpc_connection_send_message_with_reply_sync`**: Im Gegensatz dazu wird bei dieser Methode die XPC-Nachricht empfangen und auf der aktuellen Dispatch-Warteschlange verarbeitet.

Diese Unterscheidung ist entscheidend, da sie die Möglichkeit eröffnet, dass **Antwortpakete gleichzeitig mit der Ausführung eines XPC-Ereignis-Handlers analysiert werden**. Bemerkenswerterweise implementiert `_xpc_connection_set_creds` zwar eine Sperre, um gegen die teilweise Überschreibung des Audit-Tokens zu schützen, jedoch erstreckt sich dieser Schutz nicht auf das gesamte Verbindungsobjekt. Folglich entsteht eine Schwachstelle, bei der das Audit-Token während des Zeitraums zwischen der Analyse eines Pakets und der Ausführung seines Ereignis-Handlers ersetzt werden kann.

Um diese Schwachstelle auszunutzen, ist die folgende Einrichtung erforderlich:

- Zwei Mach-Dienste, bezeichnet als **`A`** und **`B`**, die beide eine Verbindung herstellen können.
- Dienst **`A`** sollte eine Autorisierungsprüfung für eine spezifische Aktion enthalten, die nur **`B`** ausführen kann (die Anwendung des Benutzers kann dies nicht).
- Dienst **`A`** sollte eine Nachricht senden, die eine Antwort erwartet.
- Der Benutzer kann eine Nachricht an **`B`** senden, auf die er antworten wird.

Der Ausbeutungsprozess umfasst die folgenden Schritte:

1. Warten Sie, bis Dienst **`A`** eine Nachricht sendet, die eine Antwort erwartet.
2. Anstatt direkt an **`A`** zu antworten, wird der Antwortport gehijackt und verwendet, um eine Nachricht an Dienst **`B`** zu senden.
3. Anschließend wird eine Nachricht mit der verbotenen Aktion gesendet, in der Erwartung, dass sie gleichzeitig mit der Antwort von **`B`** verarbeitet wird.

Unten ist eine visuelle Darstellung des beschriebenen Angriffszenarios:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Entdeckungsprobleme

- **Schwierigkeiten beim Auffinden von Instanzen**: Die Suche nach Instanzen der Verwendung von `xpc_connection_get_audit_token` war sowohl statisch als auch dynamisch herausfordernd.
- **Methodologie**: Frida wurde verwendet, um die Funktion `xpc_connection_get_audit_token` zu hooken und Aufrufe zu filtern, die nicht von Ereignis-Handlern stammen. Diese Methode war jedoch auf den gehookten Prozess beschränkt und erforderte eine aktive Nutzung.
- **Analysetools**: Tools wie IDA/Ghidra wurden verwendet, um erreichbare Mach-Dienste zu untersuchen, aber der Prozess war zeitaufwendig und kompliziert durch Aufrufe, die den dyld Shared Cache betreffen.
- **Scripting-Einschränkungen**: Versuche, die Analyse für Aufrufe von `xpc_connection_get_audit_token` aus `dispatch_async`-Blöcken zu skripten, wurden durch Komplexitäten beim Parsen von Blöcken und Interaktionen mit dem dyld Shared Cache behindert.

## Der Fix <a href="#the-fix" id="the-fix"></a>

- **Gemeldete Probleme**: Ein Bericht wurde an Apple über die allgemeinen und spezifischen Probleme, die in `smd` gefunden wurden, eingereicht.
- **Apples Antwort**: Apple hat das Problem in `smd` behoben, indem es `xpc_connection_get_audit_token` durch `xpc_dictionary_get_audit_token` ersetzt hat.
- **Art des Fixes**: Die Funktion `xpc_dictionary_get_audit_token` gilt als sicher, da sie das Audit-Token direkt aus der Mach-Nachricht abruft, die mit der empfangenen XPC-Nachricht verbunden ist. Sie ist jedoch nicht Teil der öffentlichen API, ähnlich wie `xpc_connection_get_audit_token`.
- **Fehlen eines umfassenderen Fixes**: Es bleibt unklar, warum Apple keinen umfassenderen Fix implementiert hat, wie das Verwerfen von Nachrichten, die nicht mit dem gespeicherten Audit-Token der Verbindung übereinstimmen. Die Möglichkeit legitimer Änderungen des Audit-Tokens in bestimmten Szenarien (z. B. Verwendung von `setuid`) könnte ein Faktor sein.
- **Aktueller Status**: Das Problem besteht weiterhin in iOS 17 und macOS 14 und stellt eine Herausforderung für diejenigen dar, die versuchen, es zu identifizieren und zu verstehen.

{{#include ../../../../../../banners/hacktricks-training.md}}
