# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und um sie zu ändern.\
Wenn Sie es herunterladen und ausführen, wird Ihnen ein **Tutorial** angezeigt, wie Sie das Tool verwenden. Wenn Sie lernen möchten, wie man das Tool benutzt, wird dringend empfohlen, es abzuschließen.

## Was suchen Sie?

![](<../../images/image (762).png>)

Dieses Tool ist sehr nützlich, um **herauszufinden, wo ein Wert** (normalerweise eine Zahl) **im Speicher** eines Programms **gespeichert ist**.\
**Normalerweise werden Zahlen** in **4 Bytes** gespeichert, aber Sie könnten sie auch in **double** oder **float** Formaten finden, oder Sie möchten nach etwas **anderem als einer Zahl** suchen. Aus diesem Grund müssen Sie sicherstellen, dass Sie **auswählen**, wonach Sie **suchen möchten**:

![](<../../images/image (324).png>)

Außerdem können Sie **verschiedene** Arten von **Suchen** angeben:

![](<../../images/image (311).png>)

Sie können auch das Kästchen ankreuzen, um **das Spiel während des Scannens des Speichers zu stoppen**:

![](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ können Sie verschiedene **Hotkeys** für verschiedene Zwecke festlegen, wie z.B. **das Spiel zu stoppen** (was sehr nützlich ist, wenn Sie zu einem bestimmten Zeitpunkt den Speicher scannen möchten). Weitere Optionen sind verfügbar:

![](<../../images/image (864).png>)

## Den Wert ändern

Sobald Sie **gefunden** haben, wo der **Wert** ist, den Sie **suchen** (mehr dazu in den folgenden Schritten), können Sie ihn **ändern**, indem Sie doppelt darauf klicken und dann erneut auf seinen Wert doppelt klicken:

![](<../../images/image (563).png>)

Und schließlich **das Kästchen markieren**, um die Änderung im Speicher vorzunehmen:

![](<../../images/image (385).png>)

Die **Änderung** im **Speicher** wird sofort **angewendet** (beachten Sie, dass der Wert **nicht im Spiel aktualisiert wird**, bis das Spiel diesen Wert nicht erneut verwendet).

## Den Wert suchen

Angenommen, es gibt einen wichtigen Wert (wie das Leben Ihres Benutzers), den Sie verbessern möchten, und Sie suchen diesen Wert im Speicher.

### Durch eine bekannte Änderung

Angenommen, Sie suchen den Wert 100, Sie **führen einen Scan** durch, um nach diesem Wert zu suchen, und finden viele Übereinstimmungen:

![](<../../images/image (108).png>)

Dann tun Sie etwas, damit sich der **Wert ändert**, und Sie **stoppen** das Spiel und **führen** einen **nächsten Scan** durch:

![](<../../images/image (684).png>)

Cheat Engine wird nach den **Werten** suchen, die **von 100 auf den neuen Wert** gewechselt sind. Glückwunsch, Sie **haben** die **Adresse** des Wertes gefunden, den Sie gesucht haben, und können ihn jetzt ändern.\
&#xNAN;_Wenn Sie immer noch mehrere Werte haben, tun Sie etwas, um diesen Wert erneut zu ändern, und führen Sie einen weiteren "nächsten Scan" durch, um die Adressen zu filtern._

### Unbekannter Wert, bekannte Änderung

In dem Szenario, dass Sie **den Wert nicht kennen**, aber wissen, **wie man ihn ändert** (und sogar den Wert der Änderung), können Sie nach Ihrer Zahl suchen.

Beginnen Sie also mit einem Scan vom Typ "**Unbekannter Anfangswert**":

![](<../../images/image (890).png>)

Ändern Sie dann den Wert, geben Sie an, **wie** sich der **Wert** **geändert hat** (in meinem Fall wurde er um 1 verringert) und führen Sie einen **nächsten Scan** durch:

![](<../../images/image (371).png>)

Sie werden **alle Werte sehen, die auf die ausgewählte Weise geändert wurden**:

![](<../../images/image (569).png>)

Sobald Sie Ihren Wert gefunden haben, können Sie ihn ändern.

Beachten Sie, dass es eine **Menge möglicher Änderungen** gibt und Sie diese **Schritte so oft wiederholen können, wie Sie möchten**, um die Ergebnisse zu filtern:

![](<../../images/image (574).png>)

### Zufällige Speicheradresse - Den Code finden

Bis jetzt haben wir gelernt, wie man eine Adresse findet, die einen Wert speichert, aber es ist sehr wahrscheinlich, dass in **verschiedenen Ausführungen des Spiels diese Adresse an verschiedenen Stellen im Speicher** ist. Lassen Sie uns also herausfinden, wie man diese Adresse immer findet.

Verwenden Sie einige der erwähnten Tricks, um die Adresse zu finden, an der Ihr aktuelles Spiel den wichtigen Wert speichert. Dann (stoppen Sie das Spiel, wenn Sie möchten) klicken Sie mit der **rechten Maustaste** auf die gefundene **Adresse** und wählen Sie "**Herausfinden, was auf diese Adresse zugreift**" oder "**Herausfinden, was in diese Adresse schreibt**":

![](<../../images/image (1067).png>)

Die **erste Option** ist nützlich, um zu wissen, welche **Teile** des **Codes** diese **Adresse verwenden** (was für mehr Dinge nützlich ist, wie z.B. **zu wissen, wo Sie den Code** des Spiels **ändern können**).\
Die **zweite Option** ist spezifischer und wird in diesem Fall hilfreicher sein, da wir daran interessiert sind, **von wo dieser Wert geschrieben wird**.

Sobald Sie eine dieser Optionen ausgewählt haben, wird der **Debugger** an das Programm **angehängt** und ein neues **leeres Fenster** erscheint. Jetzt **spielen** Sie das **Spiel** und **ändern** Sie diesen **Wert** (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen** gefüllt sein, die den **Wert ändern**:

![](<../../images/image (91).png>)

Jetzt, da Sie die Adresse gefunden haben, die den Wert ändert, können Sie **den Code nach Belieben ändern** (Cheat Engine ermöglicht es Ihnen, ihn schnell in NOPs zu ändern):

![](<../../images/image (1057).png>)

So können Sie ihn jetzt so ändern, dass der Code Ihre Zahl nicht beeinflusst oder immer positiv beeinflusst.

### Zufällige Speicheradresse - Den Zeiger finden

Befolgen Sie die vorherigen Schritte, um herauszufinden, wo sich der Wert befindet, der Sie interessiert. Verwenden Sie dann "**Herausfinden, was in diese Adresse schreibt**", um herauszufinden, welche Adresse diesen Wert schreibt, und doppelklicken Sie darauf, um die Disassemblierungsansicht zu erhalten:

![](<../../images/image (1039).png>)

Führen Sie dann einen neuen Scan durch, **um den Hex-Wert zwischen "\[]"** zu suchen (den Wert von $edx in diesem Fall):

![](<../../images/image (994).png>)

(_Wenn mehrere erscheinen, benötigen Sie normalerweise die kleinste Adresse_)\
Jetzt haben wir den **Zeiger gefunden, der den Wert ändert, an dem wir interessiert sind**.

Klicken Sie auf "**Adresse manuell hinzufügen**":

![](<../../images/image (990).png>)

Klicken Sie nun auf das Kontrollkästchen "Zeiger" und fügen Sie die gefundene Adresse in das Textfeld ein (in diesem Szenario war die gefundene Adresse im vorherigen Bild "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Beachten Sie, dass die erste "Adresse" automatisch aus der Zeigeradresse ausgefüllt wird, die Sie eingeben)

Klicken Sie auf OK und ein neuer Zeiger wird erstellt:

![](<../../images/image (308).png>)

Jetzt, jedes Mal, wenn Sie diesen Wert ändern, ändern Sie **den wichtigen Wert, auch wenn die Speicheradresse, an der der Wert gespeichert ist, unterschiedlich ist.**

### Code-Injektion

Code-Injektion ist eine Technik, bei der Sie ein Stück Code in den Zielprozess injizieren und dann die Ausführung des Codes so umleiten, dass sie durch Ihren eigenen geschriebenen Code geht (zum Beispiel, um Ihnen Punkte zu geben, anstatt sie abzuziehen).

Stellen Sie sich also vor, Sie haben die Adresse gefunden, die 1 vom Leben Ihres Spielers abzieht:

![](<../../images/image (203).png>)

Klicken Sie auf "Disassembler anzeigen", um den **disassemblierten Code** zu erhalten.\
Klicken Sie dann auf **CTRL+a**, um das Auto-Assembly-Fenster aufzurufen, und wählen Sie _**Template --> Code Injection**_

![](<../../images/image (902).png>)

Füllen Sie die **Adresse der Anweisung aus, die Sie ändern möchten** (dies wird normalerweise automatisch ausgefüllt):

![](<../../images/image (744).png>)

Ein Template wird generiert:

![](<../../images/image (944).png>)

Fügen Sie Ihren neuen Assembly-Code in den Abschnitt "**newmem**" ein und entfernen Sie den ursprünglichen Code aus dem "**originalcode**", wenn Sie nicht möchten, dass er ausgeführt wird\*\*.\*\* In diesem Beispiel wird der injizierte Code 2 Punkte hinzufügen, anstatt 1 abzuziehen:

![](<../../images/image (521).png>)

**Klicken Sie auf Ausführen und so weiter, und Ihr Code sollte in das Programm injiziert werden, wodurch das Verhalten der Funktionalität geändert wird!**

## **Referenzen**

- **Cheat Engine Tutorial, schließen Sie es ab, um zu lernen, wie Sie mit Cheat Engine beginnen können**

{{#include ../../banners/hacktricks-training.md}}
