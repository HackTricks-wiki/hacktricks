{{#include ../banners/hacktricks-training.md}}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

# CBC - Cipher Block Chaining

Im CBC-Modus wird der **vorherige verschlüsselte Block als IV** verwendet, um mit dem nächsten Block zu XORen:

![https://defuse.ca/images/cbc_encryption.png](https://defuse.ca/images/cbc_encryption.png)

Um CBC zu entschlüsseln, werden die **entgegengesetzten** **Operationen** durchgeführt:

![https://defuse.ca/images/cbc_decryption.png](https://defuse.ca/images/cbc_decryption.png)

Beachten Sie, dass es notwendig ist, einen **Verschlüsselungs** **schlüssel** und ein **IV** zu verwenden.

# Nachrichten-Padding

Da die Verschlüsselung in **festen** **Größen** **Blöcken** erfolgt, ist in dem **letzten** **Block** normalerweise **Padding** erforderlich, um seine Länge zu vervollständigen.\
In der Regel wird **PKCS7** verwendet, das ein Padding erzeugt, das die **Anzahl** der **Bytes** **wiederholt**, die benötigt werden, um den Block zu **vollenden**. Zum Beispiel, wenn im letzten Block 3 Bytes fehlen, wird das Padding `\x03\x03\x03` sein.

Sehen wir uns weitere Beispiele mit **2 Blöcken der Länge 8 Bytes** an:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Beachten Sie, dass im letzten Beispiel der **letzte Block voll war, sodass ein weiterer nur mit Padding generiert wurde**.

# Padding Oracle

Wenn eine Anwendung verschlüsselte Daten entschlüsselt, wird sie zuerst die Daten entschlüsseln; dann wird sie das Padding entfernen. Während der Bereinigung des Paddings, wenn ein **ungültiges Padding ein erkennbares Verhalten auslöst**, haben Sie eine **Padding-Oracle-Schwachstelle**. Das erkennbare Verhalten kann ein **Fehler**, ein **Mangel an Ergebnissen** oder eine **langsamere Antwort** sein.

Wenn Sie dieses Verhalten erkennen, können Sie **die verschlüsselten Daten entschlüsseln** und sogar **beliebigen Klartext verschlüsseln**.

## Wie man ausnutzt

Sie könnten [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) verwenden, um diese Art von Schwachstelle auszunutzen oder einfach tun
```
sudo apt-get install padbuster
```
Um zu testen, ob das Cookie einer Seite anfällig ist, könnten Sie Folgendes versuchen:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** bedeutet, dass **base64** verwendet wird (aber es sind auch andere verfügbar, siehe das Hilfemenü).

Sie könnten diese Schwachstelle auch **ausnutzen, um neue Daten zu verschlüsseln. Zum Beispiel, stellen Sie sich vor, der Inhalt des Cookies ist "**_**user=MyUsername**_**", dann könnten Sie ihn in "\_user=administrator\_" ändern und die Berechtigungen innerhalb der Anwendung eskalieren. Sie könnten dies auch mit `paduster` tun, indem Sie den -plaintext** Parameter angeben:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Wenn die Seite anfällig ist, wird `padbuster` automatisch versuchen herauszufinden, wann der Padding-Fehler auftritt, aber Sie können auch die Fehlermeldung mit dem **-error** Parameter angeben.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Die Theorie

In **Zusammenfassung** können Sie mit der Entschlüsselung der verschlüsselten Daten beginnen, indem Sie die richtigen Werte erraten, die verwendet werden können, um alle **verschiedenen Paddings** zu erstellen. Dann beginnt der Padding-Oracle-Angriff, Bytes vom Ende zum Anfang zu entschlüsseln, indem erraten wird, welcher der richtige Wert ist, der **ein Padding von 1, 2, 3 usw. erzeugt**.

![](<../images/image (629) (1) (1).png>)

Stellen Sie sich vor, Sie haben einen verschlüsselten Text, der **2 Blöcke** umfasst, die aus den Bytes von **E0 bis E15** bestehen.\
Um den **letzten** **Block** (**E8** bis **E15**) zu **entschlüsseln**, durchläuft der gesamte Block die "Blockchiffre-Entschlüsselung", die die **Zwischenbytes I0 bis I15** erzeugt.\
Schließlich wird jedes Zwischenbyte mit den vorherigen verschlüsselten Bytes (E0 bis E7) **XORed**. Also:

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

Jetzt ist es möglich, `E7` so zu **modifizieren**, dass `C15` `0x01` ist, was ebenfalls ein korrektes Padding sein wird. In diesem Fall: `\x01 = I15 ^ E'7`

Durch das Finden von E'7 ist es **möglich, I15 zu berechnen**: `I15 = 0x01 ^ E'7`

Was es uns ermöglicht, **C15 zu berechnen**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Wenn wir **C15** kennen, ist es jetzt möglich, **C14 zu berechnen**, aber diesmal durch Brute-Forcing des Paddings `\x02\x02`.

Dieses BF ist so komplex wie das vorherige, da es möglich ist, das `E''15` zu berechnen, dessen Wert 0x02 ist: `E''7 = \x02 ^ I15`, sodass nur **`E'14`** gefunden werden muss, das ein **`C14` erzeugt, das gleich `0x02` ist**.\
Dann die gleichen Schritte wiederholen, um C14 zu entschlüsseln: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Folgen Sie dieser Kette, bis Sie den gesamten verschlüsselten Text entschlüsselt haben.**

## Erkennung der Schwachstelle

Registrieren Sie sich und melden Sie sich mit diesem Konto an.\
Wenn Sie **mehrmals einloggen** und immer dasselbe **Cookie** erhalten, gibt es wahrscheinlich **etwas** **Falsches** in der Anwendung. Das **zurückgesendete Cookie sollte jedes Mal einzigartig sein**, wenn Sie sich anmelden. Wenn das Cookie **immer** dasselbe ist, wird es wahrscheinlich immer gültig sein und es **wird keinen Weg geben, es zu ungültig zu machen**.

Wenn Sie jetzt versuchen, das **Cookie zu modifizieren**, können Sie sehen, dass Sie einen **Fehler** von der Anwendung erhalten.\
Aber wenn Sie das Padding brute-forcen (zum Beispiel mit Padbuster), schaffen Sie es, ein anderes Cookie zu erhalten, das für einen anderen Benutzer gültig ist. Dieses Szenario ist höchstwahrscheinlich anfällig für Padbuster.

## Referenzen

- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{{#include ../banners/hacktricks-training.md}}
