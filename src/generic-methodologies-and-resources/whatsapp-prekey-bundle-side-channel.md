# Side-Channel durch Erschöpfung und Wiederauffüllung von WhatsApp-Prekey-Bundles

{{#include ../banners/hacktricks-training.md}}

WhatsApp speichert für jedes Gerät einen Identity Key, einen signierten Prekey und einen Vorrat an einmaligen Prekeys. Das Abrufen des Bundles eines Geräts verbraucht einen serverseitig gespeicherten einmaligen Prekey, selbst wenn der Anfragende keine Nachricht sendet. Damit erhält ein Angreifer mit einem WhatsApp-Konto und der Telefonnummer des Ziels eine **serverseitige** Probe, die sich von der [Timing-Analyse von Zustellbestätigungen auf dem Client](side-channel-attacks-on-messaging-protocols.md) unterscheidet. Ein fehlender einmaliger Prekey schwächt die Forward Secrecy für die *ersten* Nachrichten einer neu eingerichteten Sitzung; er legt für sich genommen jedoch keinen Klartext offen.<sup>[[1]](#references)[[2]](#references)</sup>

## Geräte-Bundles eines Ziels untersuchen

Das [Prekey Pogo-Artefakt](https://github.com/sbaresearch/prekey-pogo) wird als WhatsApp-Begleitsitzung gekoppelt und unterstützt **manuelle** Geräte- und Prekey-Abfragen. Kopple es mit einem Testkonto und verwende anschließend die interaktiven Befehle `target`, `devices`, `prekey` (Primärgerät) und `combine` (alle Geräte). Das veröffentlichte Artefakt lässt automatisierte Funktionen zur Erschöpfung und Serverüberlastung bewusst weg.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Erfassen Sie für jede Antwort die Geräte-JID, den Bundle-Zeitstempel `t`, die ID des signierten Prekeys `skey.id` und ob `key.id` für einen einmaligen Key vorhanden ist. Geräte-ID `0` bezeichnet das Telefon; IDs ungleich null bezeichnen Companion-Geräte. Bei den im Paper getesteten Implementierungen unterscheidet die anfängliche ID des signierten Prekeys auch einige Clients: Android beginnt bei `0`, iOS und macOS verwenden einen zufälligen Wert, und WhatsApp Web sowie Windows Desktop beginnen bei `1`. Betrachten Sie dies als Implementierungs-Fingerabdruck, nicht als unveränderliche Protokollregel.<sup>[[1]](#references)</sup>

## Refills in ein Online-Status-Orakel verwandeln

Kalibrieren Sie zunächst mit einem Gerät, das Sie kontrollieren: Fragen Sie wiederholt dessen Bundle ab, bis der Server keinen einmaligen `key` mehr zurückgibt, und notieren Sie den letzten Zeitstempel und die Key-IDs. Wiederholen Sie beim Zielgerät die Entleerung und fragen Sie nach einem kontrollierten Zeitintervall erneut ab: Ein neuer einmaliger Key und ein fortgeschrittener Bundle-Zeitstempel zeigen an, dass das Gerät einen frischen Batch hochgeladen hat. In den berichteten WhatsApp-Tests forderte der Server unterhalb von 11 verbleibenden Keys einen Refill an, und die Clients luden 812 neue Keys hoch. Wenden Sie das Verfahren für jede Geräte-JID einzeln an, um ein Telefon von Companion-Geräten zu unterscheiden. Ein verzögerter Refill **deutet lediglich darauf hin**, dass ein Gerät offline ist: Hintergrundplanung, Netzwerkausfälle und client-spezifische Refill-Latenz können dieselbe Beobachtung verursachen. Anders als eine Receipt-RTT erfordert diese Probe weder einen zugestellten Ciphertext noch eine Bestätigung auf dem Gerät des Opfers.<sup>[[1]](#references)[[2]](#references)</sup>

Jede Abfrage verbraucht einen einmaligen Key. Ein dauerhaftes Orakel erfordert daher einen Custom Client, der wiederholte Prekey-Abfragen durchführen kann; das öffentliche Artefakt demonstriert nur manuelle Abfragen. Wenn der Vorrat leer bleibt, können andere Nutzer neue Sessions ohne einmaligen Prekey aufbauen. Das verringert die Forward Secrecy für initiale Nachrichten bis zu einem frischen Ratchet-Schritt. Um aufgezeichneten Ciphertext auszunutzen, müssen jedoch zusätzlich Zugriff auf den E2EE-Ciphertext und eine spätere Kompromittierung der relevanten privaten Langzeit- und mittelfristigen Schlüssel erfolgen. Bereits bestehende Sessions werden nicht automatisch herabgestuft.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Untersuchung von Sicherheits- und Datenschutzproblemen im Handshake-Mechanismus von WhatsApp](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifacts](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
