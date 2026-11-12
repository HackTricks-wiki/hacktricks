# GitHub Issues und Repository-Dateien als C2-Kanal

{{#include ../banners/hacktricks-training.md}}

Ein privates Repository kann **Sitzungszustand** und **Payload-Übertragung** voneinander trennen: Issues halten für jeden Host den Zustand seines Handshakes fest, während Repository-Dateien verschlüsselte Daten in beide Richtungen übertragen. Dabei wird nicht einfach nur der Text eines Issues auf Befehle abgefragt. Die beobachtete Implementierung verwendet ein persönliches Zugriffstoken (PAT) von GitHub, um auf beide APIs zuzugreifen.<sup>[[1]](#references)</sup> Bei einem Fine-grained PAT ist zum Erstellen oder Aktualisieren von Issues die Berechtigung Issues write erforderlich, und zum Hochladen von Dateien die Berechtigung Contents write. Ein Classic PAT benötigt stattdessen den Bereich `repo`. Jeder, der ein ausreichend privilegiertes Token erhält, kann auf denselben Kanal zugreifen.<sup>[[2]](#references)[[3]](#references)</sup>

## Issue- und Datei-Handshake

Ein beobachteter Workflow verwendet eine kurze hexadezimale Host-ID und die folgende Zustandsmaschine. Der genaue ID-Bereich, die Zeichenfolgen und Präfixe sind Protokollmarker und keine Anforderungen der GitHub API.<sup>[[1]](#references)</sup>

1. Beim Start offene und geschlossene Issues mit `GET /repos/{owner}/{repo}/issues?state=open` (und `state=closed`) abfragen, um einen vorherigen Sitzungszustand zu finden. Mit `POST /repos/{owner}/{repo}/issues` ein offenes Issue mit dem Titel `1[ID]` und dem Text `hel` erstellen.
2. Eine Repository-Datei lesen, deren Name mit `2[ID]` beginnt; sie enthält den öffentlichen RSA-Schlüssel des Servers. Einen neuen 16-Byte-Sitzungsschlüssel generieren, mit RSA verschlüsseln und das Ergebnis in einer Datei mit dem Präfix `1[ID]` hochladen.
3. Den nachfolgenden IV durch XOR-Verknüpfung des eingebetteten IV mit diesem Sitzungsschlüssel ableiten. Für jede ausgetauschte Datei den zufälligen 16-Byte-Schlüssel aus ihrem Dateinamen verwenden, um den Inhalt mit AES zu verschlüsseln oder zu entschlüsseln. Das Präfix `2` kennzeichnet Daten vom Server zum Host; das Präfix `1` kennzeichnet Daten vom Host zum Server. Der Dateiname enthält somit Routing-Informationen und Schlüsselmaterial für die jeweilige Datei, während das Issue den Zustand enthält.
4. Die nächste Datei mit dem Präfix `2` lesen und sicherstellen, dass ihr entschlüsselter Inhalt `hel` entspricht. Verschlüsselte Host-Informationen hochladen und dann den Text des Issues mit `PATCH /repos/{owner}/{repo}/issues/{issue_number}` auf `hey` ändern. Erst dann mit dem Abfragen von Befehlen beginnen.

Die Contents API von GitHub liest eine Datei über `GET /repos/{owner}/{repo}/contents/{path}` und erstellt oder ersetzt eine Datei über `PUT` unter diesem Pfad. Bei Dateien mit einer Größe von höchstens 1 MB enthält die standardmäßige JSON-Antwort den Base64-kodierten Inhalt; bei Dateien zwischen 1 und 100 MB ist zum Abrufen ihres Inhalts der Raw-Medientyp erforderlich. Der Upload-Body benötigt eine Commit-Nachricht und den Base64-kodierten Dateiinhalt; zum Ersetzen einer vorhandenen Datei wird außerdem deren aktueller Blob-SHA benötigt. Diese API-Details sind vom oben beschriebenen Verschlüsselungsprotokoll getrennt.<sup>[[2]](#references)[[3]](#references)</sup>

Für ein autorisiertes Test-Repository kann der Issue-Steuerungsabschnitt mit der REST API getestet werden (ein Test-Repository und ein Test-PAT einsetzen). Kein aktives Token in der URL, im Issue-Text oder in einer committeten Datei ablegen.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Der Mechanismus erfordert **weder** den Issue-Titel noch die `hel`-/`hey`-Marker oder die hier gezeigte spezifische Chiffreauswahl; diese kennzeichnen lediglich eine Implementierung. Die wiederverwendbare Idee besteht darin, den veränderlichen Host-Zustand von bidirektionalen verschlüsselten Objekten zu trennen und beides an eine Host-ID zu binden.<sup>[[1]](#references)</sup> Für einen anderen GitHub-Issue-Transport siehe die [Notizen zum benutzerdefinierten Listener von AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Ein Issue-Kommentar-Fallback, der Repository-Anmeldedaten rotiert, anstatt den Sitzungszustand zu übertragen, wird unter [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers) beschrieben.

## References

- [1] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – REST-API-Endpunkte für Issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – REST-API-Endpunkte für Repository-Inhalte](https://docs.github.com/en/rest/repos/contents)
