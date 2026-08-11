# Eine Website klonen

{{#include ../../banners/hacktricks-training.md}}

Für eine Phishing-Bewertung kann es manchmal nützlich sein, eine Website vollständig zu **klonen/dumpen**.

Beachte, dass du der geklonten Website auch Payloads hinzufügen kannst, beispielsweise einen BeEF-Hook, um den Tab des Benutzers zu „kontrollieren“.

Dafür kannst du verschiedene Tools verwenden:

## wget

Der folgende Befehl verwendet die Modi zum Spiegeln, Herunterladen erforderlicher Seitenelemente, Konvertieren von Links und Anpassen von Erweiterungen in Wget und stellt die heruntergeladenen Dateien anschließend mit dem Python-Modul `http.server` aus dem aktuellen Verzeichnis auf Port 8000 bereit.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Das goclone-Repository beschreibt das Tool als Möglichkeit, eine Website in ein lokales Verzeichnis herunterzuladen und dabei ihre relative Link-Struktur beizubehalten. Außerdem wird der Aufruf `goclone <url>` dokumentiert.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolit

Das Repository des Social-Engineer Toolkits (SET) weist SET als ein Open-Source-Penetration-Testing-Framework für autorisierte Social-Engineering-Bewertungen aus.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU-Wget-Handbuch](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python-Dokumentation zu `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [goclone-Repository](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer-Toolkit-Repository](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
