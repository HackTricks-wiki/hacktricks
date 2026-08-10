# Klonen einer Website

Für ein Phishing-Assessment kann es manchmal nützlich sein, eine Website vollständig zu **klonen/dumpen**.

Beachte, dass du der geklonten Website auch einige Payloads hinzufügen kannst, etwa einen BeEF-Hook, um den Tab des Benutzers zu „kontrollieren“.

Für diesen Zweck kannst du verschiedene Tools verwenden:

## wget

Der folgende Befehl verwendet Wgets Modi zum Spiegeln, Herunterladen der erforderlichen Seitenelemente, Konvertieren von Links und Anpassen von Erweiterungen und stellt die heruntergeladenen Dateien anschließend mit Pythons `http.server`-Modul aus dem aktuellen Verzeichnis auf Port 8000 bereit.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Das Repository von goclone beschreibt das Utility als ein Tool, das eine Website in ein lokales Verzeichnis herunterlädt und dabei ihre relative Linkstruktur beibehält. Außerdem wird die Verwendung von `goclone <url>` dokumentiert.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social-Engineering-Toolkit

Das Repository des Social-Engineer Toolkit (SET) beschreibt SET als ein Open-Source-Penetration-Testing-Framework für autorisierte Social-Engineering-Assessments.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU-Wget-Handbuch](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python-`http.server`-Dokumentation](https://docs.python.org/3/library/http.server.html)
- [3] [goclone-Repository](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer-Toolkit-Repository](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
