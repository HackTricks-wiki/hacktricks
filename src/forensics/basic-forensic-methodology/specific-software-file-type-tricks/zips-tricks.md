# ZIPs Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Befehlszeilenwerkzeuge** zur Verwaltung von **Zip-Dateien** sind entscheidend für die Diagnose, Reparatur und das Knacken von Zip-Dateien. Hier sind einige wichtige Dienstprogramme:

- **`unzip`**: Zeigt an, warum eine Zip-Datei möglicherweise nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder im Zip-Dateiformat.
- **`zipinfo`**: Listet den Inhalt einer Zip-Datei auf, ohne sie zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte Zip-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von Zip-Passwörtern, effektiv für Passwörter von bis zu etwa 7 Zeichen.

Die [Zip-Dateiformatspezifikation](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) bietet umfassende Details zur Struktur und zu den Standards von Zip-Dateien.

Es ist wichtig zu beachten, dass passwortgeschützte Zip-Dateien **keine Dateinamen oder Dateigrößen** innerhalb verschlüsseln, ein Sicherheitsmangel, der bei RAR- oder 7z-Dateien nicht auftritt, die diese Informationen verschlüsseln. Darüber hinaus sind Zip-Dateien, die mit der älteren ZipCrypto-Methode verschlüsselt sind, anfällig für einen **Plaintext-Angriff**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt, um das Passwort der Zip-Datei zu knacken, eine Schwachstelle, die in [HackThis's Artikel](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) und weiter in [diesem akademischen Papier](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) erklärt wird. Zip-Dateien, die mit **AES-256**-Verschlüsselung gesichert sind, sind jedoch immun gegen diesen Plaintext-Angriff, was die Bedeutung der Wahl sicherer Verschlüsselungsmethoden für sensible Daten verdeutlicht.

## Referenzen

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
