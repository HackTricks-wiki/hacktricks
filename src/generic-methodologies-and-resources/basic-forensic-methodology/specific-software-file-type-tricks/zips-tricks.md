# ZIP-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** zur Verwaltung von **ZIP-Dateien** sind für die Diagnose, Reparatur und das Cracking von ZIP-Dateien unverzichtbar. Hier sind einige wichtige Dienstprogramme:<sup>[[1]](#references)</sup>

- **`unzip`**: Zeigt, warum eine ZIP-Datei möglicherweise nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des ZIP-Dateiformats.
- **`zipinfo`**: Listet den Inhalt einer ZIP-Datei auf, ohne ihn zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte ZIP-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Cracking von ZIP-Passwörtern, das bei Passwörtern mit bis zu etwa 7 Zeichen effektiv ist.

Die [Spezifikation des Zip-Dateiformats](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) enthält umfassende Informationen über die Struktur und Standards von ZIP-Dateien.<sup>[[4]](#references)</sup>

Es ist wichtig zu beachten, dass passwortgeschützte ZIP-Dateien **Dateinamen oder Dateigrößen** der darin enthaltenen Dateien **nicht verschlüsseln**. Dies ist eine Sicherheitslücke, die bei RAR- oder 7z-Dateien nicht besteht, da diese Informationen dort verschlüsselt werden. Außerdem sind ZIP-Dateien, die mit der älteren ZipCrypto-Methode verschlüsselt wurden, für einen **plaintext attack** anfällig, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist.<sup>[[1]](#references)</sup> Dieser Angriff nutzt den bekannten Inhalt, um das Passwort der ZIP-Datei zu knacken. Die Schwachstelle wird im [Artikel von HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beschrieben und in [diesem wissenschaftlichen Paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) ausführlicher erklärt.<sup>[[11]](#references)[[12]](#references)</sup> Mit **AES-256**-Verschlüsselung geschützte ZIP-Dateien sind jedoch gegen diesen plaintext attack immun. Dies verdeutlicht, wie wichtig die Auswahl sicherer Verschlüsselungsmethoden für sensible Daten ist.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks in APKs using manipulierte ZIP-Header

Moderne Android-Malware-Dropper verwenden fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu beeinträchtigen, während die APK auf dem Gerät weiterhin installierbar bleibt. Die häufigsten Tricks sind:<sup>[[2]](#references)</sup>

- Fake encryption durch Setzen von Bit 0 des ZIP General Purpose Bit Flag (GPBF)
- Missbrauch großer oder benutzerdefinierter Extra-Felder, um Parser zu verwirren
- Kollisionen zwischen Datei- und Verzeichnisnamen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) ohne echte Kryptografie

Symptome:
- `jadx-gui` schlägt mit Fehlern wie diesem fehl:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fordert für zentrale APK-Dateien ein Passwort an, obwohl eine gültige APK keine verschlüsselten `classes*.dex`, `resources.arsc` oder `AndroidManifest.xml` enthalten darf:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Erkennung mit zipdetails:
```bash
zipdetails -v sample.apk | less
```
Sieh dir das General Purpose Bit Flag für lokale und zentrale Header an. Ein verräterischer Wert ist gesetztes Bit 0 (Encryption), selbst bei Core-Einträgen:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn ein APK auf dem Gerät installiert wird und läuft, aber zentrale Einträge für Tools als „verschlüsselt“ erscheinen, wurde das GPBF manipuliert.

Behebung durch Löschen von GPBF-Bit 0 sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen. Minimaler Byte-Patcher:

<details>
<summary>Minimaler GPBF-Bit-Clear-Patcher</summary>
```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
out = bytearray(buf)
i = 0
patched = 0
while True:
i = out.find(sig, i)
if i == -1:
break
flags, = struct.unpack_from('<H', out, i + flag_off)
if flags & 1:  # encryption bit set
struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
patched += 1
i += 4  # move past signature to continue search
return bytes(out), patched

if __name__ == '__main__':
inp, outp = sys.argv[1], sys.argv[2]
data = open(inp, 'rb').read()
data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
open(outp, 'wb').write(data)
print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```
</details>

Verwendung:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sie sollten jetzt `General Purpose Flag  0000` bei den Core-Einträgen sehen, und Tools werden das APK erneut analysieren.

### 2) Große/benutzerdefinierte Extra fields zum Aushebeln von Parsern

Angreifer fügen übergroße Extra fields und ungewöhnliche IDs in Header ein, um Decompiler aus dem Tritt zu bringen. In freier Wildbahn können Sie dort benutzerdefinierte Marker sehen, beispielsweise Zeichenketten wie `JADXBLOCK`.

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:"), die große Payloads enthalten.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra fields bei wichtigen Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra IDs bei diesen Einträgen als verdächtig einstufen.

Praktische Gegenmaßnahme: Das Archiv neu erstellen (z. B. die extrahierten Dateien erneut zu zippen) entfernt schädliche Extra fields. Wenn Tools die Extraktion aufgrund einer vorgetäuschten Verschlüsselung verweigern, zuerst wie oben das GPBF-Bit 0 löschen und anschließend das Archiv neu packen:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kollisionen zwischen Datei-/Verzeichnisnamen (Verbergen echter Artefakte)

Ein ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Einige Extraktoren und Dekompilierer können dadurch verwirrt werden und die echte Datei mit einem Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit zentralen APK-Namen wie `classes.dex` kollidieren.

Triage und sichere Extraktion:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programmatische Erkennung nach der Behebung:
```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
names = z.namelist()

collisions = defaultdict(list)
for n in names:
base = n[:-1] if n.endswith('/') else n
collisions[base].append(n)

for base, variants in collisions.items():
if len(variants) > 1:
print('COLLISION', base, '->', variants)
```
Blue-Team-Erkennungsideen:
- APKs markieren, deren lokale Header Verschlüsselung kennzeichnen (GPBF bit 0 = 1), die sich jedoch installieren/ausführen lassen.
- Große/unbekannte Extra-Felder bei zentralen Einträgen markieren (nach Markern wie `JADXBLOCK` suchen).
- Pfad-Kollisionen (`X` und `X/`) speziell bei `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` markieren.

---

## Andere bösartige ZIP-Tricks (2024–2026)

### Verkettete zentrale Verzeichnisse (Multi-EOCD-Umgehung)

Aktuelle Phishing-Kampagnen versenden einen einzelnen Blob, der tatsächlich aus **zwei aneinandergehängten ZIP-Dateien** besteht. Jede Datei besitzt ihr eigenes End of Central Directory (EOCD) + zentrales Verzeichnis. Verschiedene Extractors parsen unterschiedliche Verzeichnisse (7zip liest das erste, WinRAR das letzte), wodurch Angreifer Payloads verstecken können, die nur bestimmte Tools anzeigen. Dies umgeht auch grundlegendes Mail-Gateway-AV, das nur das erste Verzeichnis untersucht.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage-Befehle**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Wenn mehr als ein EOCD vorkommt oder Warnungen zu „data after payload“ angezeigt werden, teile den Blob auf und untersuche jeden Teil:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / Overlapping-Entry-Bombs (nicht rekursiv)

Moderne „bessere Zip-Bomben“ erstellen einen winzigen **Kernel** (hochkomprimierter **DEFLATE**-Block) und verwenden ihn über überlappende lokale Header mehrfach. Jeder Eintrag im zentralen Verzeichnis verweist auf dieselben komprimierten Daten, wodurch ohne verschachtelte Archive Kompressionsverhältnisse von über 28M:1 erreicht werden. Bibliotheken, die den Größenangaben des zentralen Verzeichnisses vertrauen (`Python zipfile`, `Java java.util.zip`, Info-ZIP vor gehärteten Builds), können dazu gezwungen werden, Petabytes zu allokieren.<sup>[[7]](#references)[[8]](#references)</sup>

**Schnelle Erkennung (doppelte LFH-Offsets)**
```python
# detect overlapping entries by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
i = buf.find(b'PK\x01\x02', off)
if i<0: break
rel = struct.unpack_from('<I', buf, i+42)[0]
if rel in seen:
print('OVERLAP at offset', rel)
break
seen.add(rel); off = i+4
```
**Handhabung**
- Führe einen Dry-Run-Walk durch: `zipdetails -v file.zip | grep -n "Rel Off"` und stelle sicher, dass die Offsets streng monoton steigend und eindeutig sind.
- Begrenze die akzeptierte Gesamtgröße der unkomprimierten Daten und die Anzahl der Einträge vor der Extraktion (`zipdetails -t` oder ein benutzerdefinierter Parser).
- Wenn du extrahieren musst, führe dies innerhalb eines cgroup/VM mit CPU- und Festplattenlimits durch (vermeide Abstürze durch unbounded inflation).

---

### Verwechslung von Local-header- und Central-directory-Parsern

Aktuelle Forschung zu Differential-Parsern hat gezeigt, dass ZIP-Ambiguität in modernen Toolchains weiterhin ausnutzbar ist. Die Grundidee ist einfach: Manche Software vertraut auf den **Local File Header (LFH)**, während andere dem **Central Directory (CD)** vertrauen. Dadurch kann ein Archiv verschiedenen Tools unterschiedliche Dateinamen, Pfade, Kommentare, Offsets oder Entry-Sets präsentieren.<sup>[[9]](#references)</sup>

Praktische offensive Einsatzmöglichkeiten:
- Sorge dafür, dass ein Upload-Filter, ein AV-Pre-Scan oder ein Package-Validator eine harmlose Datei im CD erkennt, während der Extractor einen anderen LFH-Namen oder -Pfad berücksichtigt.
- Missbrauche doppelte Namen, Einträge, die nur in einer der beiden Strukturen vorhanden sind, oder mehrdeutige Unicode-Pfadmetadaten (zum Beispiel das Info-ZIP Unicode Path Extra Field `0x7075`), damit verschiedene Parser unterschiedliche Verzeichnisbäume rekonstruieren.
- Kombiniere dies mit Path Traversal, um eine „harmlose“ Archivansicht während der Extraktion in ein Write-Primitive zu verwandeln. Informationen zur Extraktionsseite findest du unter [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR-Triage:
```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
n, e = struct.unpack_from('<HH', b, i + 26)
lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
n = struct.unpack_from('<H', b, i + 28)[0]
off = struct.unpack_from('<I', b, i + 42)[0]
cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
if off in lfh and cd != lfh[off]:
print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
i += 4
```
Ergänze es mit:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiken:
- Archive mit nicht übereinstimmenden LFH/CD-Namen, doppelten Dateinamen, mehreren EOCD-Records oder nach dem letzten EOCD vorhandenen Bytes zurückweisen oder isolieren.<sup>[[10]](#references)</sup>
- ZIPs mit ungewöhnlichen Unicode-Pfad-Extra-Feldern oder inkonsistenten Kommentaren als verdächtig behandeln, wenn verschiedene Tools sich beim extrahierten Verzeichnisbaum nicht einig sind.<sup>[[9]](#references)</sup>
- Wenn die Analyse wichtiger ist als die Bewahrung der ursprünglichen Bytes, das Archiv nach der Extraktion in einer sandbox mit einem strikten parser neu verpacken und die resultierende Dateiliste mit den ursprünglichen Metadaten vergleichen.

Dies ist nicht nur für Package-Ökosysteme relevant: Dieselbe Mehrdeutigkeitsklasse kann Payloads vor Mail-Gateways, statischen Scannern und benutzerdefinierten Ingestion-Pipelines verbergen, die einen Blick in ZIP-Inhalte werfen, bevor ein anderer extractor das Archiv verarbeitet.

---



## Referenzen

- [1] [Leitfaden zur CTF-Forensik (Mikes Blog, CTF-Kategorie)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Teil 1 – Ein mehrstufiger dropper (APK-ZIP-Anti-Reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip-Script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Spezifikation des ZIP-Dateiformats (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Struktur von ZIP-Archiven zum unentdeckten Verbergen von Malware ausgenutzt (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hacker verstecken Malware in neuem ZIP-Dateiangriff – verkettete zentrale ZIP-Verzeichnisse](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Eine bessere zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Zip-Bomben verstehen: Konstruktion des Overlapping/Quoted-Overlap-Kernels](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mein ZIP ist nicht dein ZIP: Semantische Lücken zwischen ZIP-Parsern identifizieren und ausnutzen (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [ZIP-Parser-Confusion-Angriffe auf Python-Package-Installer verhindern](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP-Angriffe mit reduziertem bekanntem Klartext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known-Plaintext-Angriff: ZIP-Dateien knacken](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
