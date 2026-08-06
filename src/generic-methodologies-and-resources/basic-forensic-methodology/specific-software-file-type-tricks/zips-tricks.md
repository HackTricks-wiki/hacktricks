# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** zur Verwaltung von **zip files** sind für die Diagnose, Reparatur und das Cracking von zip files unerlässlich. Hier sind einige wichtige Utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Zeigt, warum ein zip file möglicherweise nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des zip file-Formats.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Listet den Inhalt eines zip file auf, ohne ihn zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte zip files zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Cracking von zip passwords, das bei passwords mit bis zu etwa 7 Zeichen effektiv ist.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) enthält umfassende Details zur Struktur und zu den Standards von zip files.<sup>[[4]](#references)</sup>

Es ist wichtig zu beachten, dass password-protected zip files **weder filenames noch file sizes** der enthaltenen Dateien verschlüsseln – ein Sicherheitsmangel, der bei RAR- oder 7z files nicht vorhanden ist, da diese Informationen dort verschlüsselt werden. Außerdem sind zip files, die mit der älteren ZipCrypto-Methode verschlüsselt wurden, anfällig für einen **plaintext attack**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist.<sup>[[1]](#references)</sup> Dieser Angriff nutzt den bekannten Inhalt, um das password des zip zu cracken – eine Schwachstelle, die im [Artikel von HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beschrieben und in [diesem wissenschaftlichen Paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) weiter erläutert wird.<sup>[[11]](#references)[[12]](#references)</sup> Mit **AES-256** encryption gesicherte zip files sind jedoch gegen diesen plaintext attack immun, was die Bedeutung der Auswahl sicherer encryption methods für sensible Daten verdeutlicht.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Moderne Android malware droppers verwenden fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu beeinträchtigen, während die APK auf dem Gerät weiterhin installierbar bleibt. Die häufigsten tricks sind:<sup>[[2]](#references)</sup>

- Fake encryption durch Setzen von Bit 0 des ZIP General Purpose Bit Flag (GPBF)
- Missbrauch großer oder benutzerdefinierter Extra fields zur Verwirrung von Parsern
- Kollisionen bei Datei-/Verzeichnisnamen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben dem echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptome:
- `jadx-gui` schlägt mit Fehlern wie diesem fehl:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fordert ein password für zentrale APK-Dateien an, obwohl eine gültige APK keine verschlüsselten `classes*.dex`, `resources.arsc` oder `AndroidManifest.xml` enthalten kann:

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
Betrachte das General Purpose Bit Flag für lokale und zentrale Header. Ein charakteristischer Wert ist Bit 0 gesetzt (Encryption), selbst bei Core-Einträgen:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn sich ein APK auf dem Gerät installieren und ausführen lässt, aber zentrale Einträge für Tools als „encrypted“ erscheinen, wurde das GPBF manipuliert.

Behebe dies, indem du Bit 0 des GPBF sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen löschst. Minimaler Byte-Patcher:

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
Du solltest jetzt `General Purpose Flag  0000` bei den Kern-Einträgen sehen, und Tools werden das APK erneut parsen.

### 2) Große/benutzerdefinierte Extra-Felder zum Stören von Parsern

Angreifer fügen übergroße Extra-Felder und ungewöhnliche IDs in Header ein, um Decompiler aus dem Tritt zu bringen. In freier Wildbahn können dort benutzerdefinierte Marker eingebettet sein (z. B. Zeichenfolgen wie `JADXBLOCK`).

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:"), die große Payloads enthalten.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra fields bei zentralen Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra IDs bei diesen Einträgen als verdächtig einstufen.

Praktische Gegenmaßnahme: Das erneute Erstellen des Archivs (z. B. das erneute Verpacken extrahierter Dateien als ZIP) entfernt schädliche Extra fields. Wenn Tools die Extraktion aufgrund einer vorgetäuschten Verschlüsselung verweigern, zuerst wie oben das GPBF-Bit 0 löschen und anschließend das Paket neu erstellen:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Datei-/Verzeichnisnamenskollisionen (Verbergen echter Artefakte)

Ein ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Einige Extractors und Decompiler geraten dadurch durcheinander und können die echte Datei mit einem Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit wichtigen APK-Namen wie `classes.dex` kollidieren.

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
Programmgesteuerte Erkennung nach der Behebung:
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
Blue-team detection ideas:
- APKs markieren, deren lokale Header Verschlüsselung kennzeichnen (GPBF bit 0 = 1), die sich jedoch installieren/ausführen lassen.
- Große/unbekannte Extra-Felder bei zentralen Einträgen markieren (nach Markern wie `JADXBLOCK` suchen).
- Pfad-Kollisionen (`X` und `X/`) gezielt für `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` markieren.

---

## Andere bösartige ZIP-Tricks (2024–2026)

### Verkettete zentrale Verzeichnisse (Multi-EOCD-Umgehung)

Aktuelle Phishing-Kampagnen versenden einen einzelnen Blob, der tatsächlich aus **zwei verketteten ZIP-Dateien** besteht. Jede Datei besitzt ihr eigenes End of Central Directory (EOCD) und zentrales Verzeichnis. Verschiedene Extractors analysieren unterschiedliche Verzeichnisse (7zip liest das erste, WinRAR das letzte), wodurch Angreifer Payloads verbergen können, die nur einige Tools anzeigen. Dies umgeht außerdem grundlegende Mail-Gateway-AV-Systeme, die nur das erste Verzeichnis untersuchen.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage-Befehle**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Wenn mehr als ein EOCD vorkommt oder Warnungen wie „data after payload“ erscheinen, teile den Blob auf und untersuche jeden Teil:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb"-Varianten erstellen einen winzigen **kernel** (hochkomprimierten DEFLATE-Block) und verwenden ihn überlappende lokale Header wieder. Jeder Eintrag im central directory verweist auf dieselben komprimierten Daten und erreicht dadurch Verhältnisse von über 28M:1, ohne Archive zu verschachteln. Bibliotheken, die den Größenangaben des central directory vertrauen (Python `zipfile`, Java `java.util.zip`, Info-ZIP vor gehärteten Builds), können dazu gezwungen werden, Petabytes zu reservieren.<sup>[[7]](#references)[[8]](#references)</sup>

**Schnelle Erkennung (doppelte LFH offsets)**
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
- Führe einen Dry-Run-Durchlauf aus: `zipdetails -v file.zip | grep -n "Rel Off"` und stelle sicher, dass die Offsets strikt aufsteigend und eindeutig sind.
- Begrenze die akzeptierte gesamte unkomprimierte Größe und die Anzahl der Einträge vor der Extraktion (`zipdetails -t` oder eigener Parser).
- Wenn du extrahieren musst, führe dies innerhalb eines cgroup/VM mit CPU- und Disk-Limits aus (vermeide Abstürze durch unbounded inflation).

---

### Verwirrung zwischen Local-Header- und Central-Directory-Parsern

Aktuelle Forschung zu Differential-Parsern hat gezeigt, dass ZIP-Ambiguität in modernen Toolchains weiterhin ausnutzbar ist. Die Grundidee ist einfach: Manche Software vertraut auf den **Local File Header (LFH)**, während andere dem **Central Directory (CD)** vertrauen. Dadurch kann ein Archiv verschiedenen Tools unterschiedliche Dateinamen, Pfade, Kommentare, Offsets oder Entry-Sets präsentieren.<sup>[[9]](#references)</sup>

Praktische offensive Einsatzmöglichkeiten:
- Sorge dafür, dass ein Upload-Filter, ein AV-Pre-Scan oder ein Package-Validator eine harmlose Datei im CD erkennt, während der Extractor einen anderen LFH-Namen/-Pfad verwendet.
- Nutze Duplicate Names, Einträge, die nur in einer der Strukturen vorhanden sind, oder mehrdeutige Unicode-Pfadmetadaten (zum Beispiel das Info-ZIP Unicode Path Extra Field `0x7075`), damit verschiedene Parser unterschiedliche Trees rekonstruieren.
- Kombiniere dies mit Path Traversal, um aus einer „harmlosen“ Archivansicht während der Extraktion eine Write-Primitive zu machen. Informationen zur Extraktionsseite findest du unter [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
- Archive mit nicht übereinstimmenden LFH/CD-Namen, doppelten Dateinamen, mehreren EOCD-Records oder nach dem letzten EOCD vorhandenen nachgestellten Bytes ablehnen oder isolieren.<sup>[[10]](#references)</sup>
- ZIPs, die ungewöhnliche Unicode-Pfad-Extra-Felder oder inkonsistente Kommentare verwenden, als verdächtig behandeln, wenn verschiedene Tools unterschiedliche extrahierte Dateibäume liefern.<sup>[[9]](#references)</sup>
- Wenn die Analyse wichtiger ist als die Bewahrung der ursprünglichen Bytes, das Archive nach der Extraktion in einer Sandbox mit einem strikten Parser neu paketieren und die resultierende Dateiliste mit den ursprünglichen Metadaten vergleichen.

Dies ist nicht nur für Paketökosysteme relevant: Dieselbe Mehrdeutigkeitsklasse kann Payloads vor Mail-Gateways, statischen Scannern und benutzerdefinierten Ingestion-Pipelines verbergen, die den Inhalt von ZIPs zunächst „überprüfen“, bevor ein anderer Extractor das Archive verarbeitet.

---



## Referenzen

- [1] [CTF-Forensics-Leitfaden (Mikes Blog, CTF-Kategorie)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Teil 1 – Ein mehrstufiger Dropper (APK-ZIP-Anti-Reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip-Skript)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Spezifikation des ZIP-Dateiformats (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Struktur von ZIP-Archiven zur unentdeckten Verschleierung von Malware ausgenutzt (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hacker vergraben Malware in einem neuen ZIP-Dateiangriff – verkettete zentrale ZIP-Verzeichnisse](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Eine bessere Zip-Bombe (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Zip-Bomben verstehen: Konstruktion des Overlapping/Quoted-Overlap-Kernels](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mein ZIP ist nicht dein ZIP: Semantische Lücken zwischen ZIP-Parsern erkennen und ausnutzen (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [ZIP-Parser-Confusion-Angriffe auf Python-Package-Installer verhindern](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP-Angriffe mit reduziertem bekanntem Klartext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known-Plaintext-Angriff: ZIP-Dateien knacken](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
