# ZIP-Tricks

**Command-line tools** zur Verwaltung von **zip files** sind unerlässlich für die Diagnose, Reparatur und das Cracking von zip files. Hier sind einige wichtige Utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Zeigt, warum eine zip file möglicherweise nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des zip file-Formats.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Listet den Inhalt einer zip file auf, ohne ihn zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte zip files zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Cracking von zip passwords, das bei passwords mit bis zu etwa 7 Zeichen effektiv ist.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) enthält umfassende Details zur Struktur und zu den Standards von zip files.<sup>[[4]](#references)</sup>

Es ist wichtig zu beachten, dass herkömmliche password-geschützte ZIP files im Allgemeinen filenames und file sizes sichtbar lassen, anders als die von RAR und 7z unterstützten header-encryption modes. Außerdem sind ZIP files, die mit der älteren ZipCrypto-Methode verschlüsselt wurden, für einen **plaintext attack** anfällig, wenn eine unverschlüsselte Kopie einer komprimierten file verfügbar ist.<sup>[[1]](#references)</sup> Dieser Angriff nutzt den bekannten Inhalt, um das ZIP password zu knacken, wie in [diesem akademischen Paper](https://math.ucr.edu/~mike/zipattacks.pdf) erklärt und in diesem [Hack This Site walk-through](https://www.hackthissite.org/articles/read/793) veranschaulicht wird.<sup>[[11]](#references)[[12]](#references)</sup> Der ZipCrypto known-plaintext attack gilt jedoch nicht für Einträge, die mit **AES-256** encryption gesichert sind.<sup>[[1]](#references)</sup>

---

## Anti-Reversing-Tricks in APKs mit manipulierten ZIP headers

Moderne Android malware droppers verwenden fehlerhafte ZIP metadata, um statische Tools (jadx/apktool/unzip) zu stören, während die APK auf dem Gerät installierbar bleibt. Die häufigsten Tricks sind:<sup>[[2]](#references)</sup>

- Fake encryption durch Setzen von Bit 0 des ZIP General Purpose Bit Flag (GPBF)
- Missbrauch großer oder benutzerdefinierter Extra fields, um Parser zu verwirren
- Kollisionen zwischen Datei- und Verzeichnisnamen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) ohne echte crypto

Symptome:
- `jadx-gui` schlägt mit Fehlern wie diesem fehl:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fordert für zentrale APK files ein password an, obwohl eine gültige APK keine verschlüsselten `classes*.dex`, `resources.arsc` oder `AndroidManifest.xml` enthalten kann:

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
Sehen Sie sich das General Purpose Bit Flag für lokale und zentrale Header an. Ein verräterischer Wert ist gesetztes Bit 0 (Encryption), selbst bei Kerneinträgen:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn ein APK auf dem Gerät installiert wird und läuft, aber zentrale Einträge für Tools „verschlüsselt“ erscheinen, wurde das GPBF manipuliert.

Behebung durch Löschen von GPBF-Bit 0 sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen. Minimaler Byte-Patcher:

<details>
<summary>Minimaler Patcher zum Löschen des GPBF-Bits</summary>
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
Sie sollten nun `General Purpose Flag  0000` in den Core-Einträgen sehen, und Tools werden die APK erneut parsen.

### 2) Große/benutzerdefinierte Extra fields zum Stören von Parsern

Angreifer fügen übergroße Extra fields und ungewöhnliche IDs in Header ein, um Decompiler aus dem Tritt zu bringen. In freier Wildbahn können Sie dort eingebettete benutzerdefinierte Marker sehen (z. B. Zeichenfolgen wie `JADXBLOCK`).

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:"), die große Payloads enthalten.<sup>[[2]](#references)</sup>

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra-Felder bei zentralen Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra-IDs bei diesen Einträgen als verdächtig behandeln.

Praktische Gegenmaßnahme: Das Archiv neu erstellen (z. B. extrahierte Dateien erneut zippen) entfernt schädliche Extra-Felder. Wenn Tools die Extraktion aufgrund einer gefälschten Verschlüsselung verweigern, zuerst wie oben das GPBF-Bit 0 löschen und anschließend das Archiv neu packen:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kollisionen von Datei-/Verzeichnisnamen (Verbergen echter Artefakte)

Ein ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Einige Extractor und Decompiler können dadurch verwirrt werden und die echte Datei mit einem Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit zentralen APK-Namen wie `classes.dex` kollidieren.

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
Ideen zur Erkennung durch das Blue-Team:
- APKs kennzeichnen, deren lokale Header eine Verschlüsselung markieren (GPBF bit 0 = 1), die sich jedoch installieren/ausführen lassen.
- Große/unbekannte Extra fields bei wichtigen Einträgen kennzeichnen (nach Markern wie `JADXBLOCK` suchen).
- Pfad-Kollisionen (`X` und `X/`) speziell bei `AndroidManifest.xml`, `resources.arsc` und `classes*.dex` kennzeichnen.

---

## Andere bösartige ZIP-Tricks (2024–2026)

### Verkettete central directories (Multi-EOCD-Umgehung)

In einer Phishing-Kampagne von 2024 lieferten Angreifer ein einzelnes Blob aus, das tatsächlich aus **zwei verketteten ZIP-Dateien** bestand. Jede Datei hatte ihren eigenen End-of-Central-Directory-(EOCD-)Datensatz und ihr eigenes central directory. Verschiedene Extractors analysierten unterschiedliche Verzeichnisse (7-Zip las das erste, während WinRAR das letzte las). Dadurch konnten Angreifer Payloads verbergen, die nur von einigen Tools angezeigt wurden; Scanner, die nur ein Verzeichnis prüfen, können das andere Archiv übersehen.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage-Befehle**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Wenn mehr als ein EOCD vorkommt oder Warnungen zu „data after payload“ angezeigt werden, teile den Blob auf und untersuche jeden Teil:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs erstellen einen winzigen **Kernel** (einen stark komprimierten DEFLATE-Block) und verwenden ihn überlappend in mehreren Einträgen wieder. Full-overlap-Varianten verweisen mit mehreren Central-Directory-Einträgen auf einen Local Header, während Quoted-overlap-Varianten Local Headers innerhalb von DEFLATE-Streams zitieren; die veröffentlichte Konstruktion erreicht ohne verschachtelte Archive mehr als 28M:1.<sup>[[7]](#references)</sup>

**Schnellerkennung (doppelte LFH-Offsets)**
```python
# detect full-overlap variants by identical relative offsets
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
- Führe einen Dry-Run-Walk durch: `zipdetails -v file.zip | grep -n "Local Header Offset"` und vergleiche die referenzierten Local-Header-Offsets sowie die Bereiche der komprimierten Daten; doppelte Offsets weisen auf Varianten mit vollständiger Überlappung hin.<sup>[[7]](#references)[[8]](#references)</sup>
- Begrenze die akzeptierte Gesamtgröße der dekomprimierten Daten und die Anzahl der Einträge vor der Extraktion mit einem Parser; `zipinfo -t file.zip` meldet die Gesamtwerte, setzt jedoch kein Sicherheitslimit durch.<sup>[[8]](#references)</sup>
- Wenn du extrahieren musst, führe dies innerhalb eines cgroup/VM mit CPU- und Festplattenlimits durch (um Abstürze durch unbeschränkte Dekomprimierung zu vermeiden).<sup>[[8]](#references)</sup>

---

### Verwechslung von Local-Header- und Central-Directory-Parsern

Aktuelle Forschung zu Differential-Parsern hat gezeigt, dass ZIP-Ambiguität in modernen Toolchains weiterhin ausnutzbar ist. Die grundlegende Idee ist einfach: Manche Software vertraut auf den **Local File Header (LFH)**, während andere dem **Central Directory (CD)** vertrauen. Dadurch kann ein Archiv verschiedenen Tools unterschiedliche Dateinamen, Pfade, Kommentare, Offsets oder Eintragsmengen präsentieren.<sup>[[9]](#references)</sup>

Praktische offensive Anwendungen:
- Einen Upload-Filter, AV-Pre-Scan oder Package-Validator dazu bringen, eine harmlose Datei im CD zu sehen, während der Extractor einen anderen LFH-Namen/-Pfad berücksichtigt.
- Doppelte Namen, Einträge, die nur in einer der Strukturen vorhanden sind, oder mehrdeutige Unicode-Pfad-Metadaten (zum Beispiel das Info-ZIP Unicode Path Extra Field `0x7075`) ausnutzen, damit verschiedene Parser unterschiedliche Verzeichnisbäume rekonstruieren.
- Dies mit Path Traversal kombinieren, um eine „harmlose“ Archivansicht während der Extraktion in ein Write-Primitive umzuwandeln. Informationen zur Extraktionsseite findest du unter [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Bitte sende den Text, den ich ergänzen und ins Deutsche übersetzen soll.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiken:
- Bei sicherheitskritischer Verarbeitung sollten Archive mit nicht übereinstimmenden LFH/CD-Namen, doppelten Dateinamen, mehreren EOCD-Datensätzen oder nach dem letzten EOCD vorhandenen nachgestellten Bytes abgelehnt oder isoliert werden.<sup>[[9]](#references)[[10]](#references)</sup>
- ZIPs, die ungewöhnliche Unicode-Pfad-Extra-Felder oder inkonsistente Kommentare verwenden, sollten als verdächtig behandelt werden, wenn verschiedene Tools beim Extrahieren des Verzeichnisbaums zu unterschiedlichen Ergebnissen kommen.<sup>[[4]](#references)[[9]](#references)</sup>
- Wenn die Analyse wichtiger ist als die Bewahrung der ursprünglichen Bytes, sollte das Archiv nach der Extraktion in einer Sandbox mit einem strikten Parser neu gepackt und die resultierende Dateiliste mit den ursprünglichen Metadaten verglichen werden.

Dies ist nicht nur für Package-Ökosysteme relevant: Dieselbe Mehrdeutigkeitsklasse kann Payloads vor Mail-Gateways, statischen Scannern und benutzerdefinierten Ingestion-Pipelines verbergen, die den Inhalt von ZIPs zunächst „prüfen“, bevor ein anderer Extractor das Archiv verarbeitet.<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF-Forensik-Leitfaden (Mikes Blog, CTF-Kategorie)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Teil 1 – Ein mehrstufiger Dropper (APK-ZIP-Anti-Reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress-Skript)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Spezifikation des ZIP-Dateiformats (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Struktur von ZIP-Archiven ausgenutzt, um Malware unentdeckt zu verbergen (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hacker vergraben Malware in einem neuen ZIP-Dateiangriff – verkettete zentrale ZIP-Verzeichnisse](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Eine bessere Zip-Bombe (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zip-Bomben verstehen: Konstruktion eines überlappenden/als überlappend angegebenen Kernels](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Meine ZIP-Datei ist nicht deine ZIP-Datei: Erkennen und Ausnutzen semantischer Lücken zwischen ZIP-Parsern (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Angriffe durch ZIP-Parser-Verwirrung bei Installern von Python-Packages verhindern](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP-Angriffe mit reduziertem bekanntem Klartext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistische Web-Mission, Level 15 (ZIP-Angriff mit bekanntem Klartext)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
