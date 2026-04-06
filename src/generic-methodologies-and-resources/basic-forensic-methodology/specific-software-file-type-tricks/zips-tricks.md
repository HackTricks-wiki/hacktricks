# ZIP-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Kommandozeilen-Tools** zum Verwalten von ZIP-Dateien sind essenziell, um ZIP-Dateien zu diagnostizieren, zu reparieren und zu knacken. Hier sind einige wichtige Utilities:

- **`unzip`**: Zeigt, warum sich eine ZIP-Datei möglicherweise nicht entpacken lässt.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des ZIP-Dateiformats.
- **`zipinfo`**: Listet den Inhalt einer ZIP-Datei auf, ohne sie zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte ZIP-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von ZIP-Passwörtern, effektiv bei Passwörtern von bis zu etwa 7 Zeichen.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) liefert umfassende Details zur Struktur und den Standards von ZIP-Dateien.

Es ist wichtig zu beachten, dass passwortgeschützte ZIP-Dateien **Dateinamen oder Dateigrößen nicht verschlüsseln**, ein Sicherheitsmangel, der bei RAR oder 7z, die diese Informationen verschlüsseln, nicht auftritt. Darüber hinaus sind ZIP-Dateien, die mit der älteren ZipCrypto-Methode verschlüsselt sind, gegenüber einer **plaintext attack** verwundbar, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Diese Attacke nutzt den bekannten Inhalt, um das ZIP-Passwort zu knacken — eine Schwachstelle, die in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beschrieben und in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) näher erläutert wird. ZIP-Dateien, die hingegen mit **AES-256** verschlüsselt sind, sind gegen diese plaintext attack immun, was die Bedeutung der Wahl sicherer Verschlüsselungsverfahren für sensible Daten unterstreicht.

---

## Anti-Reversing-Tricks in APKs durch manipulierte ZIP-Header

Moderne Android-Malware-Dropper verwenden fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu stören, während die APK auf dem Gerät weiterhin installierbar bleibt. Die gängigsten Tricks sind:

- Gefälschte Verschlüsselung durch Setzen des ZIP General Purpose Bit Flag (GPBF) Bit 0
- Ausnutzung großer/benutzerdefinierter Extra-Felder, um Parser zu verwirren
- Datei-/Verzeichnisnamen-Kollisionen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptome:
- `jadx-gui` schlägt fehl mit Fehlern wie:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fragt nach einem Passwort für wichtige APK-Dateien, obwohl eine gültige APK keine verschlüsselten `classes*.dex`, `resources.arsc`, oder `AndroidManifest.xml` haben kann:

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
Schauen Sie sich das General Purpose Bit Flag für die lokalen und zentralen Header an. Ein verräterischer Wert ist, dass Bit 0 gesetzt ist (Encryption), selbst bei core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn eine APK auf dem Gerät installiert und ausgeführt wird, Kern‑Einträge für Tools aber als "verschlüsselt" erscheinen, wurde das GPBF manipuliert.

Beheben durch Löschen von GPBF Bit 0 sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen. Minimaler Byte-Patcher:

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
Du solltest nun `General Purpose Flag  0000` bei den Core-Einträgen sehen, und Tools werden das APK wieder parsen.

### 2) Große/benutzerdefinierte Extra-Felder, um Parser zu brechen

Angreifer stopfen übergroße Extra-Felder und ungewöhnliche IDs in Header, um Decompiler auszutricksen. In freier Wildbahn kannst du dort benutzerdefinierte Marker (z. B. Strings wie `JADXBLOCK`) eingebettet sehen.

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: Unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:") mit großen payloads.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra-Felder bei Kern-Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra-IDs in diesen Einträgen als verdächtig einstufen.

Praktische Gegenmaßnahme: Das Neuaufbauen des Archives (z. B. erneutes Zippen der extrahierten Dateien) entfernt bösartige Extra-Felder. Wenn Tools das Extrahieren wegen Fake-Verschlüsselung verweigern, zuerst GPBF bit 0 wie oben löschen, dann neu verpacken:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Datei-/Verzeichnisnamenskollisionen (verstecken realer Artefakte)

Eine ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Manche extractors und decompilers werden dadurch verwirrt und können die echte Datei durch einen Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit Kern-APK-Namen wie `classes.dex` kollidieren.

Triage und sicheres Extrahieren:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programmatische Erkennung (Nachsilbe):
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
Blue-team Erkennungs-Ideen:
- Flag APKs deren lokale Header Verschlüsselung markieren (GPBF bit 0 = 1), aber dennoch installiert/ausgeführt werden.
- Flag große/unkannte Extra-Felder bei Kern-Einträgen (suche nach Markern wie `JADXBLOCK`).
- Flag Pfad-Kollisionen (`X` and `X/`) speziell für `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Andere bösartige ZIP-Tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Aktuelle Phishing-Kampagnen liefern ein einzelnes Blob, das tatsächlich **zwei ZIP files concatenated** ist. Jede enthält ihr eigenes End of Central Directory (EOCD) + central directory. Verschiedene Extractoren parsen unterschiedliche Verzeichnisse (7zip liest das erste, WinRAR das letzte), wodurch Angreifer Payloads verbergen können, die nur einige Tools anzeigen. Das umgeht auch einfache Mail-Gateway-AVs, die nur das erste Verzeichnis inspizieren.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Wenn mehr als ein EOCD erscheint oder es "data after payload"-Warnungen gibt, teile den Blob und untersuche jeden Teil:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb" erzeugt einen winzigen **Kernel** (stark komprimierter DEFLATE-Block) und verwendet ihn mehrfach über überlappende Local Headers. Jeder Eintrag im Central Directory zeigt auf dieselben komprimierten Daten und erzielt Verhältnisse >28M:1 ohne geschachtelte Archive. Bibliotheken, die den Größen im Central Directory vertrauen (Python `zipfile`, Java `java.util.zip`, Info-ZIP vor gehärteten Builds), können dazu gebracht werden, Petabytes zuzuweisen.

**Schnelle Erkennung (duplizierte LFH-Offsets)**
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
- Führen Sie einen Trockendurchlauf durch: `zipdetails -v file.zip | grep -n "Rel Off"` und stellen Sie sicher, dass die Offsets strikt ansteigend und einzigartig sind.
- Begrenzen Sie die akzeptierte gesamte unkomprimierte Größe und die Anzahl der Einträge vor der Extraktion (`zipdetails -t` oder eigener Parser).
- Wenn Sie extrahieren müssen, tun Sie dies innerhalb einer cgroup/VM mit CPU- und Festplattenlimits (vermeiden Sie unkontrollierbares Aufblähen, das zu Abstürzen führt).

---

### Local-header vs central-directory parser confusion

Jüngste differential-parser-Forschung zeigte, dass ZIP-Ambiguität in modernen Toolchains weiterhin ausnutzbar ist. Die Grundidee ist einfach: manche Software vertraut dem **Local File Header (LFH)**, während andere dem **Central Directory (CD)** vertrauen, sodass ein Archiv verschiedenen Tools unterschiedliche Dateinamen, Pfade, Kommentare, Offsets oder Eintragsmengen präsentieren kann.

Praktische offensive Einsatzmöglichkeiten:
- Lassen Sie einen Upload-Filter, AV-Pre-Scan oder Paketvalidator im CD eine harmlose Datei sehen, während der Extractor einen anderen LFH-Namen/-Pfad beachtet.
- Missbrauchen Sie doppelte Namen, Einträge, die nur in einer Struktur vorhanden sind, oder mehrdeutige Unicode-Pfadmetadaten (zum Beispiel Info-ZIP Unicode Path Extra Field `0x7075`), sodass verschiedene Parser unterschiedliche Bäume rekonstruieren.
- Kombinieren Sie dies mit path traversal, um eine "harmlos" erscheinende Archivansicht während der Extraktion in eine write-primitive zu verwandeln. For the extraction side, see [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Ich habe keinen Text bzw. Auszug aus der Datei erhalten. Bitte füge hier den englischen Inhalt ein, den ich übersetzen und ergänzen soll — oder beschreibe genau, welche Ergänzung du möchtest (z. B. Beispiele, Befehle, zusätzliche Hinweise). 

Hinweis: Ich übersetze relevanten englischen Text ins Deutsche und lasse Markdown, HTML-Tags, Links, Pfade, Code, Technik‑/Plattform‑Namen und die angegebenen Tags unverändert, wie gewünscht.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Archive ablehnen oder isolieren, die nicht übereinstimmende LFH/CD-Namen, doppelte Dateinamen, mehrere EOCD-Einträge oder nachlaufende Bytes nach dem letzten EOCD aufweisen.
- ZIPs, die ungewöhnliche Unicode-path extra fields oder inkonsistente Kommentare verwenden, als verdächtig einstufen, wenn verschiedene Tools beim extrahierten Verzeichnisbaum zu unterschiedlichen Ergebnissen kommen.
- Wenn die Analyse wichtiger ist als das Bewahren der Originalbytes, das Archiv nach der Extraktion in einer sandbox mit einem strikten Parser neu verpacken und die resultierende Dateiliste mit den ursprünglichen Metadaten vergleichen.

This matters beyond package ecosystems: the same ambiguity class can hide payloads from mail gateways, static scanners, and custom ingestion pipelines that "peek" at ZIP contents before a different extractor handles the archive.

---



## Referenzen

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
