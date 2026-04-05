# ZIPs-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Kommandozeilen-Tools** zur Verwaltung von **ZIP-Dateien** sind unerlässlich, um ZIP-Dateien zu diagnostizieren, zu reparieren und zu knacken. Hier sind einige wichtige Werkzeuge:

- **`unzip`**: Zeigt, warum sich eine ZIP-Datei möglicherweise nicht dekomprimieren lässt.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des ZIP-Dateiformats.
- **`zipinfo`**: Listet den Inhalt einer ZIP-Datei auf, ohne die Dateien zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte ZIP-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von ZIP-Passwörtern, wirksam für Passwörter bis etwa 7 Zeichen.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) liefert umfassende Informationen zur Struktur und den Standards von ZIP-Dateien.

Es ist wichtig zu beachten, dass passwortgeschützte ZIP-Dateien **verschlüsseln nicht Dateinamen oder Dateigrößen**, ein Sicherheitsmangel, der bei RAR- oder 7z-Dateien, die diese Informationen verschlüsseln, nicht auftritt. Darüber hinaus sind mit dem älteren ZipCrypto-Verfahren verschlüsselte ZIP-Dateien anfällig für einen **plaintext attack**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt, um das Passwort der ZIP zu knacken — eine Schwachstelle, die im Artikel [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) detailliert beschrieben und in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) weiter erläutert wird. ZIP-Dateien, die mit **AES-256** verschlüsselt sind, sind gegen diesen **plaintext attack** immun, was die Bedeutung sicherer Verschlüsselungsmethoden für sensible Daten unterstreicht.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Moderne Android-Malware-Dropper nutzen fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zum Scheitern zu bringen, während die APK weiterhin auf dem Gerät installierbar bleibt. Die gebräuchlichsten Tricks sind:

- Gefälschte Verschlüsselung durch Setzen des ZIP General Purpose Bit Flag (GPBF) Bit 0
- Ausnutzung großer/benutzerdefinierter Extra-Felder, um Parser zu verwirren
- Kollisionen von Datei-/Verzeichnisnamen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptome:
- `jadx-gui` schlägt fehl mit Fehlern wie:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fordert ein Passwort für Kern-APK-Dateien an, obwohl eine gültige APK keine verschlüsselten `classes*.dex`, `resources.arsc`, oder `AndroidManifest.xml` haben kann:

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
Sieh dir das General Purpose Bit Flag für lokale und zentrale Header an. Ein verräterischer Wert ist, dass Bit 0 gesetzt ist (Encryption) selbst bei Kerneinträgen:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn eine APK auf dem Gerät installiert und ausgeführt wird, aber Kerneinträge für Tools als "encrypted" erscheinen, wurde das GPBF manipuliert.

Abhilfe: GPBF-Bit 0 sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen löschen. Minimaler Byte-Patcher:

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
Sie sollten jetzt `General Purpose Flag  0000` bei core entries sehen und Tools werden das APK erneut parsen.

### 2) Große/benutzerdefinierte Extra-Felder, um Parser zu brechen

Angreifer füllen Header mit übergroßen Extra-Feldern und ungewöhnlichen IDs, um decompilers zu stören. In freier Wildbahn können Sie dort eingebettete benutzerdefinierte Marker sehen (z. B. Strings wie `JADXBLOCK`).

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:") mit großen payloads.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra fields bei wichtigen Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra-IDs in diesen Einträgen als verdächtig einstufen.

Praktische Gegenmaßnahme: Das Neuaufbauen des Archivs (z. B. erneutes Zippen der extrahierten Dateien) entfernt bösartige Extra fields. Falls Tools aufgrund gefälschter Verschlüsselung die Extraktion verweigern, zuerst GPBF bit 0 wie oben löschen, dann neu verpacken:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Datei-/Verzeichnis-Kollisionen (Verbergen echter Artefakte)

Ein ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Some extractors und decompilers werden verwirrt und können die echte Datei durch einen Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit Kern-APK-Namen wie `classes.dex` kollidieren.

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
Programmgesteuerte Erkennung Postfix:
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
Blue-team Erkennungsansätze:
- Markiere APKs, deren lokale Header Verschlüsselung markieren (GPBF bit 0 = 1), die sich dennoch installieren/ausführen.
- Markiere große/unklare Extra-Felder auf Kern-Einträgen (achte auf Marker wie `JADXBLOCK`).
- Markiere Pfad-Kollisionen (`X` und `X/`) speziell für `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Andere bösartige ZIP-Tricks (2024–2026)

### Konkatenierte zentrale Verzeichnisse (multi-EOCD-Umgehung)

Aktuelle Phishing-Kampagnen liefern ein einzelnes Blob, das tatsächlich aus **zwei aneinandergehängten ZIP-Dateien** besteht. Jede hat ihren eigenen End of Central Directory (EOCD) + central directory. Unterschiedliche Extractoren parsen unterschiedliche Verzeichnisse (7zip liest das erste, WinRAR das letzte), wodurch Angreifer payloads verbergen können, die nur einige Tools anzeigen. Dies umgeht auch grundlegende Mail-Gateway-AVs, die nur das erste Verzeichnis inspizieren.

**Triage-Befehle**
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

Moderne "better zip bomb" baut einen winzigen **Kern** (stark komprimierter DEFLATE-Block) und nutzt ihn mehrfach über überlappende local headers. Jeder Eintrag im central directory zeigt auf dieselben komprimierten Daten und erzielt Verhältnisse von >28M:1 ohne verschachtelte Archive. Bibliotheken, die den Größen im central directory vertrauen (Python `zipfile`, Java `java.util.zip`, Info-ZIP vor gehärteten Builds), können dazu gebracht werden, Petabytes zuzuweisen.

**Schnelle Erkennung (duplicate LFH offsets)**
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
- Führe einen Dry-Run durch: `zipdetails -v file.zip | grep -n "Rel Off"` und stelle sicher, dass die Offsets streng ansteigend und eindeutig sind.
- Begrenze die akzeptierte gesamte unkomprimierte Größe und die Anzahl der Einträge vor der Extraktion (`zipdetails -t` oder eigener Parser).
- Wenn du extrahieren musst, tu dies innerhalb einer cgroup/VM mit CPU- und Festplattenlimits (vermeide ungebremste Aufblähung/Abstürze).

---

### Konfusion zwischen Local-header- und Central-directory-Parsern

Kürzliche Forschung zu differential-parsing hat gezeigt, dass ZIP-Ambiguität in modernen Toolchains weiterhin ausnutzbar ist. Die Grundidee ist simpel: Manche Software vertraut dem **Local File Header (LFH)**, andere dem **Central Directory (CD)**, sodass ein Archiv verschiedenen Tools unterschiedliche Dateinamen, Pfade, Kommentare, Offsets oder Eintragsmengen präsentieren kann.

Praktische offensive Anwendungen:
- Lass einen Upload-Filter, AV-Pre-Scan oder Paket-Validator im CD eine harmlose Datei sehen, während der Extractor einen anderen Namen/Pfad aus dem LFH verwendet.
- Missbrauche doppelte Namen, Einträge, die nur in einer Struktur vorhanden sind, oder mehrdeutige Unicode-Pfad-Metadaten (z. B. Info-ZIP Unicode Path Extra Field `0x7075`), sodass verschiedene Parser unterschiedliche Verzeichnisbäume rekonstruieren.
- Kombiniere dies mit path traversal, um eine "harmlos" erscheinende Archivansicht während der Extraktion in ein Schreib-Primitive zu verwandeln. Für die Extraktionsseite siehe [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Bitte den Inhalt von src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md hier einfügen oder genau beschreiben, welche Ergänzungen du willst (z. B. Beispiele, Commands, Detection, Fixes, Hinweise zu Tools). Ich kann dann den relevanten englischen Text ins Deutsche übersetzen und die Markdown-/HTML-Syntax unverändert lassen.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiken:
- Archive ablehnen oder isolieren, die widersprüchliche LFH/CD-Namen, doppelte Dateinamen, mehrere EOCD-Einträge oder nachlaufende Bytes nach dem letzten EOCD enthalten.
- ZIPs, die ungewöhnliche Unicode-path extra fields oder inkonsistente Kommentare verwenden, als verdächtig einstufen, wenn verschiedene Tools beim extrahierten Verzeichnisbaum nicht übereinstimmen.
- Wenn die Analyse wichtiger ist als das Bewahren der Originalbytes, das Archiv nach der Extraktion in einer sandbox mit einem strikten Parser neu verpacken und die resultierende Dateiliste mit den Originalmetadaten vergleichen.

Das ist nicht nur für Paket-Ökosysteme relevant: dieselbe Klasse von Mehrdeutigkeiten kann payloads vor mail gateways, static scanners und benutzerdefinierten ingestion pipelines verbergen, die kurz in ZIP-Inhalte „hineinschauen“, bevor ein anderer extractor das Archiv verarbeitet.

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
