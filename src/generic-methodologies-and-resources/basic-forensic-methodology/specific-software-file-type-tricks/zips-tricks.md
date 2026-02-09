# ZIPs-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Kommandozeilen-Tools** zur Verwaltung von **ZIP-Dateien** sind unerlässlich, um ZIP-Dateien zu diagnostizieren, zu reparieren und zu knacken. Hier einige wichtige Werkzeuge:

- **`unzip`**: Zeigt, warum eine ZIP-Datei möglicherweise nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Feldstrukturen des ZIP-Dateiformats.
- **`zipinfo`**: Listet den Inhalt einer ZIP-Datei auf, ohne ihn zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte ZIP-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von ZIP-Passwörtern, effektiv bei Passwörtern bis etwa 7 Zeichen.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) liefert umfassende Details zur Struktur und den Standards von ZIP-Dateien.

Wichtig ist, dass passwortgeschützte ZIP-Dateien intern **keine Dateinamen oder Dateigrößen verschlüsseln**, ein Sicherheitsmangel, den RAR- oder 7z-Dateien, die diese Informationen verschlüsseln, nicht teilen. Darüber hinaus sind ZIP-Dateien, die mit der älteren ZipCrypto-Methode verschlüsselt sind, anfällig für einen **plaintext attack**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt, um das ZIP-Passwort zu knacken — eine Schwachstelle, die in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beschrieben und in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) näher erläutert wird. ZIP-Dateien, die mit **AES-256** verschlüsselt sind, sind hingegen gegen diesen plaintext attack immun, was die Bedeutung sicherer Verschlüsselungsmethoden für sensible Daten unterstreicht.

---

## Anti-reversing Tricks in APKs using manipulated ZIP headers

Moderne Android-Malware-Dropper verwenden fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu stören, während das APK auf dem Gerät installierbar bleibt. Die gängigsten Tricks sind:

- Vortäuschen von Verschlüsselung durch Setzen des ZIP General Purpose Bit Flag (GPBF) Bit 0
- Ausnutzen großer/benutzerdefinierter Extra-Felder, um Parser zu verwirren
- Kollisionen von Datei-/Verzeichnisnamen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptome:
- `jadx-gui` schlägt fehl mit Fehlern wie:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fordert ein Passwort für zentrale APK-Dateien an, obwohl ein gültiges APK keine verschlüsselten `classes*.dex`, `resources.arsc` oder `AndroidManifest.xml` enthalten kann:

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
Schau dir das General Purpose Bit Flag für lokale und zentrale Header an. Ein verräterischer Wert ist, dass Bit 0 gesetzt ist (Encryption) sogar für Core-Einträge:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn eine APK auf dem Gerät installiert und ausgeführt wird, aber Kern-Einträge für Tools als "verschlüsselt" erscheinen, wurde das GPBF manipuliert.

Abhilfe: GPBF bit 0 sowohl in Local File Headers (LFH) als auch in Central Directory (CD) Einträgen löschen. Minimaler Byte-Patcher:

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
Sie sollten jetzt `General Purpose Flag  0000` bei den Core-Einträgen sehen, und Tools werden das APK wieder parsen.

### 2) Große/benutzerdefinierte Extra-Felder, um Parser zum Absturz zu bringen

Angreifer stopfen übergroße Extra-Felder und ungewöhnliche IDs in die Header, um Decompiler zu verwirren. In freier Wildbahn sieht man dort möglicherweise benutzerdefinierte Marker (z. B. Strings wie `JADXBLOCK`) eingebettet.

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:") mit großen Payloads.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra-Felder auf Kern-Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Behandle unbekannte Extra-IDs in diesen Einträgen als verdächtig.

Praktische Gegenmaßnahme: Das Neuaufbauen des Archivs (z. B. erneutes Zippen der extrahierten Dateien) entfernt bösartige Extra-Felder. Wenn Tools aufgrund falscher Verschlüsselung das Extrahieren verweigern, zuerst GPBF bit 0 wie oben zurücksetzen, dann neu packen:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Datei-/Verzeichnis-Namenskollisionen (Verbergen echter Artefakte)

Eine ZIP-Datei kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Einige extractors und decompilers werden dadurch verwirrt und können die echte Datei durch einen Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit Kern-APK-Namen wie `classes.dex` kollidieren.

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
Programmgesteuerte Erkennungs-Postfix:
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
- Markiere APKs, deren lokale Header Verschlüsselung kennzeichnen (GPBF bit 0 = 1), die sich aber trotzdem installieren/ausführen lassen.
- Markiere große/unklare Extra fields in Core-Einträgen (achte auf Marker wie `JADXBLOCK`).
- Markiere Pfad-Kollisionen (`X` und `X/`) speziell für `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Andere bösartige ZIP-Tricks (2024–2025)

### Konkatenierte central directories (Multi-EOCD-Umgehung)

Jüngste Phishing-Kampagnen liefern ein einzelnes blob, das tatsächlich aus **zwei aneinandergereihten ZIP-Dateien** besteht. Jede hat ihr eigenes End of Central Directory (EOCD) + central directory. Verschiedene extractors parsen unterschiedliche Verzeichnisse (7zip liest das erste, WinRAR das letzte), wodurch Angreifer payloads verbergen können, die nur von einigen Tools angezeigt werden. Das umgeht außerdem einfache Mail-Gateway-AVs, die nur das erste Verzeichnis untersuchen.

**Triage-Befehle**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Wenn mehr als ein EOCD erscheint oder es "data after payload"-Warnungen gibt, teile den blob auf und untersuche jeden Teil:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb" baut einen winzigen **kernel** (highly compressed DEFLATE block) und nutzt ihn mehrfach über overlapping local headers. Jeder central directory entry zeigt auf dieselben komprimierten Daten und erreicht Verhältnisse von >28M:1 ohne verschachtelte Archive. Bibliotheken, die den central directory sizes vertrauen (Python `zipfile`, Java `java.util.zip`, Info-ZIP vor gehärteten Builds), können dazu gezwungen werden, Petabytes zu reservieren.

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
- Führe einen Dry-Run durch: `zipdetails -v file.zip | grep -n "Rel Off"` und stelle sicher, dass die Offsets strikt aufsteigend und eindeutig sind.
- Begrenze die akzeptierte gesamte unkomprimierte Größe und die Anzahl der Einträge vor der Extraktion (`zipdetails -t` oder eigener Parser).
- Wenn du extrahieren musst, mache das innerhalb einer cgroup/VM mit CPU- und Festplattenlimits (vermeide unkontrollierte Aufblähungen/Abstürze).

---

## Referenzen

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
