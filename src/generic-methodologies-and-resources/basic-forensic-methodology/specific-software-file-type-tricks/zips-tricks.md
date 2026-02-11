# ZIP-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Kommandozeilen-Tools** zum Verwalten von **zip files** sind unerlässlich, um zip-Dateien zu diagnostizieren, zu reparieren und zu knacken. Hier sind einige wichtige Utilities:

- **`unzip`**: Zeigt, warum eine zip-Datei nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der ZIP-Formatfelder.
- **`zipinfo`**: Listet den Inhalt einer zip-Datei ohne Extraktion auf.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte zip-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool für Brute-Force-Cracking von zip-Passwörtern, effektiv für Passwörter bis etwa 7 Zeichen.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) liefert umfassende Details zur Struktur und zu Standards von zip-Dateien.

Wichtig zu wissen: Passwortgeschützte zip-Dateien **verschlüsseln nicht Dateinamen oder Dateigrößen** darin — ein Sicherheitsmanko, das RAR oder 7z nicht teilen, da diese diese Informationen verschlüsseln können. Außerdem sind mit der älteren ZipCrypto-Methode verschlüsselte zip-Dateien anfällig für einen **known-plaintext attack**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt, um das Passwort der zip-Datei zu knacken — eine Verwundbarkeit, die in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beschrieben und in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) weiter erläutert wird. ZIPs, die mit **AES-256** gesichert sind, sind gegen diesen plaintext-Angriff immun, was die Bedeutung sicherer Verschlüsselungsmethoden für sensible Daten unterstreicht.

---

## Anti-Reversing-Tricks in APKs mit manipulierten ZIP-Headern

Moderne Android malware droppers nutzen fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu zerschlagen, während die APK auf dem Gerät weiterhin installierbar bleibt. Die gebräuchlichsten Tricks sind:

- Gefälschte Verschlüsselung durch Setzen des ZIP General Purpose Bit Flag (GPBF) Bit 0
- Missbrauch großer/benutzerdefinierter Extra-Felder, um Parser zu verwirren
- Dateiname-/Verzeichnis-Kollisionen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptome:
- `jadx-gui` scheitert mit Fehlern wie:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fordert für zentrale APK-Dateien ein Passwort, obwohl eine gültige APK keine verschlüsselten `classes*.dex`, `resources.arsc` oder `AndroidManifest.xml` haben kann:

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
Sieh dir das General Purpose Bit Flag für lokale und zentrale Header an. Ein verräterischer Wert ist Bit 0 gesetzt (Encryption), selbst bei Core-Einträgen:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn eine APK auf dem Gerät installiert ist und läuft, aber Kern-Einträge für Tools als "encrypted" erscheinen, wurde der GPBF manipuliert.

Behebung: GPBF-Bit 0 sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen löschen. Minimaler Byte-Patcher:

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
Du solltest jetzt `General Purpose Flag  0000` bei den Core-Einträgen sehen, und Tools werden die APK wieder parsen.

### 2) Große/benutzerdefinierte Extra-Felder, die Parser brechen

Angreifer stopfen übergroße Extra-Felder und ungewöhnliche IDs in Header, um decompilers auszutricksen. In freier Wildbahn sieht man dort möglicherweise benutzerdefinierte Marker (z. B. Zeichenketten wie `JADXBLOCK`) eingebettet.

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:") mit großen Payloads.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra-Felder bei Kerneinträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra-IDs in diesen Einträgen als verdächtig behandeln.

Praktische Gegenmaßnahme: Das Neuaufbauen des Archivs (z. B., erneutes Zippen der extrahierten Dateien) entfernt bösartige Extra-Felder. Falls Werkzeuge das Extrahieren wegen gefälschter Verschlüsselung verweigern, zuerst wie oben GPBF bit 0 zurücksetzen und dann neu verpacken:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Datei-/Verzeichnisnamenskollisionen (echte Artefakte verbergen)

Ein ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Manche extractors und decompilers werden verwirrt und können die echte Datei durch einen Verzeichniseintrag überdecken oder verbergen. Dies wurde bei Einträgen beobachtet, die mit Kern-APK-Namen wie `classes.dex` kollidieren.

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
Programmatische Erkennung Nachfix:
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
- Markiere APKs, deren lokale Header Verschlüsselung markieren (GPBF bit 0 = 1), die dennoch installiert/ausgeführt werden.
- Markiere große/unklare Extra-Felder bei Core-Einträgen (achte auf Marker wie `JADXBLOCK`).
- Markiere Pfadkollisionen (`X` und `X/`) speziell für `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Weitere bösartige ZIP-Tricks (2024–2025)

### Konkatenierte central directories (multi-EOCD-Umgehung)

Kürzliche Phishing-Kampagnen liefern ein einzelnes Blob, das tatsächlich aus **zwei aneinandergereihten ZIP-Dateien** besteht. Jede hat ihr eigenes End of Central Directory (EOCD) + central directory. Verschiedene Extractor parsen unterschiedliche Verzeichnisse (7zip liest das erste, WinRAR das letzte), sodass Angreifer Payloads verbergen können, die nur einige Tools anzeigen. Das umgeht auch einfache Mail-Gateway-AV, die nur das erste Verzeichnis untersucht.

**Triage-Befehle**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Wenn mehr als ein EOCD erscheint oder es "data after payload" warnings gibt, teile den blob und untersuche jeden Teil:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb" baut einen winzigen **kernel** (stark komprimierter DEFLATE-Block) und nutzt ihn mehrfach durch überlappende local headers. Jeder Eintrag im central directory zeigt auf dieselben komprimierten Daten und erzielt Kompressionsverhältnisse von >28M:1, ohne Archive zu verschachteln. Bibliotheken, die den Größenangaben im central directory vertrauen (Python `zipfile`, Java `java.util.zip`, Info-ZIP vor gehärteten Builds) können dazu gezwungen werden, Petabytes zu reservieren.

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
- Führe einen Trockenlauf durch: `zipdetails -v file.zip | grep -n "Rel Off"` und stelle sicher, dass die Offsets strikt ansteigend und eindeutig sind.
- Begrenze die akzeptierte gesamte unkomprimierte Größe und die Anzahl der Einträge vor der Extraktion (`zipdetails -t` oder ein benutzerdefinierter Parser).
- Wenn du extrahieren musst, führe dies innerhalb einer cgroup/VM mit CPU- und Festplattenlimits aus (vermeide unkontrollierte Aufblähungen, die zu Abstürzen führen).

---

## Referenzen

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
