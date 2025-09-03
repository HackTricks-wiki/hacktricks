# ZIP-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Kommandozeilen-Tools** zur Verwaltung von **zip files** sind unverzichtbar, um zip files zu diagnostizieren, zu reparieren und zu knacken. Hier einige wichtige Utilities:

- **`unzip`**: Zeigt, warum eine zip file möglicherweise nicht entpackt werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des zip file-Formats.
- **`zipinfo`**: Listet den Inhalt einer zip file auf, ohne sie zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte zip files zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von zip-Passwörtern, effektiv für Passwörter bis etwa 7 Zeichen.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) liefert umfassende Details zur Struktur und zu den Standards von zip files.

Wichtig ist, dass passwortgeschützte zip files **nicht die Dateinamen oder Dateigrößen verschlüsseln**, ein Sicherheitsmangel, der bei RAR- oder 7z-Dateien nicht vorhanden ist, da diese diese Informationen verschlüsseln können. Außerdem sind zip files, die mit der älteren ZipCrypto-Methode verschlüsselt wurden, anfällig für einen **plaintext attack**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt aus, um das Zip-Passwort zu knacken — eine Schwachstelle, die in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beschrieben und in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) weiter erläutert wird. Zip files, die mit **AES-256** gesichert sind, sind gegen diesen plaintext attack immun, was die Bedeutung sicherer Verschlüsselungsmethoden für sensible Daten unterstreicht.

---

## Anti-Reversing-Tricks in APKs durch manipulierte ZIP-Header

Moderne Android-Malware-Dropper nutzen fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu zerstören, während die APK auf dem Gerät weiterhin installierbar bleibt. Die häufigsten Tricks sind:

- Gefälschte Verschlüsselung durch Setzen des ZIP General Purpose Bit Flag (GPBF) Bit 0
- Ausnutzung großer/benutzerdefinierter Extra fields, um Parser zu verwirren
- Datei-/Verzeichnisnamen-Kollisionen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptome:
- `jadx-gui` schlägt fehl mit Fehlern wie:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` fragt nach einem Passwort für zentrale APK-Dateien, obwohl eine gültige APK keine verschlüsselten `classes*.dex`, `resources.arsc` oder `AndroidManifest.xml` haben kann:

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
Sieh dir das General Purpose Bit Flag für lokale und zentrale Header an. Ein verräterischer Wert ist, dass Bit 0 gesetzt ist (Encryption), selbst für Core-Einträge:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn eine APK auf dem Gerät installiert und ausgeführt wird, aber Kern‑Einträge für Tools als "encrypted" erscheinen, wurde das GPBF manipuliert.

Behebung: GPBF-Bit 0 sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen auf 0 zurücksetzen. Minimaler Byte-Patcher:
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
Verwendung:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sie sollten nun `General Purpose Flag  0000` bei den Core-Einträgen sehen und Tools werden die APK erneut parsen.

### 2) Große/benutzerdefinierte Extra fields, um parsers zu brechen

Angreifer stopfen übergroße Extra fields und ungewöhnliche IDs in headers, um decompilers auszutricksen. In der Praxis sieht man dort möglicherweise eigene Marker (z. B. Strings wie `JADXBLOCK`) eingebettet.
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:") mit großen Payloads.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra fields bei Kern-Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra IDs in diesen Einträgen als verdächtig einstufen.

Praktische Gegenmaßnahme: Neuaufbau des Archives (z. B. erneutes Zippen der extrahierten Dateien) entfernt bösartige Extra fields. Wenn Tools das Extrahieren wegen gefälschter Verschlüsselung verweigern, zuerst GPBF bit 0 wie oben löschen, dann neu verpacken:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (hiding real artifacts)

Ein ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Manche extractors und decompilers werden verwirrt und können die echte Datei durch einen Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit Kern-APK-Namen wie `classes.dex` kollidieren.

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
Erkennungsansätze für das Blue Team:
- Markiere APKs, deren lokale Header Verschlüsselung kennzeichnen (GPBF bit 0 = 1), die sich dennoch installieren/ausführen.
- Markiere große/unklare Extra-Felder in Core-Einträgen (nach Markern wie `JADXBLOCK` suchen).
- Markiere Pfad-Kollisionen (`X` und `X/`) insbesondere für `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
