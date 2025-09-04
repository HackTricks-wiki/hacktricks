# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** zur Verwaltung von **zip files** sind unerlässlich, um Zip-Dateien zu diagnostizieren, zu reparieren und zu knacken. Hier sind einige wichtige Werkzeuge:

- **`unzip`**: Zeigt, warum sich eine Zip-Datei möglicherweise nicht entpacken lässt.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder im Zip-Dateiformat.
- **`zipinfo`**: Listet den Inhalt einer Zip-Datei auf, ohne diese zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte Zip-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von Zip-Passwörtern, effektiv für Passwörter bis etwa 7 Zeichen.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) liefert umfassende Details zur Struktur und den Standards von Zip-Dateien.

Wichtig ist, dass passwortgeschützte Zip-Dateien **keine Dateinamen oder Dateigrößen** innerhalb der Datei verschlüsseln — ein Sicherheitsmangel, der bei RAR- oder 7z-Dateien, die diese Informationen verschlüsseln, nicht vorhanden ist. Darüber hinaus sind Zip-Dateien, die mit der älteren ZipCrypto-Methode verschlüsselt sind, anfällig für einen **plaintext attack**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt, um das Zip-Passwort zu knacken — eine Verwundbarkeit, die im [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beschrieben und in [diesem akademischen Paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) weiter erläutert wird. Zip-Dateien, die hingegen mit **AES-256** verschlüsselt sind, sind gegen diesen plaintext attack immun, was die Bedeutung sicherer Verschlüsselungsmethoden für sensible Daten unterstreicht.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Moderne Android-Malware-Dropper verwenden fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu zerstören und gleichzeitig die APK auf dem Gerät installierbar zu halten. Die gebräuchlichsten Tricks sind:

- Fake-Verschlüsselung durch Setzen des ZIP General Purpose Bit Flag (GPBF) Bit 0
- Ausnutzen großer/benutzerdefinierter Extra-Felder, um Parser zu verwirren
- Dateiname-/Verzeichnis-Kollisionen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

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
Sieh dir das General Purpose Bit Flag für lokale und zentrale Header an. Ein verräterischer Wert ist Bit 0 gesetzt (Encryption) sogar bei Core-Einträgen:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristik: Wenn eine APK auf dem Gerät installiert und ausgeführt wird, aber Kern‑Einträge für Tools als "verschlüsselt" erscheinen, wurde das GPBF manipuliert.

Beheben: Setze Bit 0 des GPBF sowohl in Local File Headers (LFH) als auch in Central Directory (CD)-Einträgen zurück. Minimaler Byte-Patcher:
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
Sie sollten nun `General Purpose Flag  0000` bei den Kerneinträgen sehen und Tools werden die APK wieder parsen.

### 2) Große/benutzerdefinierte Extra-Felder, um Parser zu brechen

Angreifer packen übergroße Extra-Felder und ungewöhnliche IDs in Header, um Decompiler auszulösen. In freier Wildbahn kann man dort benutzerdefinierte Marker sehen (z. B. strings wie `JADXBLOCK`) eingebettet.

Inspektion:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Beobachtete Beispiele: unbekannte IDs wie `0xCAFE` ("Java Executable") oder `0x414A` ("JA:") mit großen payloads.

DFIR-Heuristiken:
- Alarm auslösen, wenn Extra-Felder bei Kern-Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra-IDs in diesen Einträgen als verdächtig behandeln.

Praktische Gegenmaßnahme: Das Neuaufbauen des Archivs (z. B. erneutes Zippen der extrahierten Dateien) entfernt bösartige Extra-Felder. Wenn Tools die Extraktion aufgrund gefälschter Verschlüsselung verweigern, setzen Sie zuerst GPBF bit 0 wie oben beschrieben zurück und verpacken dann neu:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Datei-/Verzeichnisnamen-Kollisionen (Verbergen echter Artefakte)

Eine ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Manche Extractoren und Decompiler werden dadurch verwirrt und können die eigentliche Datei durch einen Verzeichniseintrag überlagern oder verbergen. Das wurde bei Einträgen beobachtet, die mit zentralen APK-Namen wie `classes.dex` kollidierten.

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
Programmatische Erkennung (Suffix):
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
Ideen zur Blue-Team-Erkennung:
- Markiere APKs, deren lokale Header Verschlüsselung kennzeichnen (GPBF bit 0 = 1), die sich dennoch installieren/ausführen.
- Markiere große/unklare Extra-Felder bei Kern-Einträgen (achte auf Marker wie `JADXBLOCK`).
- Markiere Pfad-Kollisionen (`X` und `X/`) speziell für `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Referenzen

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
