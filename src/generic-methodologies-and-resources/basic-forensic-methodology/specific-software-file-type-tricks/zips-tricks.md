# Astuces pour les ZIPs

{{#include ../../../banners/hacktricks-training.md}}

Les outils en ligne de commande pour gérer les fichiers zip sont essentiels pour diagnostiquer, réparer et cracker des zip. Voici quelques utilitaires clés :

- **`unzip`** : révèle pourquoi un zip peut ne pas se décompresser.
- **`zipdetails -v`** : offre une analyse détaillée des champs du format zip.
- **`zipinfo`** : liste le contenu d'un zip sans l'extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : tentent de réparer des zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : outil de brute-force pour cracker les mots de passe zip, efficace pour des mots de passe jusqu'à environ 7 caractères.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des détails complets sur la structure et les standards des zip.

Il est crucial de noter que les fichiers zip protégés par mot de passe **n'encryptent pas les noms de fichiers ni les tailles de fichiers** à l'intérieur, une faille de sécurité qui n'existe pas pour les fichiers RAR ou 7z qui encryptent cette information. De plus, les zip chiffrés avec l'ancienne méthode ZipCrypto sont vulnérables à une **plaintext attack** si une copie non chiffrée d'un fichier compressé est disponible. Cette attaque exploite le contenu connu pour cracker le mot de passe du zip, vulnérabilité détaillée dans l'article de [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus en détail dans [cet article académique](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Cependant, les zip protégés avec **AES-256** sont immunisés contre cette plaintext attack, ce qui illustre l'importance de choisir des méthodes de chiffrement sûres pour des données sensibles.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Les droppers Android modernes utilisent des metadata ZIP malformés pour casser les outils statiques (jadx/apktool/unzip) tout en gardant l'APK installable sur l'appareil. Les astuces les plus courantes sont :

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptômes :
- `jadx-gui` échoue avec des erreurs comme :

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour des fichiers core de l'APK alors qu'un APK valide ne peut pas avoir `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` chiffrés :

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Détection avec zipdetails:
```bash
zipdetails -v sample.apk | less
```
Regardez le General Purpose Bit Flag pour les en-têtes locaux et centraux. Une valeur révélatrice est le bit 0 activé (Encryption) même pour les entrées core :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : Si une APK s'installe et s'exécute sur l'appareil mais que des entrées principales apparaissent « chiffrées » pour les outils, le GPBF a été altéré.

Corriger en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Byte-patcher minimal :
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
Utilisation :
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Vous devriez maintenant voir `General Purpose Flag  0000` sur les entrées core et les outils analyseront à nouveau l'APK.

### 2) Extra fields volumineux/personnalisés pour casser les parseurs

Les attaquants insèrent dans les headers des Extra fields surdimensionnés et des IDs étranges pour piéger les décompilateurs. En conditions réelles, vous pouvez voir des marqueurs personnalisés (par ex., des chaînes comme `JADXBLOCK`) insérés là.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : des IDs inconnus comme `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") transportant de gros payloads.

DFIR heuristics :
- Alerter lorsque les Extra fields sont anormalement volumineux sur les entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer les Extra IDs inconnus sur ces entrées comme suspects.

Practical mitigation : reconstruire l'archive (e.g., re-zipping extracted files) supprime les Extra fields malveillants. Si les outils refusent d'extraire en raison d'une fake encryption, effacer d'abord GPBF bit 0 comme ci-dessus, puis reconditionner :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisions de noms fichier/répertoire (masquer les vrais artefacts)

Une archive ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs se trompent et peuvent superposer ou masquer le vrai fichier par une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms d'APK critiques comme `classes.dex`.

Triage et extraction sûre:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Postfixe de détection programmatique :
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
Blue-team — idées de détection :
- Signaler les APK dont les en-têtes locaux indiquent le chiffrement (GPBF bit 0 = 1) mais qui s'installent/s'exécutent.
- Signaler les champs Extra volumineux/inconnus sur les entrées principales (chercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Références

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
