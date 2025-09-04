# Astuces ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et craquer des zip. Voici quelques utilitaires clés :

- **`unzip`**: Révèle pourquoi un fichier zip peut ne pas se décompresser.
- **`zipdetails -v`**: Offre une analyse détaillée des champs du format zip.
- **`zipinfo`**: Liste le contenu d'un zip sans l'extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`**: Tente de réparer des fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Un outil de force brute pour les mots de passe zip, efficace pour des mots de passe d'environ 7 caractères ou moins.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des détails complets sur la structure et les standards des fichiers zip.

Il est crucial de noter que les fichiers zip protégés par mot de passe **n'encryptent pas les noms de fichiers ni les tailles de fichiers** à l'intérieur, une faiblesse de sécurité que RAR ou 7z n'ont pas car ils chiffrent ces informations. De plus, les fichiers zip chiffrés avec l'ancienne méthode ZipCrypto sont vulnérables à une plaintext attack si une copie non chiffrée d'un fichier compressé est disponible. Cette attaque utilise le contenu connu pour craquer le mot de passe du zip, une vulnérabilité détaillée dans [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus en détail dans [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Cependant, les fichiers zip sécurisés avec **AES-256** sont immunisés contre cette plaintext attack, ce qui montre l'importance de choisir des méthodes de chiffrement robustes pour des données sensibles.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Les malware droppers Android modernes utilisent des métadonnées ZIP malformées pour casser les outils statiques (jadx/apktool/unzip) tout en gardant l'APK installable sur l'appareil. Les astuces les plus courantes sont :

- Faux chiffrement en définissant le ZIP General Purpose Bit Flag (GPBF) bit 0
- Abus de grandes/custom Extra fields pour perturber les parseurs
- Collisions de noms de fichiers/répertoires pour cacher de vrais artefacts (par ex., un répertoire nommé `classes.dex/` à côté du vrai `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptômes:
- `jadx-gui` échoue avec des erreurs comme :

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour des fichiers APK centraux bien qu'un APK valide ne puisse pas avoir `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` chiffrés :

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
Consultez le General Purpose Bit Flag des en-têtes locaux et centraux. Une valeur révélatrice est le bit 0 défini (Encryption) même pour les core entries :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : si un APK s'installe et s'exécute sur l'appareil mais que les core entries apparaissent « chiffrées » pour les outils, le GPBF a été modifié.

Corriger en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Patcheur d'octets minimal :
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
Vous devriez maintenant voir `General Purpose Flag  0000` sur les entrées principales et les outils analyseront à nouveau l'APK.

### 2) Champs Extra volumineux/personnalisés pour casser les analyseurs

Les attaquants insèrent des Extra fields surdimensionnés et des IDs étranges dans les en-têtes pour piéger les décompilateurs. Dans la pratique, vous pouvez voir des marqueurs personnalisés (par ex., des chaînes comme `JADXBLOCK`) intégrés là.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : des IDs inconnus comme `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") transportant de gros payloads.

DFIR heuristics:
- Alerter lorsque les Extra fields sont inhabituellement volumineux sur les entrées core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer les Extra IDs inconnus sur ces entrées comme suspects.

Practical mitigation: la reconstruction de l'archive (par ex., re-zipping des fichiers extraits) supprime les Extra fields malveillants. Si les outils refusent d'extraire à cause d'une fake encryption, d'abord effacer GPBF bit 0 comme indiqué ci-dessus, puis reconditionner :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Conflits de noms fichier/répertoire (masquer les artefacts réels)

Une archive ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs se trompent et peuvent superposer ou masquer le fichier réel au profit d'une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms d'APK principaux comme `classes.dex`.

Triage et extraction sécurisée:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Suffixe pour la détection programmatique:
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
Idées de détection pour Blue-team :
- Signaler les APKs dont les en-têtes locaux indiquent un chiffrement (GPBF bit 0 = 1) mais qui s'installent/s'exécutent.
- Signaler les champs Extra volumineux/inconnus sur les entrées core (rechercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Références

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
