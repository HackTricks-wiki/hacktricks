# Astuces ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et craquer des zip. Voici quelques utilitaires clés :

- **`unzip`** : Révèle pourquoi un zip peut ne pas se décompresser.
- **`zipdetails -v`** : Offre une analyse détaillée des champs du format zip.
- **`zipinfo`** : Liste le contenu d’un zip sans l’extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : Tentent de réparer des zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : Un outil de brute-force pour craquer des mots de passe zip, efficace pour des mots de passe jusqu’à environ 7 caractères.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des détails complets sur la structure et les standards des zip.

Il est crucial de noter que les zip protégés par mot de passe **n’encryptent pas les noms de fichiers ni les tailles de fichiers** à l’intérieur, une faille de sécurité que ne partagent pas RAR ou 7z qui chiffrent ces informations. De plus, les zip chiffrés avec la méthode plus ancienne ZipCrypto sont vulnérables à une **plaintext attack** si une copie non chiffrée d’un fichier compressé est disponible. Cette attaque exploite le contenu connu pour craquer le mot de passe du zip, une vulnérabilité détaillée dans l’article de [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus avant dans [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Cependant, les zip protégés avec **AES-256** sont immunisés contre cette plaintext attack, ce qui montre l’importance de choisir des méthodes de chiffrement sécurisées pour les données sensibles.

---

## Astuces anti-reverse dans les APKs utilisant des en-têtes ZIP manipulés

Les Android malware droppers modernes utilisent des métadonnées ZIP malformées pour casser les outils statiques (jadx/apktool/unzip) tout en gardant l’APK installable sur l’appareil. Les trucs les plus courants sont :

- Fake encryption en réglant le ZIP General Purpose Bit Flag (GPBF) bit 0
- Abuser de Extra fields larges/personnalisés pour confondre les parsers
- Collisions de noms de fichiers/répertoires pour cacher les artefacts réels (par ex., un répertoire nommé `classes.dex/` à côté du vrai `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptômes :
- `jadx-gui` échoue avec des erreurs comme :

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour des fichiers APK centraux alors qu’un APK valide ne peut pas avoir `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` chiffrés :

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
Vérifiez le General Purpose Bit Flag pour les en-têtes locaux et centraux. Une valeur révélatrice est le bit 0 activé (Encryption) même pour les core entries :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : si une APK s'installe et s'exécute sur l'appareil mais que les entrées core apparaissent "chiffrées" pour les outils, le GPBF a été altéré.

Corriger en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et dans les entrées du Central Directory (CD). Patcher binaire minimal :

<details>
<summary>Patcher minimal pour effacer le bit 0 du GPBF</summary>
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

Utilisation:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Vous devriez maintenant voir `General Purpose Flag  0000` sur les entrées principales et les outils analyseront l'APK à nouveau.

### 2) Champs Extra volumineux/personnalisés pour casser les parseurs

Les attaquants insèrent des champs Extra surdimensionnés et des IDs étranges dans les en-têtes pour faire trébucher les décompilateurs. En conditions réelles, vous pouvez voir des marqueurs personnalisés (p.ex., des chaînes comme `JADXBLOCK`) intégrés là.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : des IDs inconnus comme `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") contenant de gros payloads.

Heuristiques DFIR :
- Alerter lorsque les Extra fields sont anormalement volumineux sur les entrées core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer comme suspect tout Extra ID inconnu sur ces entrées.

Atténuation pratique : la reconstruction de l'archive (p. ex., zipper à nouveau les fichiers extraits) supprime les Extra fields malveillants. Si les outils refusent d'extraire en raison d'un chiffrement factice, effacez d'abord GPBF bit 0 comme indiqué ci-dessus, puis recréez l'archive :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisions de noms de fichier/répertoire (cacher les vrais artefacts)

Un ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extractors et decompilers se confondent et peuvent recouvrir ou masquer le vrai fichier par une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms de base d'APK comme `classes.dex`.

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
Détection programmatique post-fix:
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
- Signaler les APK dont les en-têtes locaux marquent un chiffrement (GPBF bit 0 = 1) mais qui s'installent/s'exécutent.
- Signaler les champs Extra volumineux/inconnus sur les entrées core (chercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Autres astuces ZIP malveillantes (2024–2025)

### Répertoires centraux concaténés (contournement multi-EOCD)

Des campagnes de phishing récentes livrent un seul blob qui est en réalité **deux fichiers ZIP concaténés**. Chacun a son propre End of Central Directory (EOCD) + central directory. Différents extracteurs parsent différents répertoires (7zip lit le premier, WinRAR le dernier), ce qui permet aux attaquants de cacher des payloads que seuls certains outils montrent. Cela contourne aussi les AV de passerelle mail basiques qui n'inspectent que le premier répertoire.

**Commandes de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
S'il apparaît plus d'un EOCD ou s'il y a des avertissements "data after payload", divisez le blob et inspectez chaque partie :
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

La 'better zip bomb' moderne construit un petit **kernel** (bloc DEFLATE fortement compressé) et le réutilise via des local headers qui se chevauchent. Chaque entrée du central directory pointe vers les mêmes données compressées, atteignant des ratios >28M:1 sans imbriquer d'archives. Les bibliothèques qui font confiance aux tailles du central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP avant les versions durcies) peuvent être forcées d'allouer des pétaoctets.

**Détection rapide (offsets LFH dupliqués)**
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
**Gestion**
- Effectuer un dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` et s'assurer que les offsets sont strictement croissants et uniques.
- Limiter la taille totale décompressée acceptée et le nombre d'entrées avant extraction (`zipdetails -t` ou parseur personnalisé).
- Lorsqu'il faut extraire, le faire dans un cgroup/VM avec des limites CPU+disk (éviter les plantages dus à une expansion non bornée).

---

## Références

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
