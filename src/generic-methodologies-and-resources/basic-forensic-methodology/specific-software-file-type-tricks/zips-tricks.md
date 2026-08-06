# Astuces ZIP

{{#include ../../../banners/hacktricks-training.md}}

Les **outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et cracker les fichiers zip. Voici quelques utilitaires clés :<sup>[[1]](#references)</sup>

- **`unzip`** : révèle pourquoi un fichier zip peut ne pas être décompressé.
- **`zipdetails -v`** : fournit une analyse détaillée des champs du format de fichier zip.
- **`zipinfo`** : liste le contenu d’un fichier zip sans l’extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : tentent de réparer les fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : outil de brute-force des mots de passe zip, efficace pour les mots de passe allant jusqu’à environ 7 caractères.

La [spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des informations détaillées sur la structure et les normes des fichiers zip.<sup>[[4]](#references)</sup>

Il est essentiel de noter que les fichiers zip protégés par mot de passe **ne chiffrent pas les noms de fichiers ni les tailles des fichiers** qu’ils contiennent, une faille de sécurité qui n’affecte pas les fichiers RAR ou 7z, lesquels chiffrent ces informations. De plus, les fichiers zip chiffrés avec l’ancienne méthode ZipCrypto sont vulnérables à une **plaintext attack** si une copie non chiffrée d’un fichier compressé est disponible.<sup>[[1]](#references)</sup> Cette attaque exploite le contenu connu pour cracker le mot de passe du zip, une vulnérabilité décrite dans [l’article de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus en détail dans [cet article académique](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Cependant, les fichiers zip protégés par un chiffrement **AES-256** sont immunisés contre cette plaintext attack, ce qui démontre l’importance de choisir des méthodes de chiffrement sécurisées pour les données sensibles.<sup>[[1]](#references)</sup>

---

## Techniques anti-reversing dans les APK utilisant des en-têtes ZIP manipulés

Les droppers de malware Android modernes utilisent des métadonnées ZIP malformées pour perturber les outils d’analyse statique (jadx/apktool/unzip) tout en conservant la possibilité d’installer l’APK sur l’appareil. Les techniques les plus courantes sont les suivantes :<sup>[[2]](#references)</sup>

- Fausse encryption en définissant le bit 0 du ZIP General Purpose Bit Flag (GPBF)
- Abus de champs Extra volumineux ou personnalisés pour perturber les parsers
- Collisions entre noms de fichiers et de répertoires pour masquer les artefacts réels (par exemple, un répertoire nommé `classes.dex/` à côté du véritable `classes.dex`)

### 1) Fausse encryption (bit 0 du GPBF défini) sans véritable crypto

Symptômes :
- `jadx-gui` échoue avec des erreurs telles que :

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour les fichiers APK principaux, même si un APK valide ne peut pas contenir de `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` chiffré :

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Détection avec zipdetails :
```bash
zipdetails -v sample.apk | less
```
Examinez le General Purpose Bit Flag pour les en-têtes local et central. Une valeur révélatrice est le bit 0 activé (Encryption), même pour les entrées principales :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : si un APK s’installe et s’exécute sur l’appareil, mais que les entrées principales apparaissent comme « encrypted » pour les tools, le GPBF a été altéré.

Corrigez cela en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Byte-patcher minimal :

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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

Utilisation :
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Vous devriez maintenant voir `General Purpose Flag  0000` sur les entrées principales, et les outils pourront à nouveau analyser l’APK.

### 2) Champs Extra volumineux/personnalisés pour casser les parseurs

Les attaquants insèrent des champs Extra surdimensionnés et des identifiants inhabituels dans les en-têtes afin de perturber les décompilateurs. Dans la nature, vous pouvez voir des marqueurs personnalisés (par exemple, des chaînes comme `JADXBLOCK`) qui y sont intégrés.

Inspection :
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : identifiants inconnus comme `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") transportant de gros payloads.

Heuristiques DFIR :
- Déclencher une alerte lorsque les Extra fields sont inhabituellement volumineux dans les entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer comme suspects les Extra IDs inconnus présents dans ces entrées.

Mitigation pratique : reconstruire l’archive (par exemple, re-zipper les fichiers extraits) supprime les Extra fields malveillants. Si les outils refusent l’extraction en raison d’un faux chiffrement, effacer d’abord le bit 0 du GPBF comme indiqué ci-dessus, puis reconditionner :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisions entre noms de fichiers/répertoires (dissimulation d’artefacts réels)

Un ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs peuvent être désorientés et superposer ou masquer le fichier réel avec une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms APK essentiels comme `classes.dex`.

Triage et extraction sûre :
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Détection programmatique post-correction :
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
Idées de détection côté blue-team :
- Signaler les APK dont les en-têtes locaux indiquent un chiffrement (GPBF bit 0 = 1) alors qu’ils s’installent/s’exécutent.
- Signaler les champs Extra volumineux/inconnus dans les entrées principales (rechercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc` et `classes*.dex`.

---

## Autres techniques malveillantes liées aux ZIP (2024–2026)

### Répertoires centraux concaténés (évasion multi-EOCD)

Des campagnes de phishing récentes distribuent un blob unique qui est en réalité **deux fichiers ZIP concaténés**. Chacun possède son propre End of Central Directory (EOCD) et son propre répertoire central. Les extracteurs ne parsant pas tous le même répertoire (7zip lit le premier, WinRAR le dernier), les attaquants peuvent dissimuler des payloads que seuls certains outils affichent. Cela permet également de contourner les solutions antivirus basiques des mail gateways qui n’inspectent que le premier répertoire.<sup>[[5]](#references)[[6]](#references)</sup>

**Commandes de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Si plusieurs EOCD apparaissent ou si des avertissements « data after payload » sont affichés, scindez le blob et inspectez chaque partie :
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Les **better zip bomb** modernes construisent un petit **kernel** (bloc DEFLATE hautement compressé) et le réutilisent via des en-têtes locaux qui se chevauchent. Chaque entrée du répertoire central pointe vers les mêmes données compressées, atteignant des ratios supérieurs à 28M:1 sans imbriquer d'archives. Les bibliothèques qui font confiance aux tailles du répertoire central (`zipfile` de Python, `java.util.zip` de Java, Info-ZIP avant les builds renforcés) peuvent être forcées à allouer des pétaoctets.<sup>[[7]](#references)[[8]](#references)</sup>

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
- Effectuez une analyse à blanc : `zipdetails -v file.zip | grep -n "Rel Off"` et vérifiez que les offsets sont strictement croissants et uniques.
- Limitez la taille totale décompressée et le nombre d’entrées acceptés avant l’extraction (`zipdetails -t` ou un parser personnalisé).
- Lorsque vous devez extraire, faites-le dans un cgroup/VM avec des limites CPU et disque (évitez les crashes liés à une inflation sans limite).

---

### Confusion entre le parser du local header et celui du central directory

Des recherches récentes sur les differential-parsers ont montré que l’ambiguïté des ZIP reste exploitable dans les toolchains modernes. L’idée principale est simple : certains logiciels font confiance au **Local File Header (LFH)**, tandis que d’autres font confiance au **Central Directory (CD)**. Ainsi, une même archive peut présenter différents noms de fichiers, chemins, commentaires, offsets ou ensembles d’entrées selon les outils.<sup>[[9]](#references)</sup>

Utilisations offensives pratiques :
- Faire en sorte qu’un upload filter, qu’un pré-scan AV ou qu’un package validator voie un fichier inoffensif dans le CD, tandis que l’extracteur respecte un nom/chemin LFH différent.
- Exploiter les noms dupliqués, les entrées présentes uniquement dans une des structures ou des métadonnées de chemin Unicode ambiguës (par exemple, le Info-ZIP Unicode Path Extra Field `0x7075`) afin que différents parsers reconstruisent des arborescences différentes.
- Combiner cela avec un path traversal pour transformer une vue d’archive « inoffensive » en write-primitive lors de l’extraction. Pour le côté extraction, voir [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triage DFIR :
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
Veuillez fournir le contenu à traduire.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiques :
- Rejetez ou isolez les archives dont les noms LFH/CD ne correspondent pas, qui contiennent des noms de fichiers en double, plusieurs enregistrements EOCD ou des octets supplémentaires après le dernier EOCD.<sup>[[10]](#references)</sup>
- Considérez comme suspects les ZIP utilisant des champs supplémentaires de chemin Unicode inhabituels ou des commentaires incohérents si différents outils ne sont pas d'accord sur l'arborescence extraite.<sup>[[9]](#references)</sup>
- Si l'analyse est plus importante que la préservation des octets d'origine, reconditionnez l'archive avec un parser strict après l'extraction dans un sandbox, puis comparez la liste de fichiers obtenue aux métadonnées d'origine.

Cela est important au-delà des écosystèmes de packages : la même classe d'ambiguïté peut dissimuler des payloads aux passerelles de messagerie, aux scanners statiques et aux pipelines d'ingestion personnalisés qui « examinent » le contenu des ZIP avant qu'un autre extracteur ne traite l'archive.

---



## Références

- [1] [Guide de terrain de la forensique CTF (blog de Mike, catégorie CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Partie 1 – Un dropper multistade (anti-reversing APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script Archive::Zip)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Spécification du format de fichier ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [La structure flexible des archives ZIP exploitée pour dissimuler des malwares sans être détectée (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Des hackers dissimulent des malwares dans une nouvelle attaque par fichier ZIP — répertoires centraux ZIP concaténés](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Une meilleure zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Comprendre les zip bombs : construction de noyaux avec chevauchement/citation de chevauchement](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mon ZIP n'est pas votre ZIP : identifier et exploiter les écarts sémantiques entre les parsers ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prévenir les attaques par confusion de parser ZIP contre les installateurs de packages Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Attaques ZIP avec texte en clair connu réduit (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Attaque par texte en clair connu : casser des fichiers ZIP](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
