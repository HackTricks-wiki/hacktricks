# Astuces ZIP

Les **outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et cracker les fichiers zip. Voici quelques utilitaires clés :<sup>[[1]](#references)</sup>

- **`unzip`** : Révèle pourquoi un fichier zip peut ne pas être décompressé.
- **`zipdetails -v`** : Fournit une analyse détaillée des champs du format de fichier zip.<sup>[[3]](#references)</sup>
- **`zipinfo`** : Liste le contenu d’un fichier zip sans l’extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : Tentent de réparer les fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : Un outil de brute-force pour cracker les mots de passe zip, efficace pour les mots de passe d’environ 7 caractères au maximum.

La [spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des informations complètes sur la structure et les standards des fichiers zip.<sup>[[4]](#references)</sup>

Il est important de noter que les fichiers ZIP traditionnels protégés par mot de passe laissent généralement les noms de fichiers et les tailles de fichiers visibles, contrairement aux modes de chiffrement des headers pris en charge par RAR et 7z. De plus, les fichiers ZIP chiffrés avec l’ancienne méthode ZipCrypto sont vulnérables à une **plaintext attack** lorsqu’une copie non chiffrée d’un fichier compressé est disponible.<sup>[[1]](#references)</sup> Cette attaque exploite le contenu connu pour cracker le mot de passe du ZIP, comme l’expliquent [cet article académique](https://math.ucr.edu/~mike/zipattacks.pdf) et l’illustre [ce walk-through de Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Cependant, la known-plaintext attack de ZipCrypto ne s’applique pas aux entrées protégées par un chiffrement **AES-256**.<sup>[[1]](#references)</sup>

---

## Techniques anti-reversing dans les APK utilisant des headers ZIP manipulés

Les droppers de malware Android modernes utilisent des métadonnées ZIP malformées pour faire échouer les outils statiques (jadx/apktool/unzip) tout en maintenant l’installation de l’APK sur l’appareil. Les astuces les plus courantes sont les suivantes :<sup>[[2]](#references)</sup>

- Fausse encryption en définissant le bit 0 du ZIP General Purpose Bit Flag (GPBF)
- Abus de champs Extra volumineux/personnalisés pour perturber les parsers
- Collisions entre les noms de fichiers et de répertoires pour masquer de vrais artifacts (par exemple, un répertoire nommé `classes.dex/` à côté du véritable `classes.dex`)

### 1) Fausse encryption (bit 0 du GPBF défini) sans véritable crypto

Symptômes :
- `jadx-gui` échoue avec des erreurs telles que :

``` 
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour les fichiers APK principaux, même si un APK valide ne peut pas contenir `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` chiffrés :

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
Examinez le General Purpose Bit Flag des en-têtes local et central. Une valeur révélatrice est le bit 0 activé (Encryption), même pour les entrées centrales :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : Si un APK s’installe et s’exécute sur l’appareil, mais que les entrées principales apparaissent comme « encrypted » pour les outils, le GPBF a été altéré.

Corrigez cela en effaçant le bit 0 du GPBF dans les entrées des Local File Headers (LFH) et du Central Directory (CD). Patcher d’octets minimal :

<details>
<summary>Patcher minimal pour effacer le bit du GPBF</summary>
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

### 2) Champs Extra volumineux/personnalisés pour perturber les parsers

Les attaquants insèrent des champs Extra surdimensionnés et des ID inhabituels dans les headers afin de faire échouer les décompilateurs. Dans la nature, vous pouvez voir des marqueurs personnalisés (par exemple, des chaînes comme `JADXBLOCK`) qui y sont intégrés.

Inspection :
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : des IDs inconnus comme `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") contenant de larges payloads.<sup>[[2]](#references)</sup>

Heuristiques DFIR :
- Déclencher une alerte lorsque les champs Extra sont inhabituellement volumineux sur les entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer les IDs Extra inconnus sur ces entrées comme suspects.

Mesure d’atténuation pratique : reconstruire l’archive (par exemple, rezipper les fichiers extraits) supprime les champs Extra malveillants. Si les outils refusent l’extraction en raison d’un faux chiffrement, effacez d’abord le bit 0 du GPBF comme indiqué ci-dessus, puis reconditionnez :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisions de noms de fichiers/répertoires (dissimulation d’artefacts réels)

Un ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs peuvent être désorientés et superposer ou dissimuler le fichier réel avec une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms APK essentiels comme `classes.dex`.

Triage et extraction sécurisée :
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Détection programmatique après correction :
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
Idées de détection côté Blue-team :
- Signaler les APK dont les en-têtes locaux indiquent un chiffrement (GPBF bit 0 = 1), mais qui s’installent/s’exécutent.
- Signaler les champs Extra volumineux/inconnus sur les entrées principales (chercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc` et `classes*.dex`.

---

## Autres techniques malveillantes liées aux ZIP (2024–2026)

### Répertoires centraux concaténés (évasion multi-EOCD)

Lors d’une campagne de phishing en 2024, les attaquants ont distribué un blob unique qui était en réalité **deux fichiers ZIP concaténés**. Chacun possédait son propre enregistrement End of Central Directory (EOCD) et son propre répertoire central. Différents extracteurs analysaient des répertoires différents (7-Zip lisait le premier, tandis que WinRAR lisait le dernier), permettant aux attaquants de dissimuler des payloads que seuls certains outils affichaient ; les scanners qui n’inspectent qu’un seul répertoire peuvent manquer l’autre archive.<sup>[[5]](#references)[[6]](#references)</sup>

**Commandes de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Si plusieurs EOCD apparaissent ou si des avertissements « data after payload » sont affichés, découpez le blob et examinez chaque partie :
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Les ZIP bombs Quoted-overlap construisent un petit **kernel** (un bloc DEFLATE fortement compressé) et le réutilisent entre des entrées qui se chevauchent. Les variantes en chevauchement complet font pointer plusieurs entrées du répertoire central vers un même en-tête local, tandis que les variantes Quoted-overlap citent des en-têtes locaux à l’intérieur des flux DEFLATE ; la construction publiée atteint un ratio supérieur à 28M:1 sans archives imbriquées.<sup>[[7]](#references)</sup>

**Détection rapide (duplicate LFH offsets)**
```python
# detect full-overlap variants by identical relative offsets
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
- Effectuez une analyse à blanc : `zipdetails -v file.zip | grep -n "Local Header Offset"` et comparez les offsets des en-têtes locaux référencés ainsi que les plages de données compressées ; des offsets dupliqués signalent des variantes avec chevauchement complet.<sup>[[7]](#references)[[8]](#references)</sup>
- Limitez la taille totale acceptée après décompression et le nombre d'entrées avant l'extraction avec un parser ; `zipinfo -t file.zip` affiche les totaux, mais n'impose pas de limite de sécurité.<sup>[[8]](#references)</sup>
- Lorsque l'extraction est nécessaire, effectuez-la dans un cgroup/VM avec des limites CPU et disque (pour éviter les crashes dus à une inflation non bornée).<sup>[[8]](#references)</sup>

---

### Confusion entre les parsers des en-têtes locaux et du répertoire central

Des recherches récentes sur les parsers différentiels ont montré que l'ambiguïté ZIP reste exploitable dans les toolchains modernes. L'idée principale est simple : certains logiciels font confiance au **Local File Header (LFH)**, tandis que d'autres font confiance au **Central Directory (CD)**. Ainsi, une archive peut présenter des noms de fichiers, des chemins, des commentaires, des offsets ou des ensembles d'entrées différents selon les tools utilisés.<sup>[[9]](#references)</sup>

Utilisations offensives pratiques :
- Faire en sorte qu'un upload filter, qu'un pré-scan AV ou qu'un package validator voie un fichier bénin dans le CD, tandis que l'extractor utilise un nom/chemin LFH différent.
- Exploiter les noms dupliqués, les entrées présentes dans une seule structure ou des métadonnées de chemin Unicode ambiguës (par exemple, le champ supplémentaire Info-ZIP Unicode Path `0x7075`) afin que différents parsers reconstruisent des arbres différents.
- Combiner cela avec un path traversal pour transformer une vue d'archive « inoffensive » en write-primitive lors de l'extraction. Pour le côté extraction, voir [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Veuillez fournir le texte à traduire.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiques :
- Pour l'ingestion sensible à la sécurité, rejetez ou isolez les archives dont les noms LFH/CD ne correspondent pas, qui contiennent des noms de fichiers en double, plusieurs enregistrements EOCD ou des octets supplémentaires après le dernier EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Considérez les ZIP utilisant des champs supplémentaires de chemin Unicode inhabituels ou des commentaires incohérents comme suspects si différents outils ne sont pas d'accord sur l'arbre extrait.<sup>[[4]](#references)[[9]](#references)</sup>
- Si l'analyse est plus importante que la préservation des octets d'origine, reconditionnez l'archive avec un parseur strict après extraction dans un sandbox, puis comparez la liste de fichiers obtenue aux métadonnées d'origine.

Cela est important au-delà des écosystèmes de packages : la même classe d'ambiguïté peut dissimuler des payloads aux passerelles de messagerie, aux scanners statiques et aux pipelines d'ingestion personnalisés qui « inspectent » le contenu des ZIP avant qu'un autre extracteur ne traite l'archive.<sup>[[9]](#references)</sup>

---



## References

- [1] [Guide de terrain de la forensic pour les CTF (blog de Mike, catégorie CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Partie 1 – Un dropper multistade (anti-reversing d'APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Spécification du format de fichier ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [La structure flexible des archives ZIP exploitée pour dissimuler des malwares sans être détectée (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Des hackers enfouissent des malwares dans une nouvelle attaque via des fichiers ZIP — répertoires centraux ZIP concaténés](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Une meilleure zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Comprendre les zip bombs : construction de noyau avec chevauchement/chevauchement cité](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mon ZIP n'est pas votre ZIP : identifier et exploiter les écarts sémantiques entre les parseurs ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Empêcher les attaques par confusion de parseurs ZIP contre les installateurs de packages Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Attaques ZIP avec texte en clair connu réduit (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site : mission Web réaliste, niveau 15 (attaque ZIP à texte en clair connu)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
