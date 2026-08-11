# Astuces ZIP

{{#include ../../../banners/hacktricks-training.md}}

Les **outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et cracker les fichiers zip. Voici quelques utilitaires clés :<sup>[[1]](#references)</sup>

- **`unzip`** : indique pourquoi un fichier zip peut ne pas être décompressé.
- **`zipdetails -v`** : fournit une analyse détaillée des champs du format de fichier zip.<sup>[[3]](#references)</sup>
- **`zipinfo`** : liste le contenu d'un fichier zip sans l'extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : tentent de réparer les fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : outil de brute-force pour cracker les mots de passe zip, efficace pour les mots de passe d'environ 7 caractères maximum.

La [spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des informations détaillées sur la structure et les standards des fichiers zip.<sup>[[4]](#references)</sup>

Il est essentiel de noter que les fichiers ZIP traditionnels protégés par mot de passe laissent généralement les noms de fichiers et les tailles de fichiers visibles, contrairement aux modes de chiffrement des en-têtes pris en charge par RAR et 7z. En outre, les fichiers ZIP chiffrés avec l'ancienne méthode ZipCrypto sont vulnérables à une **plaintext attack** si une copie non chiffrée d'un fichier compressé est disponible.<sup>[[1]](#references)</sup> Cette attaque exploite le contenu connu pour cracker le mot de passe du ZIP, comme expliqué dans [cet article académique](https://math.ucr.edu/~mike/zipattacks.pdf) et illustré dans [ce walk-through de Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Cependant, la known-plaintext attack de ZipCrypto ne s'applique pas aux entrées protégées par le chiffrement **AES-256**.<sup>[[1]](#references)</sup>

---

## Astuces anti-reversing dans les APK utilisant des en-têtes ZIP manipulés

Les malware droppers Android modernes utilisent des métadonnées ZIP malformées pour perturber les outils statiques (jadx/apktool/unzip) tout en gardant l'APK installable sur l'appareil. Les astuces les plus courantes sont les suivantes :<sup>[[2]](#references)</sup>

- Fake encryption en définissant le bit 0 du ZIP General Purpose Bit Flag (GPBF)
- Abus de champs Extra volumineux ou personnalisés pour perturber les parsers
- Collisions entre noms de fichiers et de répertoires pour dissimuler de véritables artefacts (par exemple, un répertoire nommé `classes.dex/` à côté du véritable `classes.dex`)

### 1) Fake encryption (bit 0 du GPBF défini) sans véritable chiffrement

Symptômes :
- `jadx-gui` échoue avec des erreurs telles que :

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour les fichiers principaux de l'APK, même si un APK valide ne peut pas contenir `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` chiffrés :

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
Examinez le General Purpose Bit Flag des en-têtes local et central. Une valeur révélatrice est le bit 0 activé (Encryption), même pour les entrées core :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : si un APK s’installe et s’exécute sur l’appareil, mais que les entrées principales apparaissent comme « chiffrées » pour les outils, le GPBF a été altéré.

Corrigez cela en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Patcher d’octets minimal :

<details>
<summary>Patcher minimal d’effacement du bit GPBF</summary>
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

Les attaquants insèrent des champs Extra surdimensionnés ainsi que des ID inhabituels dans les en-têtes afin de perturber les décompilateurs. Dans la nature, vous pouvez voir des marqueurs personnalisés (par exemple, des chaînes comme `JADXBLOCK`) qui y sont intégrés.

Inspection :
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : des IDs inconnus comme `0xCAFE` (« Java Executable ») ou `0x414A` (« JA: ») contenant de grandes charges utiles.<sup>[[2]](#references)</sup>

Heuristiques DFIR :
- Déclencher une alerte lorsque les champs Extra sont inhabituellement volumineux dans les entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer comme suspects les IDs Extra inconnus sur ces entrées.

Mitigation pratique : reconstruire l’archive (par exemple, en re-zippant les fichiers extraits) supprime les champs Extra malveillants. Si les outils refusent l’extraction en raison d’un chiffrement factice, effacer d’abord le bit 0 du GPBF comme indiqué ci-dessus, puis reconditionner :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisions de noms de fichiers/répertoires (dissimulation de vrais artefacts)

Un ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs peuvent être désorientés et superposer ou dissimuler le fichier réel avec une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms APK fondamentaux comme `classes.dex`.

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
- Signaler les champs Extra volumineux/inconnus sur les entrées principales (rechercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Autres tricks malveillants liés aux ZIP (2024–2026)

### Central directories concaténés (évasion multi-EOCD)

Dans une campagne de phishing de 2024, les attaquants ont fourni un blob unique qui était en réalité **deux fichiers ZIP concaténés**. Chacun possédait son propre enregistrement End of Central Directory (EOCD) et son propre central directory. Différents extractors analysaient des directories différents (7-Zip lisait le premier, tandis que WinRAR lisait le dernier), ce qui permettait aux attaquants de dissimuler des payloads que seuls certains outils affichaient ; les scanners qui n’inspectent qu’un seul directory peuvent manquer l’autre archive.<sup>[[5]](#references)[[6]](#references)</sup>

**Commandes de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Si plusieurs EOCD apparaissent ou si des avertissements « data after payload » sont présents, scindez le blob et examinez chaque partie :
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Les ZIP bombs Quoted-overlap construisent un petit **kernel** (un bloc DEFLATE hautement compressé) et le réutilisent dans plusieurs entrées qui se chevauchent. Les variantes en chevauchement total font pointer plusieurs entrées du répertoire central vers un seul en-tête local, tandis que les variantes Quoted-overlap intègrent des en-têtes locaux dans les flux DEFLATE ; la construction publiée atteint un ratio supérieur à 28M:1 sans archives imbriquées.<sup>[[7]](#references)</sup>

**Quick detection (duplicate LFH offsets)**
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
- Effectuez une analyse à blanc : `zipdetails -v file.zip | grep -n "Local Header Offset"` et comparez les offsets des local headers référencés ainsi que les plages de données compressées ; des offsets dupliqués signalent des variantes avec chevauchement complet.<sup>[[7]](#references)[[8]](#references)</sup>
- Limitez la taille totale acceptée après décompression et le nombre d'entrées avant l'extraction à l'aide d'un parser ; `zipinfo -t file.zip` indique les totaux, mais n'applique aucune limite de sécurité.<sup>[[8]](#references)</sup>
- Lorsque l'extraction est nécessaire, effectuez-la dans un cgroup/VM avec des limites CPU et disque (pour éviter les crashes liés à une inflation non bornée).<sup>[[8]](#references)</sup>

---

### Confusion entre les parsers du local header et du central directory

Des recherches récentes sur les differential parsers ont montré que l'ambiguïté des ZIP reste exploitable dans les toolchains modernes. L'idée principale est simple : certains logiciels font confiance au **Local File Header (LFH)**, tandis que d'autres font confiance au **Central Directory (CD)** ; une même archive peut donc présenter des noms de fichiers, des chemins, des commentaires, des offsets ou des ensembles d'entrées différents selon les outils.<sup>[[9]](#references)</sup>

Utilisations offensives pratiques :
- Faire en sorte qu'un upload filter, qu'un pré-scan AV ou qu'un package validator voie un fichier bénin dans le CD, tandis que l'extracteur respecte un nom ou un chemin LFH différent.
- Exploiter des noms dupliqués, des entrées présentes dans une seule structure ou des métadonnées de chemin Unicode ambiguës (par exemple, le champ supplémentaire Info-ZIP Unicode Path `0x7075`) afin que différents parsers reconstruisent des arborescences différentes.
- Combiner cela avec un path traversal pour transformer la vue d'une archive « inoffensive » en primitive d'écriture lors de l'extraction. Pour la partie extraction, voir [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Veuillez fournir le texte à traduire après « Complement it with: ».
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiques :
- Pour l'ingestion sensible à la sécurité, rejetez ou isolez les archives dont les noms LFH/CD ne correspondent pas, qui contiennent des noms de fichiers dupliqués, plusieurs enregistrements EOCD ou des octets supplémentaires après le dernier EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Considérez comme suspects les ZIP utilisant des extra fields inhabituels pour les chemins Unicode ou des commentaires incohérents si différents outils ne sont pas d'accord sur l'arborescence extraite.<sup>[[4]](#references)[[9]](#references)</sup>
- Si l'analyse est plus importante que la préservation des octets d'origine, reconditionnez l'archive avec un parser strict après extraction dans un sandbox, puis comparez la liste de fichiers obtenue aux métadonnées d'origine.

Cela importe au-delà des écosystèmes de packages : la même classe d'ambiguïté peut dissimuler des payloads aux mail gateways, aux static scanners et aux pipelines d'ingestion personnalisés qui « examinent » le contenu des ZIP avant qu'un autre extractor ne traite l'archive.<sup>[[9]](#references)</sup>

---



## References

- [1] [Guide de terrain de la forensique CTF (blog de Mike, catégorie CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Partie 1 – Un dropper multistage (anti-reversing APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Spécification du format de fichier ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Structure flexible des archives Zip exploitée pour dissimuler des malwares sans être détectée (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Des hackers dissimulent des malwares dans une nouvelle attaque de fichiers ZIP — central directories ZIP concaténés](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Une meilleure zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Comprendre les Zip Bombs : construction de kernel avec overlapping/quoted-overlap](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mon ZIP n'est pas votre ZIP : identifier et exploiter les écarts sémantiques entre les ZIP parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prévenir les attaques de confusion de ZIP parser contre les installateurs de packages Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Attaques ZIP avec une portion de plaintext connue réduite (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site : mission Web réaliste, niveau 15 (attaque ZIP à plaintext connu)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
