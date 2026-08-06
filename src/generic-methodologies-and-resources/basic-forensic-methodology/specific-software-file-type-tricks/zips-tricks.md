# Techniques sur les ZIP

{{#include ../../../banners/hacktricks-training.md}}

Les **outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et cracker des fichiers zip. Voici quelques utilitaires clés :<sup>[[1]](#references)</sup>

- **`unzip`** : indique pourquoi un fichier zip peut ne pas être décompressé.
- **`zipdetails -v`** : fournit une analyse détaillée des champs du format de fichier zip.<sup>[[3]](#references)</sup>
- **`zipinfo`** : liste le contenu d'un fichier zip sans l'extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : tentent de réparer les fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : outil de brute-force cracking des mots de passe zip, efficace pour les mots de passe allant jusqu'à environ 7 caractères.

La [spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des informations détaillées sur la structure et les standards des fichiers zip.<sup>[[4]](#references)</sup>

Il est important de noter que les fichiers zip protégés par mot de passe **ne chiffrent pas les noms de fichiers ni les tailles des fichiers** qu'ils contiennent, une faille de sécurité qui n'existe pas dans les fichiers RAR ou 7z, qui chiffrent ces informations. De plus, les fichiers zip chiffrés avec l'ancienne méthode ZipCrypto sont vulnérables à une **plaintext attack** si une copie non chiffrée d'un fichier compressé est disponible.<sup>[[1]](#references)</sup> Cette attaque exploite le contenu connu pour cracker le mot de passe du zip, une vulnérabilité détaillée dans [l'article de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus en détail dans [cet article académique](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Cependant, les fichiers zip sécurisés avec le chiffrement **AES-256** sont immunisés contre cette plaintext attack, ce qui montre l'importance de choisir des méthodes de chiffrement sécurisées pour les données sensibles.<sup>[[1]](#references)</sup>

---

## Techniques anti-reversing dans les APK utilisant des headers ZIP manipulés

Les malware droppers Android modernes utilisent des métadonnées ZIP malformées pour faire échouer les outils statiques (jadx/apktool/unzip), tout en conservant la possibilité d'installer l'APK sur l'appareil. Les techniques les plus courantes sont :<sup>[[2]](#references)</sup>

- Fake encryption en définissant le bit 0 du ZIP General Purpose Bit Flag (GPBF)
- Abus de champs Extra volumineux/personnalisés pour perturber les parsers
- Collisions de noms de fichiers/répertoires pour masquer de vrais artifacts (par exemple, un répertoire nommé `classes.dex/` à côté du véritable `classes.dex`)

### 1) Fake encryption (bit 0 du GPBF défini) sans véritable crypto

Symptômes :
- `jadx-gui` échoue avec des erreurs telles que :

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour les fichiers APK essentiels, alors qu'un APK valide ne peut pas contenir de `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` chiffrés :

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
Examinez le General Purpose Bit Flag des en-têtes local et central. Une valeur révélatrice est le bit 0 défini (Encryption), même pour les entrées principales :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : si un APK s’installe et s’exécute sur l’appareil, mais que les entrées principales apparaissent comme « encrypted » pour les outils, le GPBF a été altéré.

Corrigez cela en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Patcher minimal au niveau des octets :

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
Vous devriez maintenant voir `General Purpose Flag  0000` dans les entrées principales, et les outils pourront à nouveau analyser l’APK.

### 2) Champs Extra volumineux/personnalisés pour perturber les parsers

Les attaquants insèrent des champs Extra surdimensionnés et des identifiants inhabituels dans les en-têtes afin de perturber les décompilateurs. Dans la nature, vous pouvez voir des marqueurs personnalisés (par exemple, des chaînes comme `JADXBLOCK`) qui y sont intégrés.

Inspection :
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : identifiants inconnus comme `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") contenant de grandes charges utiles.

Heuristiques DFIR :
- Déclencher une alerte lorsque les champs Extra sont inhabituellement volumineux dans les entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer les identifiants Extra inconnus sur ces entrées comme suspects.

Mitigation pratique : reconstruire l’archive (par exemple, en re-zippant les fichiers extraits) supprime les champs Extra malveillants. Si les outils refusent l’extraction en raison d’un chiffrement factice, effacer d’abord le bit 0 du GPBF comme indiqué ci-dessus, puis reconditionner :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisions de noms de fichiers/répertoires (dissimulation de véritables artefacts)

Un ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs peuvent être désorientés et superposer ou masquer le véritable fichier avec une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms APK essentiels comme `classes.dex`.

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
Blue-team detection ideas:
- Signaler les APK dont les en-têtes locaux indiquent un chiffrement (GPBF bit 0 = 1), mais qui s’installent/s’exécutent.
- Signaler les champs Extra volumineux/inconnus sur les entrées principales (rechercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc` et `classes*.dex`.

---

## Autres techniques ZIP malveillantes (2024–2026)

### Répertoires centraux concaténés (évasion multi-EOCD)

De récentes campagnes de phishing distribuent un blob unique qui est en réalité **deux fichiers ZIP concaténés**. Chacun possède son propre End of Central Directory (EOCD) et son propre répertoire central. Les extracteurs traitent des répertoires différents (7zip lit le premier, WinRAR le dernier), ce qui permet aux attaquants de dissimuler des payloads que seuls certains outils affichent. Cela contourne également les systèmes anti-virus basiques des passerelles de messagerie qui n’inspectent que le premier répertoire.<sup>[[5]](#references)[[6]](#references)</sup>

**Commandes de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Si plusieurs EOCD apparaissent ou s'il y a des avertissements « data after payload », scindez le blob et examinez chaque partie :
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Bombes à chevauchement cité / à entrées chevauchantes (non récursives)

Les constructions modernes de **better zip bomb** créent un petit **kernel** (bloc DEFLATE hautement compressé) et le réutilisent via des en-têtes locaux chevauchants. Chaque entrée du répertoire central pointe vers les mêmes données compressées, atteignant des ratios supérieurs à 28M:1 sans imbriquer d’archives. Les bibliothèques qui font confiance aux tailles du répertoire central (`zipfile` de Python, `java.util.zip` de Java, Info-ZIP avant les builds renforcés) peuvent être contraintes d’allouer des pétaoctets.<sup>[[7]](#references)[[8]](#references)</sup>

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
- Effectuez un parcours à blanc : `zipdetails -v file.zip | grep -n "Rel Off"` et vérifiez que les offsets sont strictement croissants et uniques.
- Limitez la taille totale décompressée et le nombre d'entrées acceptés avant l'extraction (`zipdetails -t` ou un parser personnalisé).
- Lorsque l'extraction est nécessaire, effectuez-la dans un cgroup/VM avec des limites CPU et disque (évitez les crashes dus à une inflation non bornée).

---

### Confusion entre les parsers du Local-header et du central-directory

De récentes recherches sur les parsers différentiels ont montré que l'ambiguïté des ZIP reste exploitable dans les toolchains modernes. L'idée principale est simple : certains logiciels font confiance au **Local File Header (LFH)**, tandis que d'autres font confiance au **Central Directory (CD)** ; une même archive peut donc présenter des noms de fichiers, chemins, commentaires, offsets ou ensembles d'entrées différents selon les outils.<sup>[[9]](#references)</sup>

Utilisations offensives pratiques :
- Faire en sorte qu'un filtre d'upload, un pré-scan AV ou un validateur de package voie un fichier bénin dans le CD, tandis que l'extracteur respecte un nom/chemin LFH différent.
- Exploiter les noms en double, les entrées présentes dans une seule structure ou des métadonnées de chemin Unicode ambiguës (par exemple, le champ supplémentaire Unicode Path d'Info-ZIP `0x7075`) afin que différents parsers reconstruisent des arborescences différentes.
- Combiner cela avec un path traversal pour transformer une vue d'archive « inoffensive » en primitive d'écriture lors de l'extraction. Pour le côté extraction, voir [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Veuillez fournir le texte à compléter ou à traduire.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiques :
- Rejeter ou isoler les archives dont les noms LFH/CD ne correspondent pas, qui contiennent des noms de fichiers en double, plusieurs enregistrements EOCD ou des octets suivant le dernier EOCD.<sup>[[10]](#references)</sup>
- Considérer comme suspects les ZIP utilisant des champs supplémentaires de chemin Unicode inhabituels ou des commentaires incohérents si différents outils ne sont pas d'accord sur l'arborescence extraite.<sup>[[9]](#references)</sup>
- Si l'analyse est plus importante que la préservation des octets originaux, reconditionner l'archive avec un parseur strict après extraction dans un sandbox, puis comparer la liste de fichiers obtenue aux métadonnées originales.

Cela est important au-delà des écosystèmes de packages : la même classe d'ambiguïté peut dissimuler des payloads aux passerelles de messagerie, aux scanners statiques et aux pipelines d'ingestion personnalisés qui « jettent un coup d'œil » au contenu des ZIP avant qu'un autre extracteur ne traite l'archive.

---



## Références

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
