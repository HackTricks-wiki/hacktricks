# Astuces ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Les outils en ligne de commande** pour gérer les fichiers zip sont essentiels pour diagnostiquer, réparer et cracking des fichiers zip. Voici quelques utilitaires clés :

- **`unzip`** : Indique pourquoi un fichier zip peut ne pas se décompresser.
- **`zipdetails -v`** : Offre une analyse détaillée des champs du format zip.
- **`zipinfo`** : Liste le contenu d'un fichier zip sans l'extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : Tentent de réparer des fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : Un outil pour le brute-force des mots de passe zip, efficace pour des mots de passe jusqu'à environ 7 caractères.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des détails complets sur la structure et les standards des fichiers zip.

Il est crucial de noter que les fichiers zip protégés par mot de passe **n'encryptent pas les noms de fichiers ni les tailles de fichiers** à l'intérieur, une faille de sécurité qui n'est pas présente dans les fichiers RAR ou 7z qui chiffrent ces informations. De plus, les fichiers zip chiffrés avec l'ancienne méthode ZipCrypto sont vulnérables à une plaintext attack si une copie non chiffrée d'un fichier compressé est disponible. Cette attaque exploite le contenu connu pour craquer le mot de passe du zip, une vulnérabilité détaillée dans l'article de HackThis et expliquée plus en détail dans cet article académique. Cependant, les fichiers zip sécurisés avec **AES-256** sont immunisés contre cette plaintext attack, ce qui montre l'importance de choisir des méthodes de chiffrement sécurisées pour les données sensibles.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Les droppers Android modernes utilisent des métadonnées ZIP malformées pour casser les outils statiques (jadx/apktool/unzip) tout en gardant l'APK installable sur l'appareil. Les astuces les plus courantes sont :

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptômes :
- `jadx-gui` échoue avec des erreurs comme :

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour des fichiers APK essentiels alors qu'un APK valide ne peut pas avoir `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` chiffrés :

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
Regardez le General Purpose Bit Flag pour les local and central headers. Une valeur révélatrice est le bit 0 activé (Encryption) même pour les core entries :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : Si une APK s'installe et s'exécute sur l'appareil mais que les core entries apparaissent « chiffrées » pour les outils, le GPBF a été altéré.

Corriger en mettant à zéro le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Patcheur d'octets minimal :

<details>
<summary>Patcheur minimal pour réinitialiser le bit 0 du GPBF</summary>
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
Vous devriez maintenant voir `General Purpose Flag  0000` sur les entrées core et les outils analyseront de nouveau l'APK.

### 2) Champs Extra volumineux/personnalisés pour casser les analyseurs

Les attaquants remplissent des champs Extra surdimensionnés et des IDs étranges dans les en-têtes pour faire échouer les décompilateurs. Dans la nature, vous pouvez voir des marqueurs personnalisés (p. ex., des chaînes comme `JADXBLOCK`) insérés à cet endroit.

Inspection :
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : des IDs inconnus comme `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") portant de gros payloads.

DFIR heuristics :
- Générer une alerte lorsque les champs Extra sont anormalement volumineux sur les entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer les IDs Extra inconnus sur ces entrées comme suspects.

Mitigation pratique : reconstruire l'archive (par ex., re-zipping les fichiers extraits) supprime les champs Extra malveillants. Si les outils refusent d'extraire à cause d'une fausse encryption, effacez d'abord GPBF bit 0 comme indiqué ci-dessus, puis reconditionnez :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisions de noms de fichier/répertoire (masquer les artefacts réels)

Une archive ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs peuvent se tromper et superposer ou masquer le fichier réel par une entrée de répertoire. Cela a été observé avec des entrées entrant en collision avec des noms d'APK principaux comme `classes.dex`.

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
Suffixe de détection programmatique:
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
Idées de détection Blue-team :
- Signaler les APKs dont les en-têtes locaux indiquent un chiffrement (GPBF bit 0 = 1) mais qui s'installent/s'exécutent.
- Signaler les Extra fields volumineux/inconnus sur les entrées core (vérifier la présence de marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Autres astuces malveillantes pour ZIP (2024–2026)

### Répertoires centraux concaténés (évasion multi-EOCD)

Des campagnes de phishing récentes envoient un seul blob qui est en fait **deux fichiers ZIP concaténés**. Chacun contient son propre End of Central Directory (EOCD) et son central directory. Différents extracteurs analysent des répertoires différents (7zip lit le premier, WinRAR le dernier), ce qui permet aux attaquants de cacher des payloads que seuls certains outils affichent. Cela contourne également les AV de passerelle mail basiques qui n'inspectent que le premier répertoire.

**Commandes de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Si plus d'un EOCD apparaît ou s'il y a des avertissements "data after payload", scindez le blob et inspectez chaque partie :
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

La "better zip bomb" moderne construit un petit **kernel** (bloc DEFLATE fortement compressé) et le réutilise via des local headers qui se chevauchent. Chaque entrée du central directory pointe vers les mêmes données compressées, atteignant des ratios >28M:1 sans imbriquer d'archives. Les bibliothèques qui font confiance aux tailles du central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP avant les versions durcies) peuvent être forcées à allouer des pétaoctets.

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
- Effectuer une vérification à blanc : `zipdetails -v file.zip | grep -n "Rel Off"` et s'assurer que les offsets sont strictement croissants et uniques.
- Limiter la taille totale décompressée acceptée et le nombre d'entrées avant extraction (`zipdetails -t` ou parseur personnalisé).
- Lorsque vous devez extraire, faites-le à l'intérieur d'un cgroup/VM avec des limites CPU et disque (éviter les plantages dus à une inflation non bornée).

---

### Confusion des parseurs Local-header vs central-directory

Des recherches récentes sur les parseurs différentiels ont montré que l'ambiguïté des ZIP reste exploitable dans les chaînes d'outils modernes. L'idée principale est simple : certains logiciels font confiance au **Local File Header (LFH)** tandis que d'autres font confiance au **Central Directory (CD)**, si bien qu'une archive peut présenter des noms de fichiers, chemins, commentaires, offsets ou ensembles d'entrées différents selon les outils.

Usages offensifs pratiques:
- Faire en sorte qu'un filtre d'upload, un pré-scan AV ou un validateur de package voie un fichier bénin dans le CD tandis que l'extracteur utilise un nom/chemin différent tiré du LFH.
- Abuser de noms dupliqués, d'entrées présentes uniquement dans une structure, ou de métadonnées de chemin Unicode ambiguës (par exemple, Info-ZIP Unicode Path Extra Field `0x7075`) afin que des parseurs différents reconstruisent des arbres différents.
- Combinez ceci avec path traversal pour transformer une vue "inoffensive" de l'archive en une write-primitive lors de l'extraction. Pour le côté extraction, voir [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triage DFIR:
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
Je n'ai pas reçu le contenu à compléter. Peux-tu coller le texte de src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md que tu veux que je traduise / complète, ou préciser exactement quels sujets / sections tu veux ajouter (par ex. Zip headers, ZipSlip, ZipCrypto vs AES, zip bombs, concatenated zips, timestamps, metadata, signed zips, outils de forensic, commandes pratiques, exemples) ?
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristiques:
- Rejeter ou isoler les archives dont les noms LFH/CD ne correspondent pas, qui contiennent des noms de fichiers dupliqués, plusieurs enregistrements EOCD, ou des octets traînants après l'EOCD final.
- Considérer comme suspects les ZIPs utilisant des champs extra Unicode-path inhabituels ou des commentaires inconsistants si différents outils divergent sur l'arborescence extraite.
- Si l'analyse prime sur la préservation des octets originaux, reconditionner l'archive avec un parseur strict après extraction dans un sandbox et comparer la liste de fichiers résultante aux métadonnées d'origine.

Cela importe au-delà des écosystèmes de packages : la même classe d'ambiguïté peut dissimuler des payloads aux passerelles mail, aux scanners statiques et aux pipelines d'ingestion personnalisés qui "jettent un coup d'œil" au contenu des ZIP avant qu'un autre extracteur ne traite l'archive.

---



## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
