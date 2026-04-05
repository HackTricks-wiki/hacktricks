# Astuces ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Les outils en ligne de commande** pour gérer **les fichiers zip** sont essentiels pour diagnostiquer, réparer et craquer les fichiers zip. Voici quelques utilitaires clés :

- **`unzip`** : indique pourquoi un fichier zip peut ne pas se décompresser.
- **`zipdetails -v`** : offre une analyse détaillée des champs du format zip.
- **`zipinfo`** : liste le contenu d'un zip sans les extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : tentent de réparer des fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : un outil pour le cracking par force brute des mots de passe de zip, efficace pour des mots de passe d'environ 7 caractères.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des détails complets sur la structure et les standards des fichiers zip.

Il est crucial de noter que les fichiers zip protégés par mot de passe **n'encryptent pas les noms de fichiers ni les tailles de fichiers** en interne, une faiblesse de sécurité que RAR ou 7z n'ont pas puisqu'ils chiffrent ces informations. De plus, les fichiers zip chiffrés avec l'ancienne méthode ZipCrypto sont vulnérables à une **plaintext attack** si une copie non chiffrée d'un fichier compressé est disponible. Cette attaque exploite le contenu connu pour craquer le mot de passe du zip, une vulnérabilité détaillée dans [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus en détail dans [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Cependant, les fichiers zip protégés par **AES-256** sont immunisés contre cette plaintext attack, ce qui montre l'importance de choisir des méthodes de chiffrement solides pour les données sensibles.

---

## Astuces anti-reverse dans les APKs utilisant des en-têtes ZIP manipulés

Les droppers de malware Android modernes utilisent des métadonnées ZIP malformées pour casser les outils statiques (jadx/apktool/unzip) tout en conservant l'APK installable sur l'appareil. Les astuces les plus courantes sont :

- Chiffrement factice en réglant le bit 0 du ZIP General Purpose Bit Flag (GPBF)
- Abuser des grands/champs Extra personnalisés pour confondre les parseurs
- Collisions de noms de fichiers/répertoires pour cacher des artefacts réels (par ex., un répertoire nommé `classes.dex/` à côté du vrai `classes.dex`)

### 1) Chiffrement factice (bit 0 du GPBF réglé) sans véritable crypto

Symptômes :
- `jadx-gui` échoue avec des erreurs comme :

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` demande un mot de passe pour des fichiers APK essentiels alors qu'un APK valide ne peut pas contenir les fichiers `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` chiffrés :

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
Regardez le General Purpose Bit Flag des en-têtes locaux et centraux. Une valeur révélatrice est le bit 0 activé (Encryption), même pour les core entries :
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristique : Si un APK s'installe et s'exécute sur l'appareil mais que des entrées core apparaissent "encrypted" pour les outils, le GPBF a été altéré.

Corriger en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Patcheur d'octets minimal :

<details>
<summary>Patcheur minimal pour effacement du bit GPBF</summary>
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
Vous devriez maintenant voir `General Purpose Flag  0000` sur les entrées principales et les outils analyseront à nouveau l'APK.

### 2) Gros champs Extra personnalisés pour casser les parseurs

Les attaquants insèrent des champs Extra surdimensionnés et des IDs étranges dans les en-têtes pour tromper les décompilateurs. Sur le terrain, vous pouvez trouver des marqueurs personnalisés (p. ex., des chaînes comme `JADXBLOCK`) intégrés là.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemples observés : unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads.

DFIR heuristics:
- Alerter lorsque les Extra fields sont inhabituellement volumineux sur les entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer les Extra IDs inconnus sur ces entrées comme suspects.

Practical mitigation: la reconstruction de l'archive (par ex., re-zipping des fichiers extraits) supprime les Extra fields malveillants. Si les outils refusent d'extraire en raison d'une fausse encryption, effacez d'abord le bit 0 du GPBF comme indiqué ci-dessus, puis reconditionnez :
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collision de noms fichier/répertoire (masquer les vrais artefacts)

Un ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs se trompent et peuvent recouvrir ou masquer le fichier réel au profit d'une entrée de répertoire. Cela a été observé lorsque des entrées entrent en collision avec des noms d'APK principaux comme `classes.dex`.

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
Blue-team detection ideas:
- Signaler les APK dont les en-têtes locaux indiquent le chiffrement (GPBF bit 0 = 1) mais qui s'installent/s'exécutent.
- Signaler les Extra fields volumineux/inconnus sur les entrées core (chercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemin (`X` and `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Autres astuces malveillantes sur ZIP (2024–2026)

### Répertoires centraux concaténés (évasion multi-EOCD)

Les campagnes de phishing récentes envoient un seul blob qui est en réalité **deux fichiers ZIP concaténés**. Chacun a son propre End of Central Directory (EOCD) + central directory. Différents extracteurs analysent différents répertoires (7zip lit le premier, WinRAR le dernier), permettant aux attaquants de cacher des payloads que seuls certains outils affichent. Cela contourne aussi l'AV basique des passerelles mail qui n'inspecte que le premier répertoire.

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

Les "better zip bomb" modernes construisent un minuscule **kernel** (bloc DEFLATE fortement compressé) et le réutilisent via des local headers qui se chevauchent. Chaque entrée du central directory pointe vers les mêmes données compressées, atteignant des rapports >28M:1 sans imbriquer d'archives. Les bibliothèques qui se fient aux tailles du central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP avant les versions durcies) peuvent être contraintes d'allouer des pétaoctets.

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
- Effectuez un parcours en dry-run : `zipdetails -v file.zip | grep -n "Rel Off"` et assurez-vous que les offsets sont strictement croissants et uniques.
- Limitez la taille totale décompressée acceptée et le nombre d'entrées avant l'extraction (`zipdetails -t` ou un parseur personnalisé).
- Si vous devez extraire, faites-le dans un cgroup/VM avec des limites CPU et disque (évitez les plantages dus à une inflation de taille non bornée).

---

### Confusion entre parseurs d'en-tête local et de répertoire central

Des recherches récentes sur les parseurs différentiels ont montré que l'ambiguïté des ZIP est encore exploitable dans les chaînes d'outils modernes. L'idée principale est simple : certains logiciels font confiance à l'**en-tête de fichier local (LFH)** tandis que d'autres font confiance au **répertoire central (CD)**, de sorte qu'une même archive peut présenter des noms de fichiers, chemins, commentaires, offsets ou jeux d'entrées différents selon les outils.

Utilisations offensives pratiques :
- Faites qu'un filtre d'upload, un pré-scan AV, ou un validateur de package voie un fichier bénin dans le CD tandis que l'extracteur respecte un nom/chemin différent dans le LFH.
- Abusez des noms dupliqués, des entrées présentes uniquement dans une des structures, ou des métadonnées de chemin Unicode ambiguës (par exemple Info-ZIP Unicode Path Extra Field `0x7075`) afin que différents parseurs reconstruisent des arbres différents.
- Combinez cela avec path traversal pour transformer une vue inoffensive d'une archive en un write-primitive lors de l'extraction. Pour le côté extraction, voir [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Je n'ai reçu aucun contenu à compléter. Fournis le texte anglais (ou le passage du fichier src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md) que tu veux que je traduise et complète, ou précise exactement quelles informations supplémentaires ajouter.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Rejeter ou isoler les archives avec des noms LFH/CD non concordants, des noms de fichiers dupliqués, plusieurs enregistrements EOCD, ou des octets traînantes après l'EOCD final.
- Considérer les ZIPs utilisant des Unicode-path extra fields inhabituels ou des commentaires incohérents comme suspects si différents outils ne s'accordent pas sur l'arborescence extraite.
- Si l'analyse prime sur la préservation des octets originaux, reconditionner l'archive avec un parseur strict après extraction dans un sandbox et comparer la liste de fichiers résultante aux métadonnées originales.

This matters beyond package ecosystems: the same ambiguity class can hide payloads from mail gateways, static scanners, and custom ingestion pipelines that "peek" at ZIP contents before a different extractor handles the archive.

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
