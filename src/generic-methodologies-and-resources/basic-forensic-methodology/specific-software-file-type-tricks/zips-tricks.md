# Astuces sur les ZIP

{{#include ../../../banners/hacktricks-training.md}}

Les **outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et craquer des fichiers zip. Voici quelques utilitaires clés :<sup>[[1]](#references)</sup>

- **`unzip`** : révèle pourquoi un fichier zip ne se décompresse pas.
- **`zipdetails -v`** : fournit une analyse détaillée des champs du format de fichier zip.<sup>[[3]](#references)</sup>
- **`zipinfo`** : liste le contenu d’un fichier zip sans l’extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : tentent de réparer les fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : un outil pour les attaques par dictionnaire et par force brute contre les mots de passe ZIP ; leur faisabilité dépend de l’espace de recherche des mots de passe.<sup>[[15]](#references)</sup>

La [spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des informations complètes sur la structure et les normes des fichiers zip.<sup>[[4]](#references)</sup>

Les fichiers ZIP traditionnels protégés par mot de passe laissent généralement visibles les noms de fichiers et leurs tailles, contrairement aux modes de chiffrement des en-têtes pris en charge par RAR et 7z. Une attaque par texte clair connu contre ZipCrypto récupère les **clés de chiffrement internes**, pas nécessairement le mot de passe d’origine ; ces clés suffisent à déchiffrer les entrées chiffrées avec le même mot de passe.<sup>[[13]](#references)</sup> L’attaque nécessite de connaître des octets du flux **avant chiffrement** : pour un membre stocké, il s’agit des octets du fichier d’origine, mais pour un membre DEFLATE, ce sont les octets compressés, ce qui peut nécessiter de recréer exactement la sortie de la compression.<sup>[[13]](#references)[[14]](#references)</sup> Consultez [Attaque ZIP par texte clair connu](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) pour une procédure pratique. Pour en savoir plus sur la cryptanalyse, consultez [l’article](https://math.ucr.edu/~mike/zipattacks.pdf) et le [tutoriel pas à pas](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Cette attaque contre ZipCrypto ne s’applique pas aux entrées ZIP chiffrées avec AES.<sup>[[13]](#references)</sup>

---

## Techniques anti-reverse engineering dans les APK utilisant des en-têtes ZIP manipulés

Les droppers de malwares Android modernes utilisent des métadonnées ZIP malformées pour perturber les outils d’analyse statique (jadx/apktool/unzip), tout en laissant l’APK installable sur l’appareil. Les techniques les plus courantes sont :<sup>[[2]](#references)</sup>

- Simuler un chiffrement en définissant le bit 0 du General Purpose Bit Flag (GPBF) du ZIP
- Abuser des champs Extra volumineux ou personnalisés pour perturber les parseurs
- Créer des collisions entre noms de fichiers et de répertoires pour dissimuler de vrais artefacts (par exemple, un répertoire nommé `classes.dex/` à côté du véritable `classes.dex`)

### 1) Faux chiffrement (bit 0 du GPBF défini) sans véritable chiffrement

Symptômes :
- `jadx-gui` échoue avec des erreurs telles que :<|fim_suffix|>
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` demande un mot de passe pour les fichiers APK essentiels, même si un APK valide ne peut pas contenir de fichiers `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` chiffrés :
  
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

Examinez le General Purpose Bit Flag des en-têtes local et central. Une valeur révélatrice est le bit 0 activé (chiffrement), même pour les entrées principales :

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristique : Si un APK s’installe et s’exécute sur l’appareil, mais que les entrées principales apparaissent comme « chiffrées » pour les outils, le GPBF a été modifié.

Corrigez le problème en effaçant le bit 0 du GPBF dans les Local File Headers (LFH) et les entrées du Central Directory (CD). Patch minimal au niveau des octets :

<details>
<summary>Patch minimal pour effacer un bit du GPBF</summary>

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

Seul le bit 0 doit changer : par exemple, `0A09` devient `0A08`, et non `0000`. Ce patcher minimal recherche les signatures d’en-tête dans les octets bruts ; des octets ressemblant à une signature dans les données du fichier peuvent donc provoquer de fausses correspondances. Travaillez sur une copie et vérifiez la liste des entrées et les en-têtes obtenus avant d’utiliser le résultat.<sup>[[4]](#references)</sup>

### 2) Champs Extra volumineux/personnalisés pour piéger les parseurs

Les attaquants bourrent les en-têtes de champs Extra surdimensionnés et d’identifiants atypiques pour piéger les décompilateurs. Dans la nature, vous pouvez trouver des marqueurs personnalisés (par exemple, des chaînes comme `JADXBLOCK`) intégrés à ces champs.

Inspection :

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Exemples observés : des ID inconnus comme `0xCAFE` (« Exécutable Java ») ou `0x414A` (« JA: ») transportant des charges utiles volumineuses.<sup>[[2]](#references)</sup>

Heuristiques DFIR :
- Déclencher une alerte lorsque les champs Extra sont exceptionnellement volumineux dans des entrées principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considérer comme suspects les ID Extra inconnus dans ces entrées.

Mesure d’atténuation pratique : reconstruire l’archive (par exemple, en compressant à nouveau les fichiers extraits) supprime les champs Extra malveillants. Si les outils refusent l’extraction en raison d’un chiffrement fictif, effacer d’abord le bit 0 de GPBF comme ci-dessus, puis reconstituer l’archive :

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Collision de noms de fichiers/répertoires (dissimulation de véritables artefacts)

Un ZIP peut contenir à la fois un fichier `X` et un répertoire `X/`. Certains extracteurs et décompilateurs peuvent être perturbés et superposer ou masquer le véritable fichier avec une entrée de répertoire. Ce phénomène a été observé avec des entrées en collision avec des noms APK essentiels comme `classes.dex`.

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

Idées de détection côté blue-team :
- Signaler les APK dont les en-têtes locaux indiquent un chiffrement (bit 0 de GPBF = 1), mais qui s’installent/s’exécutent.
- Signaler les champs Extra volumineux ou inconnus sur les entrées principales (rechercher des marqueurs comme `JADXBLOCK`).
- Signaler les collisions de chemins (`X` et `X/`) spécifiquement pour `AndroidManifest.xml`, `resources.arsc` et `classes*.dex`.

---

## Autres astuces ZIP malveillantes (2024–2026)

### Répertoires centraux concaténés (évasion multi-EOCD)

Lors d’une campagne de phishing en 2024, les attaquants ont envoyé un seul blob qui était en réalité constitué de **deux fichiers ZIP concaténés**. Chacun avait son propre enregistrement End of Central Directory (EOCD) et son propre répertoire central. Différents extracteurs analysaient différents répertoires (7-Zip lisait le premier, tandis que WinRAR lisait le dernier), ce qui permettait aux attaquants de dissimuler des payloads que seuls certains outils affichaient ; les scanners qui n’inspectent qu’un seul répertoire peuvent passer à côté de l’autre archive.<sup>[[5]](#references)[[6]](#references)</sup>

**Commandes de triage**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Si plusieurs EOCD apparaissent ou s’il y a des avertissements « data after payload », scindez le blob et inspectez chaque partie :

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Bombes Quoted-overlap / overlapping-entry (non récursives)

Les ZIP bombs Quoted-overlap construisent un minuscule **kernel** (un bloc DEFLATE hautement compressé) et le réutilisent dans des entrées qui se chevauchent. Les variantes à chevauchement complet font pointer plusieurs entrées du répertoire central vers un seul en-tête local, tandis que les variantes Quoted-overlap citent des en-têtes locaux à l’intérieur des flux DEFLATE ; la construction publiée atteint un ratio supérieur à 28M:1 sans archives imbriquées.<sup>[[7]](#references)</sup>

**Détection rapide (offsets LFH dupliqués)**

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

**Traitement**
- Effectuez un parcours à blanc : `zipdetails -v file.zip | grep -n "Local Header Offset"` et comparez les offsets des en-têtes locaux référencés et les plages de données compressées ; des offsets dupliqués signalent des variantes à chevauchement complet.<sup>[[7]](#references)[[8]](#references)</sup>
- Limitez la taille totale décompressée et le nombre d’entrées acceptés avant l’extraction à l’aide d’un parser ; `zipinfo -t file.zip` indique les totaux, mais n’impose aucune limite de sécurité.<sup>[[8]](#references)</sup>
- Si vous devez extraire les fichiers, faites-le dans un cgroup/VM avec des limites CPU et disque (pour éviter les plantages dus à une décompression sans limite).<sup>[[8]](#references)</sup>

---

### Confusion entre parser d’en-tête local et de répertoire central

Des recherches récentes sur les différences entre parsers ont montré que l’ambiguïté des fichiers ZIP reste exploitable dans les toolchains modernes. L’idée est simple : certains logiciels font confiance au **Local File Header (LFH)**, tandis que d’autres font confiance au **Central Directory (CD)** ; une même archive peut donc présenter des noms de fichiers, chemins, commentaires, offsets ou ensembles d’entrées différents selon l’outil.<sup>[[9]](#references)</sup>

Usages offensifs pratiques :
- Faire en sorte qu’un filtre d’envoi, une préanalyse antivirus ou un validateur de paquets voie un fichier bénin dans le CD, tandis que l’extracteur utilise un nom ou chemin LFH différent.
- Exploiter des noms dupliqués, des entrées présentes dans une seule structure ou des métadonnées de chemin Unicode ambiguës (par exemple, le champ supplémentaire Unicode Path d’Info-ZIP `0x7075`) afin que différents parsers reconstruisent des arborescences différentes.
- Combiner cela avec un path traversal pour transformer la vue « inoffensive » d’une archive en primitive d’écriture lors de l’extraction. Pour la partie extraction, voir [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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

Complétez-le avec :

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Heuristiques :
- Pour une ingestion sensible à la sécurité, rejetez ou isolez les archives dont les noms LFH/CD ne correspondent pas, qui contiennent des noms de fichiers en double, plusieurs enregistrements EOCD ou des octets après le dernier EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Considérez comme suspects les ZIP utilisant des champs supplémentaires de chemin Unicode inhabituels ou des commentaires incohérents si différents outils n’extraient pas la même arborescence.<sup>[[4]](#references)[[9]](#references)</sup>
- Si l’analyse importe davantage que la conservation des octets d’origine, reconditionnez l’archive à l’aide d’un parseur strict après extraction dans un bac à sable, puis comparez la liste des fichiers obtenue aux métadonnées d’origine.

Ce problème dépasse les écosystèmes de paquets : la même catégorie d’ambiguïté peut dissimuler des payloads aux passerelles de messagerie, aux scanners statiques et aux pipelines d’ingestion personnalisés qui « jettent un coup d’œil » au contenu des ZIP avant qu’un autre extracteur ne traite l’archive.<sup>[[9]](#references)</sup>

---





## References

- [1] [Guide de terrain de l’analyse forensique CTF (blog de Mike, catégorie CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Partie 1 – Un dropper à plusieurs étapes (anti-rétro-ingénierie d’APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Spécification du format de fichier ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [La structure flexible des archives ZIP exploitée pour dissimuler des malwares sans être détecté (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Des hackers enfouissent un malware dans une nouvelle attaque par fichier ZIP — répertoires centraux ZIP concaténés](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Une meilleure bombe ZIP (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Comprendre les bombes ZIP : construction de noyau avec chevauchement/chevauchement cité](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mon ZIP n’est pas votre ZIP : identifier et exploiter les écarts sémantiques entre les parseurs ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prévenir les attaques par confusion de parseur ZIP contre les installateurs de paquets Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Attaques ZIP avec texte en clair connu réduit (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site : mission Web réaliste, niveau 15 (attaque ZIP à texte en clair connu)](https://www.hackthissite.org/articles/read/793)
- [13] [Utilisation de bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Tutoriel bkcrack sur le texte en clair connu](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Dépôt fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
