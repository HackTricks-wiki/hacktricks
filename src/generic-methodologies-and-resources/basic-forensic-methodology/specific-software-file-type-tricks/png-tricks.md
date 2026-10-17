# Astuces PNG

{{#include ../../../banners/hacktricks-training.md}}

Les **fichiers PNG** sont très courants dans les **CTF**, la **réponse aux incidents** et le **staging de malware**, car ils sont **sans perte**, **basés sur des chunks** et que de nombreux outils les affichent sans problème, même s’ils contiennent des **métadonnées supplémentaires**, des **payloads ajoutés** ou des **chunks partiellement corrompus**.

Considérez un PNG comme un **conteneur**, pas seulement comme une image.

## Triage rapide

Commencez par vérifier le conteneur avant de passer au stego LSB. Pour le workflow de bit-plane/LSB, consultez [la page dédiée au stego dans les images](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Éléments utiles à rechercher :

- **Chunks auxiliaires inattendus** tels que `tEXt`, `zTXt`, `iTXt`, `eXIf` ou `iCCP`
- **Erreurs CRC** ou longueurs de chunks malformées
- **Données supplémentaires après `IEND`**
- **Plusieurs marqueurs `IEND`** ou fragments `IDAT` récupérables après la fin officielle du fichier
- Un fichier qui est un PNG valide **et** qui ressemble également à un ZIP, un PDF ou un script lorsqu'il est extrait par carving

N'oubliez pas que la structure minimale valide est généralement :

- `IHDR` (doit être en premier)
- `IDAT` (un ou plusieurs chunks consécutifs)
- `IEND` (doit être en dernier)

## Données ajoutées après `IEND`

L'un des artefacts PNG les plus révélateurs est la **présence de données ajoutées après le dernier chunk `IEND`**. De nombreux décodeurs les ignorent, ce qui les rend utiles pour :

- **Le stego simple / les payloads cachés**
- **Les PNG polyglottes**
- **Le staging de malware**
- **La récupération d'anciennes données d'image** provenant d'éditeurs défectueux

Détection rapide :

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Une recherche des octets `IEND` n’est qu’un indice : ces mêmes octets peuvent apparaître dans les données d’un chunk ou dans un trailer falsifié. Pour effectuer un carving fiable, parcourez les chunks préfixés par leur longueur à partir de la signature PNG, puis arrêtez-vous au premier `IEND` structurel ; le [parcours des chunks ci-dessous](#extract-ancillary-chunk-payloads) enregistre également le trailer.<sup>[[6]](#references)</sup>

Essayez aussi des parseurs d’archives génériques directement sur le PNG ou sur le trailer extrait :

```bash
7z l suspect.png
unzip -l suspect.png
```

## Récupération de captures d’écran recadrées/caviardées à la manière d’Acropalypse

Une astuce très pratique et récente en forensic PNG consiste à vérifier si un éditeur de captures d’écran a **écrasé** un PNG sans d’abord **tronquer** l’ancien fichier. Dans ce cas, des octets de l’**image précédente** peuvent subsister après `IEND`, et il est parfois possible de reconstruire partiellement des données `IDAT` supplémentaires.

Cette vulnérabilité est devenue bien connue sous le nom d’**aCropalypse** (Google Pixel Markup) et à la suite du problème connexe de l’**Outil Capture d’écran Windows**.<sup>[[3]](#references)</sup> En pratique, si un PNG « recadré » ou « caviardé » contient encore des données résiduelles, vous pourrez peut-être récupérer une partie de la capture d’écran d’origine.<sup>[[1]](#references)</sup>

Procédure pratique :

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Signes qui justifient fortement une analyse plus approfondie :

- `pngcheck` signale des **données supplémentaires après `IEND`**
- Vous trouvez **plus d’un `IEND`**
- Vous trouvez des **chunks `IDAT` supplémentaires** après la fin apparente de l’image
- La capture d’écran provient d’un appareil/éditeur connu pour avoir été affecté

Si c’est le cas, soumettez le fichier à un **outil de récupération aCropalypse** avant de considérer la censure comme fiable.

## Abus de chunks importants en pratique

Les chunks PNG les plus intéressants pour les enquêtes ne sont généralement pas les chunks d’image évidents, mais ceux qui peuvent contenir du **texte**, des **métadonnées** ou des **octets de payload** :

- `tEXt` / `zTXt` / `iTXt` – métadonnées textuelles et texte compressé
- `eXIf` – données EXIF intégrées au PNG
- `iCCP` – profil ICC intégré
- `PLTE` – données de palette dans les images indexées, mais aussi utiles dans les scénarios de dissimulation de payload.<sup>[[2]](#references)</sup>

Extrayez-les avec :

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Pour la persistance de payloads offensifs dans des chunks PNG (par exemple les astuces **PLTE**, **IDAT** ou **tEXt** qui résistent à certaines transformations d’images en PHP), consultez les notes plus détaillées sur l’upload ici :<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Extraire les payloads des chunks auxiliaires

Un attaquant peut placer des octets arbitraires dans un **chunk auxiliaire inconnu avant `IEND`**. Les décodeurs PNG ordinaires peuvent ignorer un chunk auxiliaire inconnu, tandis qu’un script qui récupère l’image sous forme d’octets peut lire et utiliser le payload ; ouvrir le PNG seul ne l’exécute pas.<sup>[[4]](#references)[[6]](#references)</sup> La recherche originale a présenté un chunk personnalisé compressé et chiffré.<sup>[[4]](#references)</sup> Un exemple ultérieur dans un navigateur a utilisé les octets extraits pour fournir du HTML ou un téléchargement.<sup>[[5]](#references)</sup>

Une première lettre minuscule dans le type d’un chunk signifie *auxiliaire* ; une deuxième lettre minuscule signifie *privé*. Par exemple, `paMP` est privé, tandis que `pAMP` utilise l’espace de noms public, même si ce dernier a été inventé pour la démonstration.<sup>[[4]](#references)[[6]](#references)</sup> Un chunk est structuré ainsi : `longueur (4 octets, big-endian) | type (4 octets) | données | CRC (4 octets)` ; le CRC couvre le type et les données. Analysez cette structure plutôt que d’utiliser grep pour rechercher un nom de type dans les données `IDAT` compressées. Le parcours suivant valide les limites et les CRC, exporte les payloads auxiliaires sous forme d’octets bruts et écrit tous les octets situés après le `IEND` structurel dans `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Extraire les chunks auxiliaires et le trailer PNG</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Inspectez les octets extraits avec `file`, `strings` ou `binwalk` ; ne décompressez que si le support est réellement compressé.<sup>[[4]](#references)</sup> Le réencodage peut supprimer le support ; comparez donc les octets envoyés et récupérés avant de vous y fier.<sup>[[2]](#references)[[6]](#references)</sup>

## Réparation de PNG corrompus

Pour vérifier l’intégrité et localiser précisément la zone endommagée, **pngcheck** reste l’un des meilleurs premiers outils à utiliser :

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Si le fichier est endommagé plutôt que malveillant intentionnellement, **PCRT** peut être utile dans les CTF et les travaux en laboratoire pour corriger des problèmes courants tels que des en-têtes incorrects, des valeurs IHDR erronées, des problèmes de CRC ou des dispositions de chunks mal formées.

Si votre objectif est de **nettoyer** un PNG contenant des données suspectes après la fin du fichier tout en préservant l’image visible, ExifTool peut supprimer explicitement ces données :

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Pour les preuves sensibles, travaillez toujours sur une **copie** et conservez les empreintes de l’original avant toute tentative de réparation.



## References

- [1] [Exploiter aCropalypse : récupérer des PNG tronqués](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Charges utiles PHP persistantes dans les PNG : comment injecter du code PHP dans une image et l’y conserver](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Les chunks auxiliaires sont l’endroit idéal pour stocker des informations sensibles](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Utiliser des chunks auxiliaires valides pour dissimuler des données envoyées à un endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Spécification Portable Network Graphics (PNG) (troisième édition)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
