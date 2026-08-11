# Astuces PNG

{{#include ../../../banners/hacktricks-training.md}}

Les **fichiers PNG** sont très courants dans les **CTFs**, la **réponse aux incidents** et le **malware staging**, car ils sont **sans perte**, **fondés sur des chunks**, et de nombreux outils les afficheront volontiers même lorsqu’ils contiennent des **métadonnées supplémentaires**, des **payloads ajoutés à la fin**, ou des **chunks partiellement corrompus**.

Traitez un PNG comme un **conteneur**, et pas seulement comme une image.

## Triage rapide

Commencez par effectuer des vérifications au niveau du conteneur avant de passer au LSB stego. Pour le workflow bit-plane/LSB, consultez [la page dédiée au stego d’images](../../../stego/images/README.md).
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
- Un fichier qui est un PNG valide **et** qui ressemble également à un ZIP/PDF/script lorsqu’il est extrait

N’oubliez pas que la structure minimale valide est généralement :

- `IHDR` (doit être le premier)
- `IDAT` (un ou plusieurs chunks consécutifs)
- `IEND` (doit être le dernier)

## Trailing data after `IEND`

L’un des artefacts PNG les plus révélateurs est constitué de **données ajoutées après le dernier chunk `IEND`**. De nombreux décodeurs les ignorent, ce qui les rend utiles pour :

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Récupérer d’anciennes données d’image** provenant d’éditeurs défectueux

Détection rapide :
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Si vous voulez extraire tout ce qui suit le dernier `IEND` :
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Essayez également les parseurs d’archives génériques directement sur le PNG ou sur la section finale extraite :
```bash
7z l suspect.png
unzip -l suspect.png
```
## Récupération de captures d’écran recadrées/caviardées de type Acropalypse

Une astuce forensic PNG très pratique et récente consiste à vérifier si un éditeur de captures d’écran a **écrasé** un fichier PNG sans d’abord **tronquer** l’ancien fichier. Dans ces cas, des octets de l’**ancienne image** peuvent rester après `IEND`, et il est parfois possible de reconstruire partiellement des données `IDAT` supplémentaires.

Ce problème est devenu bien connu avec **aCropalypse** (Google Pixel Markup) et le problème associé de l’outil **Windows Snipping Tool**.<sup>[[3]](#references)</sup> En pratique, si un PNG « recadré » ou « caviardé » contient encore d’anciennes données à la fin du fichier, vous pourrez peut-être récupérer une partie de la capture d’écran originale.<sup>[[1]](#references)</sup>

Workflow pratique :
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Signes justifiant fortement une analyse plus approfondie :

- `pngcheck` signale des **données supplémentaires après `IEND`**
- Vous trouvez **plus d’un `IEND`**
- Vous trouvez des **chunks `IDAT` supplémentaires** après la fin apparente de l’image
- La capture d’écran provient d’un appareil/éditeur connu pour avoir été affecté

Si c’est le cas, soumettez le fichier à un **outil de récupération aCropalypse** avant de considérer la censure comme fiable.

## Abus des chunks importants en pratique

Les chunks PNG les plus intéressants pour les investigations ne sont généralement pas ceux liés directement à l’image, mais ceux qui peuvent transporter du **texte**, des **métadonnées** ou des **octets de payload** :

- `tEXt` / `zTXt` / `iTXt` – métadonnées textuelles et texte compressé
- `eXIf` – données EXIF dans un PNG
- `iCCP` – profil ICC intégré
- `PLTE` – données de palette dans les images indexées, mais également utiles dans les scénarios de dissimulation de payload.<sup>[[2]](#references)</sup>

Extrayez-les avec :
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Pour la persistance de payloads offensifs à l’intérieur de chunks PNG (par exemple les tricks **PLTE**, **IDAT** ou **tEXt** qui survivent à certaines transformations d’images PHP), consultez les notes plus détaillées axées sur les uploads ici :<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Pour vérifier l’intégrité et localiser précisément la zone endommagée, **pngcheck** reste l’un des meilleurs outils à utiliser en premier :

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Si le fichier est endommagé plutôt que volontairement malveillant, **PCRT** peut être utile dans les CTF et les environnements de lab pour corriger des problèmes courants tels que des headers incorrects, des valeurs IHDR erronées, des problèmes de CRC ou des layouts de chunks malformés.

Si votre objectif est d’**assainir** un PNG contenant des données suspectes dans le trailer tout en préservant l’image visible, ExifTool peut supprimer explicitement le trailer :
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Pour les preuves sensibles, travaillez toujours sur une **copie** et conservez les hash de l’original avant de tenter des réparations.

## References

- [1] [Exploiter aCropalypse : récupérer des PNG tronqués](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payloads PHP persistants dans des PNG : comment injecter du code PHP dans une image et l’y conserver](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
