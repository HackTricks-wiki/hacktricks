# Stéganographie audio

{{#include ../../banners/hacktricks-training.md}}

Motifs courants :

- Messages dans le spectrogramme
- Embedding LSB dans des fichiers WAV
- Encodage DTMF / tonalités de numérotation
- Payloads dans les métadonnées

## Triage rapide

Avant d’utiliser des outils spécialisés :

- Vérifier les détails du codec/conteneur et les anomalies :
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si l’audio contient un contenu ressemblant à du bruit ou une structure tonale, examiner rapidement un spectrogramme.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Le spectrogram stego dissimule des données en modelant l’énergie au fil du temps et des fréquences afin qu’elles deviennent visibles dans un graphique temps-fréquence, tandis que l’audio peut ressembler à des tonalités ou à du bruit.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Outil principal pour l’inspection des spectrogrammes :

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (vue en spectrogramme et filtres).<sup>[[6]](#references)</sup>
- `sox` peut générer des spectrogrammes depuis la CLI :
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Décodage FSK / modem

Un audio modulé par déplacement de fréquence ressemble souvent à une alternance de tonalités uniques dans un spectrogramme. Une fois que vous avez une estimation approximative de la fréquence centrale, du décalage et du débit en bauds, effectuez une recherche par force brute avec `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` prend en charge les modes FSK Bell et autres, ainsi que les fréquences mark/space personnalisées ; consultez ses options plutôt que de supposer que chaque enregistrement peut être détecté automatiquement. Essayez `--rx-invert`, un mode baud explicite ou `--samplerate <Hz>` lorsque la sortie est brouillée.<sup>[[4]](#references)</sup>

## WAV LSB

### Technique

Pour le PCM non compressé (WAV), chaque échantillon est un entier. La modification des bits de poids faible change très légèrement la forme d’onde, ce qui permet aux attaquants de dissimuler :

- 1 bit par échantillon (ou davantage)
- Des données entrelacées sur plusieurs canaux
- Avec un pas ou une permutation

Autres familles de dissimulation audio que vous pouvez rencontrer :

- Codage de phase
- Dissimulation par écho
- Insertion à étalement de spectre
- Canaux côté codec (dépendants du format et de l’outil)

### WavSteg

Les commandes suivantes utilisent WavSteg de la boîte à outils `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Le dépôt officiel et les versions de DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tonalités de numérotation

### Technique

DTMF représente chaque signal du clavier à l’aide d’une fréquence d’un groupe de fréquences basses et d’une fréquence d’un groupe de fréquences hautes. Si l’audio ressemble à des tonalités de clavier ou à des bips réguliers à double fréquence, testez tôt le décodage DTMF.<sup>[[5]](#references)</sup>

Décodeurs en ligne :

- Outil de navigateur `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, un décodeur de fichiers audio hors ligne.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, la liste de souhaits du Père Noël, métadonnées de Noël, bruit capturé](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK en ligne de commande](https://github.com/kamalmostafa/minimodem)
- [5] [Recommandation UIT-T Q.23 — caractéristiques techniques des postes téléphoniques à clavier](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — dépôt officiel et versions](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
