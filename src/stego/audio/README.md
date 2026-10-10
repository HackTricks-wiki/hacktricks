# Stéganographie audio

{{#include ../../banners/hacktricks-training.md}}

Motifs courants :

- Messages dans le spectrogramme
- Dissimulation LSB dans un fichier WAV
- Encodage DTMF / tonalités de numérotation
- Charges utiles dans les métadonnées

## Triage rapide

Avant d’utiliser des outils spécialisés :

- Vérifiez les détails du codec/conteneur et les anomalies :
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Si l’audio contient du bruit ou une structure tonale, examinez rapidement un spectrogramme.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Stéganographie par spectrogramme

### Technique

La stéganographie par spectrogramme dissimule des données en façonnant l’énergie dans le temps et les fréquences afin qu’elles deviennent visibles sur un graphique temps-fréquence, tandis que l’audio peut ressembler à des tonalités ou à du bruit.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Outil principal pour examiner les spectrogrammes :

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (vue spectrogramme et filtres).<sup>[[6]](#references)</sup>
- `sox` peut générer des spectrogrammes depuis la CLI :

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## Décodage FSK / modem

Un signal audio à modulation par déplacement de fréquence ressemble souvent à une alternance de tons uniques dans un spectrogramme. Une fois que vous avez estimé approximativement la fréquence centrale, l’écart et le débit en bauds, faites du brute force avec `minimodem` :<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` prend en charge Bell et d’autres modes FSK, ainsi que des fréquences mark/space personnalisées ; consultez ses options au lieu de supposer que tout enregistrement peut être autodétecté. Essayez `--rx-invert`, un mode de débit en bauds explicite ou `--samplerate <Hz>` si la sortie est brouillée.<sup>[[4]](#references)</sup>

## WAV LSB

### Technique

Dans le cas du PCM non compressé (WAV), chaque échantillon est un entier. La modification des bits de poids faible change très légèrement la forme d’onde, ce qui permet aux attaquants de cacher des données :

- 1 bit par échantillon (ou plus)
- Entrelacées entre les canaux
- Avec un pas ou une permutation

Autres familles de dissimulation audio que vous pouvez rencontrer :

- Codage de phase
- Dissimulation par écho
- Incorporation à étalement de spectre
- Canaux auxiliaires côté codec (selon le format et l’outil)

### WavSteg

Les commandes suivantes utilisent WavSteg de la boîte à outils `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Dépôt officiel et versions de DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tonalités de numérotation

### Technique

Le DTMF représente chaque signal du clavier à l’aide d’une fréquence d’un groupe bas et d’une fréquence d’un groupe haut. Si l’audio ressemble à des tonalités de clavier ou à des bips réguliers à deux fréquences, essayez rapidement le décodage DTMF.<sup>[[5]](#references)</sup>

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
