# Esteganografía de audio

{{#include ../../banners/hacktricks-training.md}}

Patrones comunes:

- Mensajes en espectrogramas
- Embedding LSB en WAV
- Codificación DTMF / tonos de marcación
- Payloads en metadatos

## Análisis rápido

Antes de usar herramientas especializadas:

- Confirma los detalles del codec/contenedor y las anomalías:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si el audio contiene contenido similar a ruido o una estructura tonal, inspecciona pronto un espectrograma.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Esteganografía de espectrograma

### Técnica

La técnica spectrogram stego oculta datos dando forma a la energía a lo largo del tiempo y la frecuencia, de modo que solo sean visibles en un gráfico de tiempo-frecuencia (a menudo inaudibles o percibidos como ruido).

### Sonic Visualiser

Herramienta principal para inspeccionar espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (vista de espectrograma, filtros): https://www.audacityteam.org/
- `sox` puede generar espectrogramas desde la CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodificación FSK / modem

El audio con **Frequency-shift keying** suele verse como tonos individuales alternos en un espectrograma.<sup>[[1]](#references)</sup> Una vez que tengas una estimación aproximada del centro, el desplazamiento y la velocidad en baudios, haz brute force con `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` ajusta automáticamente la ganancia y detecta automáticamente los tonos mark/space; ajusta `--rx-invert` o `--samplerate` si la salida está distorsionada.

## WAV LSB

### Technique

Para PCM sin comprimir (WAV), cada sample es un entero. Modificar los bits bajos cambia la forma de onda muy ligeramente, por lo que los atacantes pueden ocultar:

- 1 bit por sample (o más)
- Intercalados entre canales
- Con un stride/permutation

Otras familias de ocultación de audio que puedes encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (dependientes del formato y de la herramienta)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonos de marcado

### Técnica

DTMF codifica caracteres como pares de frecuencias fijas (teclado telefónico). Si el audio se parece a tonos de teclado o pitidos regulares de doble frecuencia, prueba primero la decodificación DTMF.

Decodificadores online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referencias

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
