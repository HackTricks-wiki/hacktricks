# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Patrones comunes:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triaje rápido

Antes de herramientas especializadas:

- Confirma detalles del codec/container y anomalías:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si el audio contiene contenido con aspecto de ruido o estructura tonal, inspecciona un spectrogram lo antes posible.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Técnica

Spectrogram stego oculta datos modelando la energía en tiempo/frecuencia para que sean visibles solo en una representación tiempo-frecuencia (a menudo inaudible o percibida como ruido).

### Sonic Visualiser

Herramienta principal para la inspección de espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (vista de espectrograma, filtros): https://www.audacityteam.org/
- `sox` puede generar espectrogramas desde la CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / decodificación de modem

El audio modulado por desplazamiento de frecuencia suele verse como tonos individuales alternos en un espectrograma. Una vez que tengas una estimación aproximada del centro/desplazamiento y del baud, brute force con `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` ajusta la ganancia automáticamente y detecta automáticamente los tonos mark/space; ajuste `--rx-invert` o `--samplerate` si la salida está distorsionada.

## WAV LSB

### Técnica

Para PCM sin comprimir (WAV), cada muestra es un entero. Modificar los bits menos significativos cambia la forma de onda muy poco, por lo que los atacantes pueden ocultar:

- 1 bit por muestra (o más)
- Intercalado entre canales
- Con un stride/permutación

Otras familias de ocultación de audio que puede encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Fuente: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Técnica

DTMF codifica caracteres como pares de frecuencias fijas (teclado telefónico). Si el audio se asemeja a tonos de teclado o a pitidos regulares de doble frecuencia, prueba la decodificación DTMF lo antes posible.

Decodificadores en línea:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referencias

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
