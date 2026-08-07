# Esteganografía de audio

{{#include ../../banners/hacktricks-training.md}}

Patrones comunes:

- Mensajes en espectrogramas
- Embedding LSB en WAV
- Codificación DTMF / tonos de marcado
- Payloads en metadatos

## Triage rápido

Antes de usar herramientas especializadas:

- Confirma los detalles del códec/contenedor y las anomalías:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si el audio contiene contenido similar a ruido o una estructura tonal, inspecciona un espectrograma desde el principio.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Esteganografía en espectrogramas

### Técnica

El stego de espectrogramas oculta datos moldeando la energía a lo largo del tiempo y la frecuencia, de modo que solo se vuelve visible en un gráfico tiempo-frecuencia (a menudo es inaudible o se percibe como ruido).

### Sonic Visualiser

Herramienta principal para la inspección de espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (vista de espectrograma, filtros): https://www.audacityteam.org/
- `sox` puede generar espectrogramas desde la CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodificación de FSK / módem

El audio con modulación por desplazamiento de frecuencia suele verse como tonos individuales alternos en un espectrograma. Cuando tengas una estimación aproximada del centro, el desplazamiento y la velocidad en baudios, prueba por fuerza bruta con `minimodem`:<sup>[[1]](#references)</sup>
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

### Técnica

Para PCM sin comprimir (WAV), cada muestra es un entero. Modificar los bits de menor peso cambia la forma de onda muy ligeramente, por lo que los atacantes pueden ocultar:

- 1 bit por muestra (o más)
- Intercalados entre canales
- Con un stride/permutación

Otras familias de ocultación de audio que puedes encontrar:

- Codificación de fase
- Ocultación mediante eco
- Embedding de espectro ensanchado
- Canales del lado del codec (dependientes del formato y de la herramienta)

### WavSteg

De: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonos de marcación

### Técnica

DTMF codifica caracteres como pares de frecuencias fijas (teclado telefónico). Si el audio se parece a tonos de teclado o pitidos regulares de doble frecuencia, prueba la decodificación DTMF al principio.

Decodificadores online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referencias

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
