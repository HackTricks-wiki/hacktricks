# Esteganografía de audio

{{#include ../../banners/hacktricks-training.md}}

Patrones comunes:

- Mensajes en espectrogramas
- Embedding de LSB en WAV
- Codificación DTMF / tonos de marcado
- Payloads en metadatos

## Triaje rápido

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

El stego de espectrograma oculta datos moldeando la energía a lo largo del tiempo y la frecuencia para que se vuelva visible en un gráfico tiempo-frecuencia, mientras que el audio puede sonar como tonos o ruido.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Herramienta principal para inspeccionar espectrogramas:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternativas

- Audacity (vista de espectrograma y filtros).<sup>[[6]](#references)</sup>
- `sox` puede generar espectrogramas desde la CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodificación de FSK / modem

El audio con frequency-shift keying suele verse como tonos individuales alternos en un espectrograma. Una vez que tengas una estimación aproximada del centro/desplazamiento y de la velocidad en baudios, usa fuerza bruta con `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` admite modos Bell y otros modos FSK, además de frecuencias mark/space personalizadas; consulta sus opciones en lugar de asumir que cada grabación puede autodetectarse. Prueba `--rx-invert`, un modo de baud explícito o `--samplerate <Hz>` cuando la salida esté distorsionada.<sup>[[4]](#references)</sup>

## WAV LSB

### Técnica

Para PCM sin comprimir (WAV), cada sample es un entero. Modificar los bits bajos cambia la forma de onda muy ligeramente, por lo que los atacantes pueden ocultar:

- 1 bit por sample (o más)
- Intercalado entre canales
- Con un stride/permutación

Otras familias de ocultación de audio que puedes encontrar:

- Codificación de fase
- Ocultación mediante eco
- Embedding de espectro ensanchado
- Canales del lado del codec (dependientes del formato y de la herramienta)

### WavSteg

Los siguientes comandos usan WavSteg del toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Repositorio oficial y releases de DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tonos de marcado

### Técnica

DTMF representa cada señal del teclado usando una frecuencia de un grupo bajo y otra de un grupo alto. Si el audio se parece a tonos de teclado o a pitidos regulares de doble frecuencia, prueba la decodificación DTMF desde el principio.<sup>[[5]](#references)</sup>

Decodificadores online:

- Herramienta de navegador `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, un decodificador de archivos de audio offline.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Wishlist de Santa, Metadatos navideños, Ruido capturado](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentación](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — módem FSK de línea de comandos](https://github.com/kamalmostafa/minimodem)
- [5] [Recomendación Q.23 de la ITU-T — características técnicas de los teléfonos de botones](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — repositorio oficial y releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
