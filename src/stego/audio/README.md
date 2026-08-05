# Esteganografia de Áudio

{{#include ../../banners/hacktricks-training.md}}

Padrões comuns:

- Mensagens em espectrograma
- Incorporação de LSB em WAV
- Codificação DTMF / tons de discagem
- Payloads de metadados

## Triagem rápida

Antes de usar ferramentas especializadas:

- Confirme os detalhes do codec/container e as anomalias:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se o áudio contiver conteúdo semelhante a ruído ou uma estrutura tonal, inspecione um espectrograma logo no início.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Esteganografia de espectrograma

### Técnica

A esteganografia em espectrograma oculta dados moldando a energia ao longo do tempo/frequência, de modo que eles se tornam visíveis apenas em um gráfico de tempo-frequência (geralmente inaudíveis ou percebidos como ruído).

### Sonic Visualiser

Ferramenta principal para inspeção de espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (visualização de espectrograma, filtros): https://www.audacityteam.org/
- `sox` pode gerar espectrogramas a partir da CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodificação de FSK / modem

Áudio com frequency-shift keying geralmente se parece com tons únicos alternados em um espectrograma.<sup>[[1]](#references)</sup> Depois de obter uma estimativa aproximada da frequência central/desvio e do baud, use força bruta com `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` ajusta automaticamente o ganho e detecta automaticamente tons mark/space; ajuste `--rx-invert` ou `--samplerate` se a saída estiver ilegível.

## WAV LSB

### Technique

Para PCM não compactado (WAV), cada sample é um inteiro. Modificar bits baixos altera a forma de onda muito ligeiramente, portanto os atacantes podem ocultar:

- 1 bit por sample (ou mais)
- Intercalados entre canais
- Com um stride/permutação

Outras famílias de ocultação de áudio que você pode encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (dependente do formato e da ferramenta)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tons de discagem

### Técnica

DTMF codifica caracteres como pares de frequências fixas (teclado telefônico). Se o áudio se assemelhar a tons de teclado ou bipes regulares de frequência dupla, teste a decodificação DTMF no início.

Decoders online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referências

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
