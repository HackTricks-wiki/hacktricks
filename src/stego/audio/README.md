# Esteganografia de Áudio

{{#include ../../banners/hacktricks-training.md}}

Padrões comuns:

- Mensagens em espectrograma
- Embedding LSB em WAV
- Codificação de DTMF / tons de discagem
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
## Esteganografia em espectrograma

### Técnica

A esteganografia em espectrograma oculta dados moldando a energia ao longo do tempo/frequência, fazendo com que se tornem visíveis apenas em um gráfico tempo-frequência (frequentemente inaudíveis ou percebidos como ruído).

### Sonic Visualiser

Ferramenta principal para inspeção de espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (visualização de espectrograma, filtros): https://www.audacityteam.org/
- `sox` pode gerar espectrogramas pela CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodificação de FSK / modem

Áudios com frequency-shift keying geralmente parecem tons únicos alternados em um espectrograma. Depois de obter uma estimativa aproximada da frequência central/desvio e da baud rate, faça brute force com `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` ajusta automaticamente o ganho e detecta automaticamente os tons mark/space; ajuste `--rx-invert` ou `--samplerate` se a saída estiver distorcida.

## WAV LSB

### Técnica

Para PCM não compactado (WAV), cada sample é um número inteiro. Modificar os bits menos significativos altera a forma de onda muito pouco, portanto, attackers podem ocultar:

- 1 bit por sample (ou mais)
- Intercalados entre canais
- Com um stride/permutation

Outras famílias de ocultação de áudio que você pode encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (dependentes do formato e da ferramenta)

### WavSteg

De: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tons de discagem

### Técnica

O DTMF codifica caracteres como pares de frequências fixas (teclado telefônico). Se o áudio se assemelhar a tons de teclado ou bipes regulares de frequência dupla, teste a decodificação DTMF logo no início.

Decodificadores online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referências

- [1] [Flagvent 2025 (Medium) — pink, Lista de Desejos do Papai Noel, Metadados de Natal, Ruído Capturado](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
