# Esteganografia de Áudio

{{#include ../../banners/hacktricks-training.md}}

Padrões comuns:

- Mensagens em espectrogramas
- Incorporação de LSB em WAV
- Codificação por DTMF / tons de discagem
- Payloads de metadados

## Triagem rápida

Antes de usar ferramentas especializadas:

- Confirme os detalhes do codec/container e as anomalias:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se o áudio contiver conteúdo semelhante a ruído ou estrutura tonal, inspecione um espectrograma logo no início.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Esteganografia de espectrograma

### Técnica

O stego de espectrograma oculta dados moldando a energia ao longo do tempo/frequência para que ela se torne visível em um gráfico de tempo-frequência, enquanto o áudio pode soar como tons ou ruído.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Ferramenta principal para inspeção de espectrogramas:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternativas

- Audacity (visualização de espectrograma e filtros).<sup>[[6]](#references)</sup>
- `sox` pode gerar espectrogramas a partir da CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodificação de FSK / modem

O áudio com Frequency-shift keying geralmente se parece com tons únicos alternados em um espectrograma. Quando você tiver uma estimativa aproximada do centro/deslocamento e do baud, faça brute force com `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` oferece suporte aos modos Bell e outros modos FSK, além de frequências customizadas de mark/space; consulte suas opções em vez de presumir que toda gravação possa ser autodetectada. Tente `--rx-invert`, um modo de baud explícito ou `--samplerate <Hz>` quando a saída estiver ilegível.<sup>[[4]](#references)</sup>

## WAV LSB

### Técnica

Para PCM não compactado (WAV), cada amostra é um número inteiro. Modificar os bits menos significativos altera a forma de onda muito ligeiramente, portanto, os atacantes podem ocultar:

- 1 bit por amostra (ou mais)
- Intercalados entre os canais
- Com um stride/permutação

Outras famílias de ocultação em áudio que você pode encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Canais no codec (dependentes do formato e da ferramenta)

### WavSteg

Os comandos a seguir usam o WavSteg do toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Repositório oficial e releases do DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tons de discagem

### Técnica

O DTMF representa cada sinal do teclado usando uma frequência de um grupo baixo e uma de um grupo alto. Se o áudio se assemelhar a tons de teclado ou bipes regulares de frequência dupla, teste a decodificação DTMF logo no início.<sup>[[5]](#references)</sup>

Decoders online:

- Ferramenta de navegador `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, um decoder offline de arquivos de áudio.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — rosa, Lista de desejos do Santa, Metadados de Natal, Ruído capturado](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentação](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK de linha de comando](https://github.com/kamalmostafa/minimodem)
- [5] [Recomendação ITU-T Q.23 — características técnicas de aparelhos telefônicos com botões](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — repositório oficial e releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
