# 오디오 스테가노그래피

{{#include ../../banners/hacktricks-training.md}}

일반적인 패턴:

- Spectrogram 메시지
- WAV LSB 임베딩
- DTMF / 다이얼 톤 인코딩
- Metadata payload

## 빠른 초기 점검

전문 도구를 사용하기 전에:

- codec/container 세부 정보와 이상 징후를 확인합니다:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 오디오에 noise와 유사한 콘텐츠나 tonal structure가 포함되어 있다면, 초기에 spectrogram을 확인합니다.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego는 시간/주파수에 따른 에너지를 조절하여 데이터를 숨기므로, 시간-주파수 플롯에서 데이터가 보이게 되며 오디오는 tone이나 noise처럼 들릴 수 있습니다.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Spectrogram inspection을 위한 주요 도구:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (spectrogram view 및 filters).<sup>[[6]](#references)</sup>
- `sox`는 CLI에서 spectrogram을 생성할 수 있습니다:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed 오디오는 종종 spectrogram에서 교대로 나타나는 단일 톤처럼 보입니다. 대략적인 center/shift와 baud를 추정했다면 `minimodem`으로 brute force하세요:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem`은 Bell 및 기타 FSK modes와 custom mark/space frequencies를 지원합니다. 모든 recording이 autodetect될 수 있다고 가정하지 말고 해당 options를 확인하세요. 출력이 깨져 보이면 `--rx-invert`, 명시적인 baud mode 또는 `--samplerate <Hz>`를 시도하세요.<sup>[[4]](#references)</sup>

## WAV LSB

### Technique

압축되지 않은 PCM (WAV)의 각 sample은 정수입니다. low bits를 수정하면 waveform이 매우 미세하게 변경되므로, attackers는 다음과 같은 방식으로 숨길 수 있습니다:

- sample당 1 bit (또는 그 이상)
- channels 간 interleaved
- stride/permutation 사용

접하게 될 수 있는 기타 audio-hiding families:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format 및 tool에 따라 다름)

### WavSteg

다음 commands는 `ragibson/Steganography` toolkit의 WavSteg를 사용합니다.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- DeepSound의 공식 repository 및 releases.<sup>[[7]](#references)</sup>

## DTMF / 다이얼 톤

### Technique

DTMF는 낮은 주파수 그룹에서 하나, 높은 주파수 그룹에서 하나를 사용하여 각 키패드 신호를 표현합니다. 오디오가 키패드 톤이나 규칙적인 이중 주파수 비프음처럼 들리면 초기에 DTMF decoding을 테스트하세요.<sup>[[5]](#references)</sup>

온라인 decoder:

- `dtmf-detect` browser tool.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, offline audio-file decoder.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa의 Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — command-line FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — push-button telephone sets의 technical features](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — 공식 repository 및 releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
