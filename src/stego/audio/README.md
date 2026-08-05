# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

일반적인 패턴:

- Spectrogram 메시지
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## 빠른 triage

전문 도구를 사용하기 전에:

- codec/container 세부 정보와 이상 징후를 확인:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 오디오에 noise와 유사한 콘텐츠 또는 tonal structure가 포함되어 있다면, 먼저 spectrogram을 확인합니다.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego는 시간/주파수에 따른 energy를 조정하여 data를 숨깁니다. 따라서 time-frequency plot에서만 보이며, 종종 들리지 않거나 noise로 인식됩니다.

### Sonic Visualiser

Spectrogram inspection을 위한 주요 tool:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (spectrogram view, filters): https://www.audacityteam.org/
- `sox`는 CLI에서 spectrogram을 생성할 수 있습니다:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem 디코딩

Frequency-shift keyed 오디오는 spectrogram에서 교대로 나타나는 단일 톤처럼 보이는 경우가 많습니다.<sup>[[1]](#references)</sup> 대략적인 center/shift와 baud를 파악했다면 `minimodem`으로 brute force하세요:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem`은 mark/space 톤의 gain을 자동 조정하고 자동 감지합니다. 출력이 깨져 보이면 `--rx-invert` 또는 `--samplerate`를 조정하세요.

## WAV LSB

### 기법

압축되지 않은 PCM(WAV)에서는 각 sample이 정수입니다. 하위 bit를 수정해도 waveform이 매우 미세하게만 변경되므로, 공격자는 다음과 같이 숨길 수 있습니다.

- sample당 1 bit(또는 그 이상)
- channel 간 interleaving
- stride/permutation 사용

접할 수 있는 기타 audio-hiding 계열:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels(format 및 tool에 따라 다름)

### WavSteg

출처: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / 다이얼 톤

### 기법

DTMF는 고정 주파수 쌍으로 문자(전화 키패드)를 인코딩합니다. 오디오가 키패드 톤이나 규칙적인 이중 주파수 비프음과 유사하다면, 초기에 DTMF 디코딩을 시도하세요.

온라인 디코더:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## 참고 자료

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
