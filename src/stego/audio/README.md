# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

일반적인 패턴:

- Spectrogram 메시지
- WAV LSB 임베딩
- DTMF / 다이얼 톤 인코딩
- Metadata payload

## 빠른 초기 분석

전용 tooling을 사용하기 전에:

- codec/container 세부 정보와 이상 징후를 확인합니다:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 오디오에 noise와 유사한 콘텐츠 또는 tonal structure가 포함되어 있다면, 가능한 한 빨리 spectrogram을 확인합니다.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego는 시간/주파수에 따른 에너지를 조정하여 데이터를 숨깁니다. 따라서 시간-주파수 플롯에서만 데이터가 보이며, 일반적으로 들리지 않거나 noise로 인식됩니다.

### Sonic Visualiser

스펙트로그램 검사를 위한 주요 도구:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (스펙트로그램 보기, filters): https://www.audacityteam.org/
- `sox`는 CLI에서 스펙트로그램을 생성할 수 있습니다:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem 디코딩

Frequency-shift keyed audio는 spectrogram에서 번갈아 나타나는 단일 톤처럼 보이는 경우가 많습니다. 대략적인 center/shift와 baud 추정값을 얻었다면 `minimodem`으로 brute force하세요:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem`은 mark/space tones를 자동으로 gain 조정하고 감지합니다. 출력이 깨져 보이면 `--rx-invert` 또는 `--samplerate`를 조정하세요.

## WAV LSB

### Technique

압축되지 않은 PCM (WAV)에서는 각 sample이 정수입니다. 낮은 비트를 수정하면 waveform이 아주 미세하게 변경되므로, 공격자는 다음과 같은 방식으로 숨길 수 있습니다:

- sample당 1비트 (또는 그 이상)
- 채널 간 interleave
- stride/permutation 사용

접할 수 있는 기타 audio-hiding 계열:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format 및 tool에 따라 다름)

### WavSteg

출처: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### 기법

DTMF는 고정된 주파수 쌍(전화 키패드)을 사용해 문자를 인코딩합니다. 오디오가 키패드 톤이나 규칙적인 이중 주파수 비프음처럼 들리면 먼저 DTMF 디코딩을 테스트합니다.

온라인 디코더:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## 참고 자료

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
