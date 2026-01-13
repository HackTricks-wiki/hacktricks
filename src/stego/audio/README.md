# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

일반적인 패턴:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## 빠른 점검

특수 툴을 사용하기 전에:

- 코덱/컨테이너 세부정보 및 이상 여부 확인:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 오디오에 잡음 같은 내용이나 톤 구조가 포함되어 있다면, 초기에 spectrogram을 확인하세요.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego는 시간/주파수에 따라 에너지를 조형하여 데이터를 숨깁니다. 이렇게 하면 시간-주파수 플롯에서만 보이게 되며(종종 들리지 않거나 노이즈로 인식됩니다).

### Sonic Visualiser

스펙트로그램 검사용 주요 도구:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (스펙트로그램 보기, 필터): https://www.audacityteam.org/
- `sox`는 CLI에서 스펙트로그램을 생성할 수 있습니다:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio는 종종 스펙트로그램에서 번갈아 나타나는 단일 톤처럼 보입니다. 대략적인 center/shift 및 baud 추정치를 얻었으면, `minimodem`으로 brute force 하세요:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem`은 mark/space tones에 대해 자동 게인 및 자동 감지를 수행합니다; 출력이 깨지면 `--rx-invert` 또는 `--samplerate`를 조정하세요.

## WAV LSB

### 기법

무압축 PCM (WAV)의 경우, 각 샘플은 정수입니다. 하위 비트를 수정하면 파형이 아주 약간 변하므로 공격자는 다음을 숨길 수 있습니다:

- 샘플당 1비트(또는 그 이상)
- 채널에 인터리브됨
- 스트라이드/순열 사용

만날 수 있는 다른 오디오 은닉 방식:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (포맷 의존적 및 도구 의존적)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / 다이얼 톤

### 기법

DTMF는 문자를 고정된 두 주파수 쌍으로 인코딩합니다(telephone keypad). 오디오가 키패드 톤이나 규칙적인 이중 주파수 비프음과 유사하다면, DTMF 디코딩을 조기에 테스트하세요.

온라인 디코더:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## 참고자료

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
