# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

일반적인 패턴:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## 빠른 초기 평가

전문 도구 사용 전:

- codec/container 세부사항 및 이상 확인:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 오디오에 잡음 같은 내용이나 톤 구조가 포함되어 있으면, 초기에 spectrogram을 확인하세요.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### 기법

Spectrogram stego는 시간/주파수 영역에 걸쳐 에너지를 조작하여 데이터를 숨기므로, 시간-주파수 플롯에서만 보이고 종종 들리지 않거나 노이즈로 인식됩니다.

### Sonic Visualiser

스펙트로그램 검사를 위한 주요 도구:

- https://www.sonicvisualiser.org/

### 대체 도구

- Audacity (스펙트로그램 보기, 필터): https://www.audacityteam.org/
- `sox`는 CLI에서 스펙트로그램을 생성할 수 있습니다:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### 기법

무압축 PCM (WAV)에서는 각 샘플이 정수입니다. 하위 비트를 변경하면 파형이 아주 약간만 바뀌므로, 공격자는 다음과 같이 숨길 수 있습니다:

- 샘플당 1비트(또는 그 이상)
- 채널 간 인터리브
- 스트라이드/순열을 사용

접할 수 있는 다른 오디오 은닉 기법들:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

출처: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / dial tones

### 기법

DTMF는 문자를 고정된 두 주파수 쌍으로 인코딩합니다 (telephone keypad). 오디오가 키패드 음이나 규칙적인 이중 주파수 비프음과 유사하면, DTMF 디코딩을 조기에 테스트하세요.

온라인 디코더:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
