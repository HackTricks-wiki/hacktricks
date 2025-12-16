# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

일반적인 패턴:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## 빠른 트리아지

전문 도구 사용 전에:

- 코덱/컨테이너 세부정보와 이상 징후 확인:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 오디오에 노이즈와 유사한 내용이나 톤 구조가 포함되어 있으면, 초기에 spectrogram을 검사하세요.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego는 시간/주파수에 걸쳐 에너지를 조형하여 데이터를 숨겨, 시간-주파수 플롯에서만 보이게 만든다(종종 들리지 않거나 잡음으로 인식된다).

### Sonic Visualiser

스펙트로그램 검사를 위한 주요 도구:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (스펙트로그램 보기, 필터): https://www.audacityteam.org/
- `sox` CLI에서 스펙트로그램을 생성할 수 있음:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### 기법

무압축 PCM (WAV)의 경우, 각 샘플은 정수입니다. 하위 비트를 수정하면 파형이 아주 약간만 변경되므로, 공격자는 다음을 은닉할 수 있습니다:

- 샘플당 1비트(또는 그 이상)
- 채널 간 인터리브
- 스트라이드/치환 방식

다음과 같은 기타 오디오 은닉 기법을 만날 수 있습니다:

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

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / 다이얼 톤

### 기법

DTMF는 문자를 고정된 주파수 쌍(telephone keypad)으로 인코딩합니다. 오디오가 키패드 톤이나 규칙적인 이중 주파수 비프음과 유사하다면, DTMF 디코딩을 조기에 테스트하세요.

온라인 디코더:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
