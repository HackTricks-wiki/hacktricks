# 오디오 스테가노그래피

{{#include ../../banners/hacktricks-training.md}}

일반적인 패턴:

- 스펙트로그램 메시지
- WAV LSB 임베딩
- DTMF / 다이얼 톤 인코딩
- 메타데이터 페이로드

## 빠른 초기 분석

전문 도구를 사용하기 전에:

- 코덱/컨테이너 세부 정보와 이상 징후를 확인합니다:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- 오디오에 노이즈와 유사한 콘텐츠나 음조 구조가 포함되어 있다면, 초기에 스펙트로그램을 확인합니다.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## 스펙트로그램 스테가노그래피

### 기법

스펙트로그램 스테고는 시간/주파수에 따른 에너지를 조정해 시간-주파수 플롯에서 데이터가 보이도록 숨깁니다. 오디오는 톤이나 노이즈처럼 들릴 수 있습니다.<sup>[[3]](#references)</sup>

### Sonic Visualiser

스펙트로그램 검사에 주로 사용하는 도구:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### 대안

- Audacity (스펙트로그램 보기 및 필터).<sup>[[6]](#references)</sup>
- `sox`는 CLI에서 스펙트로그램을 생성할 수 있습니다:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / 모뎀 디코딩

주파수 편이 방식(FSK) 오디오는 스펙트로그램에서 번갈아 나타나는 단일 톤처럼 보이는 경우가 많습니다. 대략적인 중심 주파수와 편이 폭, baud rate를 추정했다면 `minimodem`으로 무차별 대입해 보세요:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem`은 Bell 및 기타 FSK 모드와 사용자 지정 mark/space 주파수를 지원합니다. 모든 녹음이 자동으로 감지된다고 가정하지 말고 옵션을 확인하세요. 출력이 깨져 있으면 `--rx-invert`, 명시적인 baud 모드 또는 `--samplerate <Hz>`를 사용해 보세요.<sup>[[4]](#references)</sup>

## WAV LSB

### 기법

비압축 PCM(WAV)에서는 각 샘플이 정수입니다. 하위 비트를 수정하면 파형이 아주 조금만 변하므로 공격자는 다음과 같은 방식으로 데이터를 숨길 수 있습니다.

- 샘플당 1비트(또는 그 이상)
- 채널 간 인터리빙
- stride/permutation 적용

접할 수 있는 다른 오디오 은닉 기법군:

- 위상 코딩
- 에코 은닉
- 확산 스펙트럼 임베딩
- 코덱 측 사이드 채널(형식과 도구에 따라 다름)

### WavSteg

다음 명령은 `ragibson/Steganography` 툴킷의 WavSteg를 사용합니다.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- DeepSound의 공식 저장소 및 릴리스.<sup>[[7]](#references)</sup>

## DTMF / 다이얼 톤

### 기법

DTMF는 저주파 그룹의 주파수 하나와 고주파 그룹의 주파수 하나를 사용해 각 키패드 신호를 나타냅니다. 오디오가 키패드 톤이나 규칙적인 이중 주파수 삐 소리처럼 들리면 먼저 DTMF 디코딩을 시도하세요.<sup>[[5]](#references)</sup>

온라인 디코더:

- `dtmf-detect` 브라우저 도구.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, 오프라인 오디오 파일 디코더.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa의 위시리스트, 크리스마스 메타데이터, 캡처된 노이즈](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — 문서](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — 명령줄 FSK 모뎀](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — 푸시 버튼 전화기의 기술적 특성](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — 공식 저장소 및 릴리스](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
