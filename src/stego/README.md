# Stego

{{#include ../banners/hacktricks-training.md}}

이 섹션에서는 이미지, 오디오, 비디오, 문서, 아카이브, 텍스트에서 **숨겨진 데이터를 찾고 추출하는 방법**을 다룹니다. Steganography는 데이터를 다른 데이터 안에 삽입해 통신의 존재를 감춥니다.<sup>[[1]](#references)</sup>

암호화 공격을 찾고 있다면 **Crypto** 섹션으로 이동하세요.

## 진입점

Steganography를 포렌식 문제로 접근하세요. 실제 컨테이너를 식별하고, 신호가 강한 위치(메타데이터, 추가된 데이터, 삽입된 파일)를 조사한 다음, 콘텐츠 수준의 추출 기법을 적용하세요.

### 워크플로 및 초기 분류

컨테이너 식별, 메타데이터 및 문자열 검사, 데이터 카빙, 형식별 분기를 우선시하는 체계적인 워크플로입니다.

{{#ref}}
workflow/README.md
{{#endref}}

### 이미지

대부분의 CTF stego가 발견되는 곳입니다. LSB/bit-plane(PNG/BMP), 청크 및 파일 형식 관련 이상 동작, JPEG 도구, 다중 프레임 GIF 기법을 다룹니다.

{{#ref}}
images/README.md
{{#endref}}

### 오디오

스펙트로그램 메시지, 샘플 LSB 임베딩, 전화 키패드 톤(DTMF)은 반복적으로 나타나는 패턴입니다.

{{#ref}}
audio/README.md
{{#endref}}

### 텍스트

텍스트가 정상적으로 표시되지만 예상과 다르게 동작한다면 Unicode homoglyph, zero-width 문자 또는 공백 기반 인코딩을 고려하세요.

{{#ref}}
text/README.md
{{#endref}}

### 문서

PDF와 Office 파일은 우선 컨테이너로 살펴봐야 합니다. 공격은 대개 삽입된 파일/스트림, 객체/관계 그래프, ZIP 추출을 중심으로 이루어집니다.

{{#ref}}
documents/README.md
{{#endref}}

### Malware 및 전달 방식의 steganography

페이로드 전달에는 GIF 또는 PNG 이미지처럼 정상적으로 보이는 파일을 사용할 수 있습니다. 이 파일은 픽셀에 데이터를 숨기는 대신, 마커로 구분된 텍스트 페이로드를 담고 있습니다.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC 용어집 - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
