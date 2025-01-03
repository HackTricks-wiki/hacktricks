# PDF 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**자세한 내용은 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF 형식은 복잡성과 데이터를 숨길 수 있는 잠재력으로 잘 알려져 있어 CTF 포렌식 챌린지의 중심이 됩니다. 이는 일반 텍스트 요소와 압축되거나 암호화될 수 있는 이진 객체를 결합하며, JavaScript나 Flash와 같은 언어의 스크립트를 포함할 수 있습니다. PDF 구조를 이해하기 위해 Didier Stevens의 [소개 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)를 참조하거나 텍스트 편집기 또는 Origami와 같은 PDF 전용 편집기를 사용할 수 있습니다.

PDF를 심층적으로 탐색하거나 조작하기 위해 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf)와 같은 도구를 사용할 수 있습니다. PDF 내 숨겨진 데이터는 다음과 같은 곳에 숨겨져 있을 수 있습니다:

- 보이지 않는 레이어
- Adobe의 XMP 메타데이터 형식
- 점진적 생성
- 배경과 같은 색상의 텍스트
- 이미지 뒤의 텍스트 또는 겹치는 이미지
- 표시되지 않는 주석

맞춤형 PDF 분석을 위해 [PeepDF](https://github.com/jesparza/peepdf)와 같은 Python 라이브러리를 사용하여 맞춤형 파싱 스크립트를 작성할 수 있습니다. 또한 PDF의 숨겨진 데이터 저장 가능성은 매우 방대하여, 원래 위치에서 더 이상 호스팅되지 않지만 PDF 위험 및 대응 조치에 대한 NSA 가이드와 같은 자료는 여전히 귀중한 통찰력을 제공합니다. [가이드 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini의 [PDF 형식 트릭 모음](https://github.com/corkami/docs/blob/master/PDF/PDF.md)은 이 주제에 대한 추가 읽기를 제공할 수 있습니다.

{{#include ../../../banners/hacktricks-training.md}}
