# 암호학 CTF 기타

{{#include ../../banners/hacktricks-training.md}}

이 섹션에서는 암호학 챌린지에 등장하지만 다른 범주에 깔끔하게 들어맞지 않는 기법을 모았습니다.

## 난해한 언어

### 기법

챌린지에서 난해한 언어로 작성된 프로그램을 실행하고 출력을 디코딩해야 하는 경우 다음 절차를 사용하세요.

표준적인 언어처럼 보이지 않는 코드를 받았다면 다음을 수행하세요.

- 독특한 토큰이나 명령어 시퀀스를 검색해 언어를 식별합니다.
- 온라인 인터프리터나 Docker 이미지를 사용합니다.
- 출력이 이상하다면 실행 후 추가로 적용된 인코딩이나 압축이 있는지 확인합니다.

유용한 언어 목록은 Esolang wiki입니다.<sup>[[1]](#references)</sup>

## References

- [1] [Esolang, 난해한 프로그래밍 언어 위키](https://esolangs.org/wiki/Main_Page)
{{#include ../../banners/hacktricks-training.md}}
