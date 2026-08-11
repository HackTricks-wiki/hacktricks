# Crypto CTF 기타

{{#include ../../banners/hacktricks-training.md}}

이 섹션에서는 암호화 challenge에 등장하지만 다른 카테고리에 깔끔하게 분류되지 않는 기술을 다룹니다.

## Esoteric languages

### Technique

challenge에서 esoteric-language 프로그램을 실행하고 그 출력을 디코딩해야 할 때 다음 workflow를 사용합니다.

challenge에서 표준 언어처럼 보이지 않는 code를 제공하는 경우:

- 독특한 token이나 instruction sequence를 검색하여 언어를 식별합니다.
- 온라인 interpreter 또는 Docker image를 사용합니다.
- 출력이 이상하다면 실행 후 여러 단계로 적용된 encoding/compression을 확인합니다.

유용한 언어 목록으로 Esolang wiki를 참고할 수 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Esolang, 에소테릭 프로그래밍 언어 wiki](https://esolangs.org/wiki/Main_Page)
{{#include ../../banners/hacktricks-training.md}}
