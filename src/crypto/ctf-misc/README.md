# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

Crypto challenges에서 자주 등장하지만 다른 곳에 깔끔하게 분류하기 어려운 내용을 모아둔 페이지입니다.

## Esoteric languages

### Technique

Crypto task가 실제로는 esolang 프로그램을 실행한 다음 출력 결과를 decode하는 작업일 때 사용합니다.

Challenge에서 standard language처럼 보이지 않는 code가 주어졌다면:

- Esolang을 식별합니다(특징적인 token을 Google에서 검색).
- Online interpreter 또는 Docker image를 사용합니다.
- 실행 후 output이 이상하다면, layered encoding/compression이 있는지 확인합니다.

좋은 시작점 목록:<sup>[[1]](#references)</sup>

{{#ref}}
https://esolangs.org/wiki/Main_Page
{{#endref}}

## References

- [1] [Esolang, the esoteric programming languages wiki](https://esolangs.org/wiki/Main_Page)

{{#include ../../banners/hacktricks-training.md}}
