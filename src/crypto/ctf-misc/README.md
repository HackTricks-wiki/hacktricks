# Crypto CTF 기타

{{#include ../../banners/hacktricks-training.md}}

이 섹션에서는 암호화 문제에 등장하지만 다른 카테고리에는 잘 들어맞지 않는 기법을 모았습니다.

## 난해한 언어

### 기법

문제에서 난해한 언어로 작성된 프로그램을 실행하고 출력을 디코딩해야 할 때 이 워크플로를 사용하세요.

문제에서 표준 언어처럼 보이지 않는 코드를 제공하는 경우:

- 독특한 토큰이나 명령어 시퀀스를 검색해 언어를 식별하세요.
- 온라인 인터프리터나 Docker 이미지를 사용하세요.
- 출력이 이상하다면 실행 후 여러 겹으로 적용된 인코딩이나 압축을 확인하세요.

유용한 언어 목록은 Esolang 위키입니다.<sup>[[1]](#references)</sup> 일반적인 인코딩 및 압축 단계에는 [Crypto CTF 워크플로](../ctf-workflow/)를 사용하세요. 단서가 실행 가능한 문법이 아니라 보이지 않는 텍스트라면 [텍스트 스테가노그래피](../../stego/text/)를 확인하세요.

### 미리 로드된 인터프리터 상태 유출

문제에서 난해한 언어 소스를 입력받아 **커스텀 인터프리터**로 실행한다면, 소스를 디코딩 문제로 보기 전에 인터프리터의 초기 메모리, 스택, 출력 명령어를 살펴보세요. 인터프리터가 비밀 값을 Befunge 스택에 미리 올려 두는 경우, 짧은 프로그램으로 기존 바이트를 꺼내 출력할 수 있습니다. 이 방법은 실행되는 소스와 출력 opcode를 제어할 수 있어야 하며, 일반적인 빈 인터프리터에서는 작동하지 않습니다. 한 Befunge 문제에서는 아래 입력을 사용해 스택에 역순으로 미리 올라간 플래그의 문자를 반복해서 출력했습니다.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>`는 오른쪽으로 실행을 시작하고, `,`는 값을 꺼내 문자를 출력하며, `<`는 명령 포인터를 `,`로 되돌립니다. 사용자 지정 인터프리터의 언더플로 및 명령 제한 동작을 확인하세요. 인용된 구현은 스택이 비거나 명령 1,024개를 실행한 후 멈춥니다. 비밀이 스택에 직접 들어 있지 않다면, 표준 Befunge 의미를 가정하는 대신 초기화된 다른 상태와 사용 가능한 출력/읽기 명령을 살펴보세요.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, 난해한 프로그래밍 언어 위키](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 Befuddled1 원본 writeup](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 Befuddled1 인터프리터 소스 코드](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge 언어 레퍼런스](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
