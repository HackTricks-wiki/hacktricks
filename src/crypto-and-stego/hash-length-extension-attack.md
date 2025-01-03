# 해시 길이 확장 공격

{{#include ../banners/hacktricks-training.md}}

## 공격 요약

서버가 **데이터**에 **비밀**을 **추가**하여 **서명**하고 그 데이터를 해싱한다고 상상해 보십시오. 다음을 알고 있다면:

- **비밀의 길이** (주어진 길이 범위에서 브루트포스할 수 있음)
- **명확한 텍스트 데이터**
- **알고리즘 (이 공격에 취약함)**
- **패딩이 알려짐**
- 일반적으로 기본값이 사용되므로 다른 3가지 요구 사항이 충족되면 이것도 해당됨
- 패딩은 비밀 + 데이터의 길이에 따라 달라지므로 비밀의 길이가 필요함

그렇다면 **공격자**가 **데이터**를 **추가**하고 **이전 데이터 + 추가된 데이터**에 대한 유효한 **서명**을 **생성**하는 것이 가능합니다.

### 어떻게?

기본적으로 취약한 알고리즘은 먼저 **데이터 블록을 해싱**하여 해시를 생성하고, 그 다음 **이전에** 생성된 **해시**(상태)에서 **다음 데이터 블록을 추가**하고 **해싱**합니다.

그런 다음 비밀이 "secret"이고 데이터가 "data"라고 가정해 보십시오. "secretdata"의 MD5는 6036708eba0d11f6ef52ad44e8b74d5b입니다.\
공격자가 "append" 문자열을 추가하고 싶다면 다음과 같이 할 수 있습니다:

- 64개의 "A"로 MD5 생성
- 이전에 초기화된 해시의 상태를 6036708eba0d11f6ef52ad44e8b74d5b로 변경
- "append" 문자열 추가
- 해시를 완료하면 결과 해시는 **"secret" + "data" + "padding" + "append"**에 대한 유효한 해시가 됩니다.

### **도구**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

### 참고 문헌

이 공격에 대한 좋은 설명은 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)에서 찾을 수 있습니다.

{{#include ../banners/hacktricks-training.md}}
