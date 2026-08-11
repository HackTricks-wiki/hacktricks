# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### 사용자 식별 변수

- **`ruid`**: **실제 사용자 ID**는 프로세스를 시작한 사용자를 나타냅니다.<sup>[[1]](#references)</sup>
- **`euid`**: **유효 사용자 ID**라고도 하며, 시스템이 프로세스 권한을 확인하는 데 사용하는 사용자 ID를 나타냅니다. 일반적으로 `euid`는 `ruid`와 동일하지만, SetUID binary 실행과 같은 경우(사용자 ID 설정 전환이 적용되는 경우)에는 `euid`가 파일 소유자의 ID를 가지므로 특정 작업 권한을 부여받습니다.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: 이 **저장된 사용자 ID**는 높은 권한을 가진 프로세스(일반적으로 root로 실행되는 프로세스)가 특정 작업을 수행하기 위해 일시적으로 권한을 포기한 후, 나중에 원래의 높은 권한 상태를 되찾아야 할 때 중요합니다.<sup>[[1]](#references)</sup>

#### 중요 참고 사항

권한이 없는 프로세스는 현재 `ruid`, `euid` 또는 `suid`와 동일한 값으로만 `euid`를 변경할 수 있습니다.<sup>[[3]](#references)</sup>

### set\*uid 함수 이해하기

- **`setuid`**: 처음 예상하는 것과 달리 `setuid`는 호출 프로세스의 `euid`를 설정합니다. 권한이 있는 프로세스의 경우 `ruid`와 `suid`도 지정된 사용자로 설정합니다. 모든 ID가 root로 설정된 후에는 프로세스가 `setuid`를 사용하여 이전 ID를 되찾을 수 없습니다. 자세한 내용은 [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)에서 확인할 수 있습니다.<sup>[[2]](#references)</sup>
- **`setreuid`** 및 **`setresuid`**: `setreuid`는 `ruid`와 `euid`를 변경하고, `setresuid`는 세 ID를 모두 변경합니다. 권한이 없는 프로세스의 경우 `setresuid`는 각 대상 값을 현재 `ruid`, `euid` 또는 `suid`로 제한하며, `setreuid`는 `euid`를 해당 값들로 제한하고 `ruid`를 현재 `ruid` 또는 `euid`로 제한합니다. `CAP_SETUID`를 가진 프로세스는 각 호출이 지원하는 ID에 임의의 값을 할당할 수 있습니다. 자세한 내용은 [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) 및 [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)에서 확인할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

이러한 기능은 security mechanism으로 설계된 것이 아니라, 프로그램이 유효 사용자 ID를 변경하여 다른 사용자의 ID를 취하는 경우와 같이 의도된 운영 흐름을 지원하기 위해 설계되었습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

특히 권한이 있는 `setuid` 호출은 세 ID를 모두 설정할 수 있는 반면, `setreuid`와 `setresuid`는 서로 다른 제어 기능을 제공합니다. 따라서 사용자 ID 전환을 이해하려면 이러한 함수들의 차이를 구분하는 것이 중요합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Linux에서의 프로그램 실행 메커니즘

#### **`execve` System Call**

- **기능**: `execve`는 첫 번째 인수로 지정된 프로그램을 시작합니다. 인수를 위한 `argv` 배열과 환경을 위한 `envp` 배열, 두 개의 배열 인수를 받습니다.<sup>[[5]](#references)</sup>
- **동작**: 호출자의 메모리 공간은 유지하지만 stack, heap 및 data segment를 새로 고칩니다. 프로그램의 code는 새 프로그램으로 교체됩니다.<sup>[[5]](#references)</sup>
- **사용자 ID 보존**:
- `ruid`와 supplementary group ID는 변경되지 않습니다.<sup>[[5]](#references)</sup>
- `euid`는 일반적으로 변경되지 않지만, 새 프로그램에 SetUID bit가 설정되어 있으면 변경될 수 있습니다.<sup>[[5]](#references)</sup>
- `suid`는 실행 후 `euid`에서 업데이트됩니다.<sup>[[5]](#references)</sup>
- **문서**: 자세한 정보는 [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)에서 확인할 수 있습니다.<sup>[[5]](#references)</sup>

#### **`system` Function**

- **기능**: `execve`와 달리 `system`은 `fork`를 사용하여 child process를 생성한 다음, 해당 child process에서 `execl`을 사용해 command를 실행하는 것처럼 동작합니다.<sup>[[6]](#references)</sup>
- **Command 실행**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`을 사용하여 `sh`를 통해 command를 실행합니다.<sup>[[6]](#references)</sup>
- **동작**: `execl`은 `exec`-family 호출이므로 새 child process의 context에서 `execve`와 유사하게 동작합니다.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **문서**: 자세한 내용은 [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)에서 확인할 수 있습니다.<sup>[[6]](#references)</sup>

#### **SUID가 설정된 `bash` 및 `sh`의 동작**

- **`bash`**:
- `euid`와 `ruid`의 처리 방식에 영향을 주는 `-p` option이 있습니다.<sup>[[7]](#references)</sup>
- `-p`가 없으면 `bash`는 시작 시 두 값이 서로 다를 경우 `euid`를 `ruid`로 설정합니다.<sup>[[7]](#references)</sup>
- `-p`를 사용하면 초기 `euid`가 보존됩니다.<sup>[[7]](#references)</sup>
- 자세한 내용은 [`bash` man page](https://linux.die.net/man/1/bash)에서 확인할 수 있습니다.<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh`는 Bash 스타일의 privilege-preservation option인 `-p`를 정의하지 않습니다.<sup>[[8]](#references)</sup>
- POSIX option 목록에는 interactive mode를 선택하는 `-i`가 포함되어 있으며, real ID와 effective ID가 다르면 거부될 수 있습니다.<sup>[[8]](#references)</sup>
- 추가 정보는 [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)에서 확인할 수 있습니다.<sup>[[8]](#references)</sup>

이러한 메커니즘은 서로 다른 방식으로 동작하며, 프로그램을 실행하고 프로그램 간에 전환할 수 있는 다양한 옵션을 제공합니다. 또한 user ID가 관리되고 보존되는 방식에도 각각의 특징이 있습니다.

### 실행 시 사용자 ID 동작 테스트

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail에서 가져온 예제입니다. 추가 정보는 해당 문서를 참고하세요.<sup>[[1]](#references)</sup>

#### Case 1: `setuid`와 `system` 사용

**목표**: `setuid`를 `system` 및 `sh`로서의 `bash`와 함께 사용할 때의 영향을 이해합니다.

**C 코드**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**컴파일 및 권한:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

- `ruid`와 `euid`는 각각 99 (nobody)와 1000 (frank)으로 시작합니다.
- 이 권한이 없는 context에서 `setuid(1000)`을 호출해도 `ruid`는 99로, `euid`는 1000으로 유지됩니다.<sup>[[1]](#references)</sup>
- `sh`에서 `bash`로 연결된 symlink로 인해 `system`은 `/bin/bash -c id`를 실행합니다.
- `bash`는 `-p` 없이 실행되면 `euid`를 `ruid`와 일치하도록 조정하므로, 둘 다 99 (nobody)가 됩니다.<sup>[[1]](#references)</sup>

#### Case 2: system에서 setreuid 사용

**C 코드:**
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**컴파일 및 권한:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

- `setreuid`는 ruid와 euid를 모두 1000으로 설정합니다.
- `system`은 bash를 호출하며, 두 사용자 ID가 동일하므로 사용자 ID를 유지하고 사실상 frank로 동작합니다.<sup>[[1]](#references)</sup>

#### 사례 3: setuid와 execve 사용

목표: setuid와 execve의 상호 작용을 살펴봅니다.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

- `ruid`는 99로 유지되지만, setuid의 효과에 따라 euid는 1000으로 설정됩니다.<sup>[[1]](#references)</sup>

**C 코드 예제 2 (Bash 호출):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

- `setuid`에 의해 `euid`가 1000으로 설정되었지만, `-p`가 없기 때문에 `bash`는 euid를 ruid(99)로 재설정합니다.<sup>[[1]](#references)</sup>

**C 코드 예제 3 (bash -p 사용):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system 매뉴얼 페이지](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
