# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### 사용자 식별 변수

- **`ruid`**: **real user ID**는 프로세스를 시작한 사용자를 나타냅니다.
- **`euid`**: **effective user ID**라고 하며, 시스템이 프로세스 권한을 확인할 때 사용하는 사용자 ID를 나타냅니다. 일반적으로 `euid`는 `ruid`와 동일하지만, SetUID 바이너리를 실행하는 경우처럼 예외가 있을 수 있습니다. 이때 `euid`는 파일 소유자의 ID를 가지므로 특정 작업 권한이 부여됩니다.
- **`suid`**: **saved user ID**는 높은 권한의 프로세스(일반적으로 root로 실행되는 프로세스)가 특정 작업을 수행하기 위해 일시적으로 권한을 포기한 뒤, 나중에 초기의 높은 권한을 다시 얻어야 할 때 중요하게 사용됩니다.

#### 중요 참고 사항

root 권한으로 실행되지 않는 프로세스는 현재 `ruid`, `euid` 또는 `suid` 중 하나와 동일한 값으로만 `euid`를 변경할 수 있습니다.

### set\*uid 함수 이해하기

- **`setuid`**: 처음 예상하는 것과 달리 `setuid`는 주로 `ruid`가 아니라 `euid`를 변경합니다. 구체적으로 권한이 있는 프로세스에서는 `ruid`, `euid`, `suid`를 지정된 사용자(대개 root)로 설정하여 세 ID를 일치시킵니다. 이때 `suid`가 덮어쓰이므로 해당 ID들은 사실상 고정됩니다. 자세한 내용은 [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)에서 확인할 수 있습니다.
- **`setreuid`** 및 **`setresuid`**: 이 함수들은 `ruid`, `euid`, `suid`를 세밀하게 조정할 수 있도록 합니다. 하지만 가능한 작업은 프로세스의 권한 수준에 따라 달라집니다. root가 아닌 프로세스는 현재 `ruid`, `euid`, `suid` 값으로만 변경할 수 있습니다. 반면 root 프로세스 또는 `CAP_SETUID` capability를 가진 프로세스는 이 ID들에 임의의 값을 지정할 수 있습니다. 자세한 내용은 [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) 및 [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)에서 확인할 수 있습니다.

이러한 기능은 보안 메커니즘이 아니라, 프로그램이 effective user ID를 변경하여 다른 사용자의 ID를 사용하는 경우처럼 의도된 작업 흐름을 지원하기 위해 설계되었습니다.

특히 `setuid`는 모든 ID를 root로 설정하므로 root로의 privilege elevation에 흔히 사용될 수 있지만, 다양한 상황에서 사용자 ID의 동작을 이해하고 조작하려면 이러한 함수들의 차이를 구분하는 것이 중요합니다.

### Linux의 프로그램 실행 메커니즘

#### **`execve` System Call**

- **기능**: `execve`는 첫 번째 인수로 지정된 프로그램을 시작합니다. 인수용 배열 `argv`와 환경용 배열 `envp`를 인수로 받습니다.
- **동작**: 호출자의 메모리 공간은 유지하지만 스택, 힙 및 데이터 세그먼트를 새로 고칩니다. 프로그램의 코드는 새 프로그램으로 대체됩니다.
- **사용자 ID 보존**:
- `ruid`, `euid` 및 supplementary group ID는 변경되지 않습니다.
- 새 프로그램에 SetUID bit가 설정되어 있으면 `euid`가 세부적으로 변경될 수 있습니다.
- 실행 후 `suid`는 `euid`에서 업데이트됩니다.
- **문서**: 자세한 내용은 [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)에서 확인할 수 있습니다.

#### **`system` Function**

- **기능**: `execve`와 달리 `system`은 `fork`를 사용하여 child process를 생성하고, 해당 child process에서 `execl`을 사용해 command를 실행합니다.
- **Command 실행**: 다음과 같이 `execl`을 통해 `sh`로 command를 실행합니다: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **동작**: `execl`은 `execve`의 한 형태이므로 새 child process의 context에서 유사하게 동작합니다.
- **문서**: 자세한 내용은 [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)에서 확인할 수 있습니다.

#### **SUID를 사용하는 `bash` 및 `sh`의 동작**

- **`bash`**:
- `euid`와 `ruid`를 처리하는 방식에 영향을 주는 `-p` option이 있습니다.
- `-p`가 없으면 `bash`는 시작 시 두 ID가 서로 다른 경우 `euid`를 `ruid`로 설정합니다.
- `-p`를 사용하면 초기 `euid`가 보존됩니다.
- 자세한 내용은 [`bash` man page](https://linux.die.net/man/1/bash)에서 확인할 수 있습니다.
- **`sh`**:
- `bash`의 `-p`와 유사한 메커니즘이 없습니다.
- `-i` option을 사용하는 경우를 제외하면 사용자 ID와 관련된 동작이 명시적으로 언급되어 있지 않으며, 이 option은 `euid`와 `ruid`의 동일성을 유지하는 것을 강조합니다.
- 추가 정보는 [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)에서 확인할 수 있습니다.

이러한 메커니즘은 서로 다른 방식으로 동작하며, 프로그램을 실행하고 프로그램 간에 전환할 수 있는 다양한 옵션을 제공합니다. 또한 사용자 ID를 관리하고 보존하는 방식에도 각각의 세부적인 차이가 있습니다.

### 실행 과정에서의 사용자 ID 동작 테스트

예시는 https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail에서 가져왔으며, 추가 정보는 해당 문서를 참고하세요.

#### Case 1: `system`과 함께 `setuid` 사용하기

**목표**: `setuid`를 `system` 및 `sh`로서의 `bash`와 함께 사용할 때의 영향을 이해합니다.

**C Code**:
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

- `ruid`와 `euid`는 각각 99(nobody)와 1000(frank)으로 시작합니다.
- `setuid`는 둘 다 1000으로 맞춥니다.
- `sh`에서 `bash`로 연결된 symlink 때문에 `system`은 `/bin/bash -c id`를 실행합니다.
- `bash`는 `-p` 없이 실행되므로 `euid`를 `ruid`에 맞게 조정하고, 결과적으로 둘 다 99(nobody)가 됩니다.

#### Case 2: system에서 setreuid 사용

**C Code**:
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
- `system`은 bash를 호출하며, 두 사용자 ID가 동일하므로 이를 유지하고 결과적으로 frank로 동작합니다.

#### 사례 3: setuid와 execve 사용

목표: setuid와 execve의 상호작용을 살펴봅니다.
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

- `ruid`는 99로 유지되지만, setuid의 효과에 따라 euid는 1000으로 설정됩니다.

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

- `setuid`에 의해 `euid`가 1000으로 설정되었지만, `-p`가 없기 때문에 `bash`는 `euid`를 `ruid`(99)로 재설정합니다.

**C Code Example 3 (Using bash -p):**
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
uid=99(nobody) gid=99(nobody) euid=100
```
## 참고 자료

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
