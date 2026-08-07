# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### 사용자 식별 변수

- **`ruid`**: **real user ID**는 프로세스를 시작한 사용자를 나타냅니다.
- **`euid`**: **effective user ID**라고 하며, 시스템이 프로세스 권한을 판단하는 데 사용하는 사용자 ID입니다. 일반적으로 `euid`는 `ruid`와 동일하지만, SetUID binary를 실행하는 경우처럼 예외가 있습니다. 이때 `euid`는 파일 소유자의 ID를 가지므로 특정 작업 권한을 부여받습니다.
- **`suid`**: **saved user ID**는 높은 권한을 가진 프로세스(일반적으로 root로 실행)가 특정 작업을 수행하기 위해 일시적으로 권한을 포기한 뒤, 나중에 원래의 높은 권한을 되찾아야 할 때 중요하게 사용됩니다.

#### 중요 참고 사항

root 권한으로 실행되지 않는 프로세스는 현재 `ruid`, `euid` 또는 `suid` 중 하나와 동일한 값으로만 `euid`를 변경할 수 있습니다.

### set\*uid Functions 이해하기

- **`setuid`**: 처음 생각하는 것과 달리 `setuid`는 주로 `ruid`가 아니라 `euid`를 변경합니다. 구체적으로 권한이 있는 프로세스의 경우 `ruid`, `euid`, `suid`를 지정된 사용자(대개 root)로 설정하여, `suid`의 영향으로 해당 ID들을 사실상 고정합니다. 자세한 내용은 [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)에서 확인할 수 있습니다.<sup>[[2]](#references)</sup>
- **`setreuid`** 및 **`setresuid`**: 이 Functions를 사용하면 `ruid`, `euid`, `suid`를 세밀하게 조정할 수 있습니다. 그러나 가능한 작업은 프로세스의 권한 수준에 따라 달라집니다. root가 아닌 프로세스는 현재 `ruid`, `euid`, `suid` 값으로만 변경할 수 있습니다. 반면 root 프로세스 또는 `CAP_SETUID` capability를 가진 프로세스는 이러한 ID에 임의의 값을 지정할 수 있습니다. 자세한 내용은 [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) 및 [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)에서 확인할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

이러한 기능은 security mechanism이 아니라, 프로그램이 effective user ID를 변경하여 다른 사용자의 ID를 취득하는 경우처럼 의도된 operation flow를 지원하기 위해 설계되었습니다.

특히 `setuid`는 모든 ID를 root로 설정하므로 root로 privilege elevation을 수행할 때 흔히 사용될 수 있지만, 다양한 상황에서 user ID의 동작을 이해하고 조작하려면 이러한 Functions의 차이를 구분하는 것이 중요합니다.

### Linux의 Program Execution Mechanisms

#### **`execve` System Call**

- **Functionality**: `execve`는 첫 번째 argument로 지정된 프로그램을 시작합니다. 두 개의 array argument를 받으며, `argv`는 arguments를, `envp`는 environment를 나타냅니다.
- **Behavior**: 호출자의 memory space를 유지하지만 stack, heap 및 data segment를 새로 고칩니다. 프로그램의 code는 새 프로그램으로 교체됩니다.
- **User ID Preservation**:
- `ruid`, `euid` 및 supplementary group ID는 변경되지 않습니다.
- 새 프로그램에 SetUID bit가 설정되어 있으면 `euid`가 세부적으로 변경될 수 있습니다.
- 실행 후 `suid`는 `euid`에서 업데이트됩니다.
- **Documentation**: 자세한 내용은 [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)에서 확인할 수 있습니다.<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Functionality**: `execve`와 달리 `system`은 `fork`를 사용해 child process를 생성하고, 해당 child process에서 `execl`을 사용해 command를 실행합니다.
- **Command Execution**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`을 통해 `sh`로 command를 실행합니다.
- **Behavior**: `execl`은 `execve`의 한 형태이므로 새로운 child process의 context에서 유사하게 동작합니다.
- **Documentation**: 자세한 내용은 [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)에서 확인할 수 있습니다.

#### **SUID가 적용된 `bash` 및 `sh`의 Behavior**

- **`bash`**:
- `euid`와 `ruid`의 처리 방식에 영향을 주는 `-p` option이 있습니다.
- `-p`가 없으면 `bash`는 처음부터 두 값이 서로 다른 경우 `euid`를 `ruid`로 설정합니다.
- `-p`를 사용하면 처음의 `euid`가 유지됩니다.
- 자세한 내용은 [`bash` man page](https://linux.die.net/man/1/bash)에서 확인할 수 있습니다.
- **`sh`**:
- `bash`의 `-p`와 유사한 mechanism이 없습니다.
- `-i` option을 사용하는 경우를 제외하면 user ID와 관련된 동작이 명시적으로 언급되어 있지 않으며, `euid`와 `ruid`의 일치를 유지하는 데 중점을 둡니다.
- 추가 정보는 [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)에서 확인할 수 있습니다.

이러한 mechanisms는 서로 다른 방식으로 동작하며, 프로그램을 실행하고 프로그램 간에 transition할 수 있는 다양한 option을 제공합니다. 또한 user ID가 관리되고 유지되는 방식에는 각각의 세부적인 차이가 있습니다.

### Execution에서 User ID Behavior 테스트하기

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail 에서 가져온 Examples입니다. 추가 정보는 해당 내용을 확인하세요.<sup>[[1]](#references)</sup>

#### Case 1: `system`과 함께 `setuid` 사용하기

**Objective**: `setuid`를 `system` 및 `sh`로서의 `bash`와 함께 사용할 때의 effect를 이해합니다.

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

- `ruid`와 `euid`는 각각 99 (nobody)와 1000 (frank)으로 시작합니다.
- `setuid`는 둘 다 1000으로 맞춥니다.
- `sh`에서 `bash`로 연결된 symlink로 인해 `system`은 `/bin/bash -c id`를 실행합니다.
- `bash`는 `-p` 없이 실행되면 `euid`를 `ruid`와 일치하도록 조정하므로, 둘 다 99 (nobody)가 됩니다.

#### system에서 setreuid 사용

**C 코드**:
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
- `system`은 bash를 호출하며, 두 user ID가 동일하므로 이를 유지하고 사실상 frank로 동작합니다.

#### Case 3: setuid와 execve 사용

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

- `ruid`는 99로 유지되지만, `euid`는 setuid의 효과에 따라 1000으로 설정됩니다.

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

- `setuid`에 의해 `euid`가 1000으로 설정되더라도, `-p`가 없기 때문에 `bash`는 euid를 `ruid`(99)로 재설정합니다.

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
uid=99(nobody) gid=99(nobody) euid=100
```
## 참고 자료

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man 페이지](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man 페이지](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man 페이지](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man 페이지](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
