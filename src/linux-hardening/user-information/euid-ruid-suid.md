# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### User Identification Variables

- **`ruid`**: The **real user ID** denotes the user who initiated the process.<sup>[[1]](#references)</sup>
- **`euid`**: Known as the **effective user ID**, it represents the user identity utilized by the system to ascertain process privileges. Generally, `euid` mirrors `ruid`, barring instances like a SetUID binary execution (when the set-user-ID transition is honored), where `euid` assumes the file owner's identity, thus granting specific operational permissions.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: This **saved user ID** is pivotal when a high-privilege process (typically running as root) needs to temporarily relinquish its privileges to perform certain tasks, only to later reclaim its initial elevated status.<sup>[[1]](#references)</sup>

#### Important Note

An unprivileged process can only modify its `euid` to match the current `ruid`, `euid`, or `suid`.<sup>[[3]](#references)</sup>

### Understanding set\*uid Functions

- **`setuid`**: Contrary to initial assumptions, `setuid` sets the calling process's `euid`. For a privileged process, it also sets `ruid` and `suid` to the specified user; after all IDs are set to root, the process cannot regain a previous identity using `setuid`. Detailed insights can be found in the [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** and **`setresuid`**: `setreuid` changes `ruid` and `euid`, while `setresuid` changes all three IDs. For an unprivileged process, `setresuid` restricts each target to the current `ruid`, `euid`, or `suid`; `setreuid` restricts `euid` to those values and `ruid` to the current `ruid` or `euid`. A process with `CAP_SETUID` can assign arbitrary values to the IDs supported by each call. More information can be gleaned from the [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) and the [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

These functionalities are designed not as a security mechanism but to facilitate the intended operational flow, such as when a program adopts another user's identity by altering its effective user ID.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Notably, a privileged call to `setuid` can assign all three IDs, whereas `setreuid` and `setresuid` expose different controls; differentiating these functions is crucial for understanding user-ID transitions.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve` initiates a program, determined by the first argument. It takes two array arguments, `argv` for arguments and `envp` for the environment.<sup>[[5]](#references)</sup>
- **Behavior**: It retains the memory space of the caller but refreshes the stack, heap, and data segments. The program's code is replaced by the new program.<sup>[[5]](#references)</sup>
- **User ID Preservation**:
  - `ruid` and supplementary group IDs remain unaltered.<sup>[[5]](#references)</sup>
  - `euid` is normally unchanged but might change if the new program has the SetUID bit set.<sup>[[5]](#references)</sup>
  - `suid` gets updated from `euid` post-execution.<sup>[[5]](#references)</sup>
- **Documentation**: Detailed information can be found on the [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Functionality**: Unlike `execve`, `system` behaves as if it creates a child process using `fork` and executes the command within that child process using `execl`.<sup>[[6]](#references)</sup>
- **Command Execution**: Executes the command via `sh` with `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Behavior**: As `execl` is an `exec`-family call, it operates similarly to `execve` but in the context of a new child process.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentation**: Further insights can be obtained from the [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
  - Has a `-p` option influencing how `euid` and `ruid` are treated.<sup>[[7]](#references)</sup>
  - Without `-p`, `bash` sets `euid` to `ruid` if they initially differ.<sup>[[7]](#references)</sup>
  - With `-p`, the initial `euid` is preserved.<sup>[[7]](#references)</sup>
  - More details can be found on the [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
  - POSIX `sh` does not define a Bash-style `-p` privilege-preservation option.<sup>[[8]](#references)</sup>
  - Its POSIX option list includes `-i`, which selects interactive mode and may be rejected when the real and effective IDs differ.<sup>[[8]](#references)</sup>
  - Additional information is available on the [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

These mechanisms, distinct in their operation, offer a versatile range of options for executing and transitioning between programs, with specific nuances in how user IDs are managed and preserved.

### Testing User ID Behaviors in Executions

Examples taken from https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, check it for further information.<sup>[[1]](#references)</sup>

#### Case 1: Using `setuid` with `system`

**Objective**: Understanding the effect of `setuid` in combination with `system` and `bash` as `sh`.

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

**Compilation and Permissions:**

```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Analysis:**

- `ruid` and `euid` start as 99 (nobody) and 1000 (frank) respectively.
- In this unprivileged context, `setuid(1000)` leaves `ruid` at 99 and `euid` at 1000.<sup>[[1]](#references)</sup>
- `system` executes `/bin/bash -c id` due to the symlink from sh to bash.
- `bash`, without `-p`, adjusts `euid` to match `ruid`, resulting in both being 99 (nobody).<sup>[[1]](#references)</sup>

#### Case 2: Using setreuid with system

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

**Compilation and Permissions:**

```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```

**Execution and Result:**

```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Analysis:**

- `setreuid` sets both ruid and euid to 1000.
- `system` invokes bash, which maintains the user IDs due to their equality, effectively operating as frank.<sup>[[1]](#references)</sup>

#### Case 3: Using setuid with execve

Objective: Exploring the interaction between setuid and execve.

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

**Execution and Result:**

```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Analysis:**

- `ruid` remains 99, but euid is set to 1000, in line with setuid's effect.<sup>[[1]](#references)</sup>

**C Code Example 2 (Calling Bash):**

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

**Execution and Result:**

```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Analysis:**

- Although `euid` is set to 1000 by `setuid`, `bash` resets euid to `ruid` (99) due to the absence of `-p`.<sup>[[1]](#references)</sup>

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

**Execution and Result:**

```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```

## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man page](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system man page](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash man page](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh man page](https://man7.org/linux/man-pages/man1/sh.1p.html)

{{#include ../../banners/hacktricks-training.md}}
