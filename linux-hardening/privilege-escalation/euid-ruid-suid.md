# euid, ruid, suid

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


### User Identification Variables

- **`ruid`**: The **real user ID** denotes the user who initiated the process.
- **`euid`**: Known as the **effective user ID**, it represents the user identity utilized by the system to ascertain process privileges. Generally, `euid` mirrors `ruid`, barring instances like a SetUID binary execution, where `euid` assumes the file owner's identity, thus granting specific operational permissions.
- **`suid`**: This **saved user ID** is pivotal when a high-privilege process (typically running as root) needs to temporarily relinquish its privileges to perform certain tasks, only to later reclaim its initial elevated status.

#### Important Note
A process not operating under root can only modify its `euid` to match the current `ruid`, `euid`, or `suid`.

### Understanding set*uid Functions

- **`setuid`**: Contrary to initial assumptions, `setuid` primarily modifies `euid` rather than `ruid`. Specifically, for privileged processes, it aligns `ruid`, `euid`, and `suid` with the specified user, often root, effectively solidifying these IDs due to the overriding `suid`. Detailed insights can be found in the [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** and **`setresuid`**: These functions allow for the nuanced adjustment of `ruid`, `euid`, and `suid`. However, their capabilities are contingent on the process's privilege level. For non-root processes, modifications are restricted to the current values of `ruid`, `euid`, and `suid`. In contrast, root processes or those with `CAP_SETUID` capability can assign arbitrary values to these IDs. More information can be gleaned from the [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) and the [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

These functionalities are designed not as a security mechanism but to facilitate the intended operational flow, such as when a program adopts another user's identity by altering its effective user ID.

Notably, while `setuid` might be a common go-to for privilege elevation to root (since it aligns all IDs to root), differentiating between these functions is crucial for understanding and manipulating user ID behaviors in varying scenarios.

### Program Execution Mechanisms in Linux

#### **`execve` System Call**
- **Functionality**: `execve` initiates a program, determined by the first argument. It takes two array arguments, `argv` for arguments and `envp` for the environment.
- **Behavior**: It retains the memory space of the caller but refreshes the stack, heap, and data segments. The program's code is replaced by the new program.
- **User ID Preservation**:
  - `ruid`, `euid`, and supplementary group IDs remain unaltered.
  - `euid` might have nuanced changes if the new program has the SetUID bit set.
  - `suid` gets updated from `euid` post-execution.
- **Documentation**: Detailed information can be found on the [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**
- **Functionality**: Unlike `execve`, `system` creates a child process using `fork` and executes a command within that child process using `execl`.
- **Command Execution**: Executes the command via `sh` with `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: As `execl` is a form of `execve`, it operates similarly but in the context of a new child process.
- **Documentation**: Further insights can be obtained from the [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior of `bash` and `sh` with SUID**
- **`bash`**:
  - Has a `-p` option influencing how `euid` and `ruid` are treated.
  - Without `-p`, `bash` sets `euid` to `ruid` if they initially differ.
  - With `-p`, the initial `euid` is preserved.
  - More details can be found on the [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
  - Does not possess a mechanism similar to `-p` in `bash`.
  - The behavior concerning user IDs is not explicitly mentioned, except under the `-i` option, emphasizing the preservation of `euid` and `ruid` equality.
  - Additional information is available on the [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

These mechanisms, distinct in their operation, offer a versatile range of options for executing and transitioning between programs, with specific nuances in how user IDs are managed and preserved.

### Testing User ID Behaviors in Executions

Examples taken from https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, check it for further information

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

* `ruid` and `euid` start as 99 (nobody) and 1000 (frank) respectively.
* `setuid` aligns both to 1000.
* `system` executes `/bin/bash -c id` due to the symlink from sh to bash.
* `bash`, without `-p`, adjusts `euid` to match `ruid`, resulting in both being 99 (nobody).

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

* `setreuid` sets both ruid and euid to 1000.
* `system` invokes bash, which maintains the user IDs due to their equality, effectively operating as frank.

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

* `ruid` remains 99, but euid is set to 1000, in line with setuid's effect.

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

* Although `euid` is set to 1000 by `setuid`, `bash` resets euid to `ruid` (99) due to the absence of `-p`.

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
uid=99(nobody) gid=99(nobody) euid=100
```

## References
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

