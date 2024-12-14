# DDexec / EverythingExec

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

## Context

In Linux in order to run a program it must exist as a file, it must be accessible in some way through the file system hierarchy (this is just how `execve()` works). This file may reside on disk or in ram (tmpfs, memfd) but you need a filepath. This has made very easy to control what is run on a Linux system, it makes easy to detect threats and attacker's tools or to prevent them from trying to execute anything of theirs at all (_e. g._ not allowing unprivileged users to place executable files anywhere).

But this technique is here to change all of this. If you can not start the process you want... **then you hijack one already existing**.

This technique allows you to **bypass common protection techniques such as read-only, noexec, file-name whitelisting, hash whitelisting...**

## Dependencies

The final script depends on the following tools to work, they need to be accessible in the system you are attacking (by default you will find all of them everywhere):

```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```

## The technique

If you are able to modify arbitrarily the memory of a process then you can take over it. This can be used to hijack an already existing process and replace it with another program. We can achieve this either by using the `ptrace()` syscall (which requires you to have the ability to execute syscalls or to have gdb available on the system) or, more interestingly, writing to `/proc/$pid/mem`.

The file `/proc/$pid/mem` is a one-to-one mapping of the entire address space of a process (_e. g._ from `0x0000000000000000` to `0x7ffffffffffff000` in x86-64). This means that reading from or writing to this file at an offset `x` is the same as reading from or modifying the contents at the virtual address `x`.

Now, we have four basic problems to face:

* In general, only root and the program owner of the file may modify it.
* ASLR.
* If we try to read or write to an address not mapped in the address space of the program we will get an I/O error.

This problems have solutions that, although they are not perfect, are good:

* Most shell interpreters allow the creation of file descriptors that will then be inherited by child processes. We can create a fd pointing to the `mem` file of the sell with write permissions... so child processes that use that fd will be able to modify the shell's memory.
* ASLR isn't even a problem, we can check the shell's `maps` file or any other from the procfs in order to gain information about the address space of the process.
* So we need to `lseek()` over the file. From the shell this cannot be done unless using the infamous `dd`.

### In more detail

The steps are relatively easy and do not require any kind of expertise to understand them:

* Parse the binary we want to run and the loader to find out what mappings they need. Then craft a "shell"code that will perform, broadly speaking, the same steps that the kernel does upon each call to `execve()`:
  * Create said mappings.
  * Read the binaries into them.
  * Set up permissions.
  * Finally initialize the stack with the arguments for the program and place the auxiliary vector (needed by the loader).
  * Jump into the loader and let it do the rest (load libraries needed by the program).
* Obtain from the `syscall` file the address to which the process will return after the syscall it is executing.
* Overwrite that place, which will be executable, with our shellcode (through `mem` we can modify unwritable pages).
* Pass the program we want to run to the stdin of the process (will be `read()` by said "shell"code).
* At this point it is up to the loader to load the necessary libraries for our program and jump into it.

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

There are several alternatives to `dd`, one of which, `tail`, is currently the default program used to `lseek()` through the `mem` file (which was the sole purpose for using `dd`). Said alternatives are:

```bash
tail
hexdump
cmp
xxd
```

Setting the variable `SEEKER` you may change the seeker used, _e. g._:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

If you find another valid seeker not implemented in the script you may still use it setting the `SEEKER_ARGS` variable:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Block this, EDRs.

## References
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

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

