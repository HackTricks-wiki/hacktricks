# SELinux

## SELinux in Containers

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) is a **labeling** **system**. Every **process** and every **file** system object has a **label**. SELinux policies define rules about what a **process label is allowed to do with all of the other labels** on the system.

Container engines launch **container processes with a single confined SELinux label**, usually `container_t`, and then set the container inside of the container to be labeled `container_file_t`. The SELinux policy rules basically say that the **`container_t` processes can only read/write/execute files labeled `container_file_t`**. If a container process escapes the container and attempts to write to content on the host, the Linux kernel denies access and only allows the container process to write to content labeled `container_file_t`.

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

## SELinux Users

There are SELinux users in addition to the regular Linux users. SELinux users are part of an SELinux policy. Each Linux user is mapped to a SELinux user as part of the policy. This allows Linux users to inherit the restrictions and security rules and mechanisms placed on SELinux users.
