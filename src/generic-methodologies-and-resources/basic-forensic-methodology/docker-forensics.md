# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}

## Container modification

There are suspicions that some docker container was compromised:

```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```

You can easily **find changes made to this container's filesystem since it was created** with:<sup>[[1]](#references)</sup>

```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```

In the previous command **C** means **Changed** and **A** means **Added**.<sup>[[1]](#references)</sup>\
If you find that some interesting file like `/etc/shadow` was modified you can download it from the container to check for malicious activity with:<sup>[[2]](#references)</sup>

```bash
docker cp wordpress:/etc/shadow shadow
```

You can also **compare it with the original one** running a new container and extracting the file from it:<sup>[[2]](#references)[[3]](#references)</sup>

```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```

If you find that **some suspicious file was added** you can access the container and check it:<sup>[[4]](#references)</sup>

```bash
docker exec -it wordpress bash
```

## Images modifications

When you are given an exported docker image (probably in `.tar` format) you can use [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) to **extract a summary of the modifications**:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```

Then, you can **decompress** the image and **access the blobs** to search for suspicious files you may have found in the changes history:<sup>[[7]](#references)</sup>

```bash
tar -xf image.tar
```

### Basic Analysis

You can get **basic information** from the image running:<sup>[[8]](#references)</sup>

```bash
docker inspect <image>
```

You can also get a summary **history of changes** with:<sup>[[9]](#references)</sup>

```bash
docker history --no-trunc <image>
```

You can also generate a **dockerfile from an image** with:<sup>[[10]](#references)</sup>

```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```

### Dive

In order to find added/modified files in docker images you can also use the [**dive**](https://github.com/wagoodman/dive) (download it from [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) utility:<sup>[[11]](#references)[[12]](#references)</sup>

Load the saved archive into Docker before opening its image tag with dive:<sup>[[11]](#references)[[13]](#references)</sup>

```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```

This allows you to **navigate through the different blobs of docker images** and check which files were modified/added/removed. Use **tab** to move to the other view and **space** to collapse/open folders.<sup>[[11]](#references)</sup>

With dive you won't be able to access the content of the different stages of the image. To do so you will need to **decompress each layer and access it**.\
You can decompress all the layers from an image from the directory where the image was decompressed executing:

```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```

## Credentials from memory

On Linux, the host's ancestor PID namespace can see processes in a container's child PID namespace, so a host process listing such as `ps -ef` can show them.<sup>[[14]](#references)</sup>

When host credentials, capabilities, and LSM/ptrace policy permit it, an appropriately privileged host investigator can **dump process memory** and search for **credentials** just [**like in the following example**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff analyzer definitions](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 release](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)

{{#include ../../banners/hacktricks-training.md}}
