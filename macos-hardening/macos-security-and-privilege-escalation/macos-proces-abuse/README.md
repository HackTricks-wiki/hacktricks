# macOS Proces Abuse

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## MacOS Process Abuse

MacOS, like any other operating system, provides a variety of methods and mechanisms for **processes to interact, communicate, and share data**. While these techniques are essential for efficient system functioning, they can also be abused by threat actors to **perform malicious activities**.

### Library Injection

Library Injection is a technique wherein an attacker **forces a process to load a malicious library**. Once injected, the library runs in the context of the target process, providing the attacker with the same permissions and access as the process.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Function Hooking

Function Hooking involves **intercepting function calls** or messages within a software code. By hooking functions, an attacker can **modify the behavior** of a process, observe sensitive data, or even gain control over the execution flow.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Inter Process Communication

Inter Process Communication (IPC) refers to different methods by which separate processes **share and exchange data**. While IPC is fundamental for many legitimate applications, it can also be misused to subvert process isolation, leak sensitive information, or perform unauthorized actions.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Electron Applications Injection

Electron applications executed with specific env variables could be vulnerable to process injection:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### .Net Applications Injection

It's possible to inject code into .Net applications by **abusing the .Net debugging functionality** (not protected by macOS protections such as runtime hardening).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Python Injection

If the environment variable **`PYTHONINSPECT`** is set, the python process will drop into a python cli once it's finished.

Other env variables such as **`PYTHONPATH`** and **`PYTHONHOME`** could also be useful to make a python command execute arbitrary scode.

Note that executables compiled with **`pyinstaller`** won't use these environmental variables even if they are running using an embedded python.

## Detection

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) is an open source application that can **detect and block process injection** actions:

* Using **Environmental Variables**: It will monitor the presence of any of the following environmental variables: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** and **`ELECTRON_RUN_AS_NODE`**
* Using **`task_for_pid`** calls: To find when one process wants to get the **task port of another** which allows to inject code in the process.
* **Electron apps params**: Someone can use **`--inspect`**, **`--inspect-brk`** and **`--remote-debugging-port`** command line argument to start an Electron app in debugging mode, and thus inject code to it.
* Using **symlinks** or **hardlinks**: Typically the most common abuse is to **place a link with our user privileges**, and **point it to a higher privilege** location. The detection is very simple for both hardlink and symlinks. If the process creating the link has a **different privilege level** than the target file, we create an **alert**. Unfortunately in the case of symlinks blocking is not possible, as we don’t have information about the destination of the link prior creation. This is a limitation of Apple’s EndpointSecuriy framework.

### Calls made by other processes

In [**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) you can find how it's possible to use the function **`task_name_for_pid`** to get information about other **processes injecting code in a process** and then getting information about that other process.

Note that to call that function you need to be **the same uid** as the one running the process or **root** (and it returns info about the process, not a way to inject code).

## References

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
