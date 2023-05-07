# Linux Environment Variables

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Global variables

The global variables **will be** inherited by **child processes**.

You can create a global variable for your current session doing:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

This variable will be accessible by your current sessions and its child processes.

You can **remove** a variable doing:

```bash
unset MYGLOBAL
```

## Local variables

The **local variables** can only be **accessed** by the **current shell/script**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## List current variables

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

## Persistent Environment variables

#### **Files that affect behavior of every user:**

* _**/etc/bash.bashrc**_: This file is read whenever an interactive shell is started (normal terminal) and all the commands specified in here are executed.
* _**/etc/profile and /etc/profile.d/\***_**:** This file is read every time a user logs in. Thus all the commands executed in here will execute only once at the time of user logging in.
  *   \*\*Example: \*\*

      `/etc/profile.d/somescript.sh`

      ```bash
      #!/bin/bash
      TEST=$(cat /var/somefile)
      export $TEST
      ```

#### **Files that affect behavior for only a specific user:**

* _**\~/.bashrc**_: This file behaves the same way _/etc/bash.bashrc_ file works but it is executed only for a specific user. If you want to create an environment for yourself go ahead and modify or create this file in your home directory.
* _**\~/.profile, \~/.bash\_profile, \~/.bash\_login**_**:** These files are same as _/etc/profile_. The difference comes in the way it is executed. This file is executed only when a user in whose home directory this file exists, logs in.

**Extracted from:** [**here**](https://codeburst.io/linux-environment-variables-53cea0245dc9) **and** [**here**](https://www.gnu.org/software/bash/manual/html\_node/Bash-Startup-Files.html)

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – the display used by **X**. This variable is usually set to **:0.0**, which means the first display on the current computer.
* **EDITOR** – the user’s preferred text editor.
* **HISTFILESIZE** – the maximum number of lines contained in the history file.
* \*\*HISTSIZE - \*\*Number of lines added to the history file when the user finish his session
* **HOME** – your home directory.
* **HOSTNAME** – the hostname of the computer.
* **LANG** – your current language.
* **MAIL** – the location of the user’s mail spool. Usually **/var/spool/mail/USER**.
* **MANPATH** – the list of directories to search for manual pages.
* **OSTYPE** – the type of operating system.
* **PS1** – the default prompt in bash.
* \*\*PATH - \*\*stores the path of all the directories which holds binary files you want to execute just by specifying the name of the file and not by relative or absolute path.
* **PWD** – the current working directory.
* **SHELL** – the path to the current command shell (for example, **/bin/bash**).
* **TERM** – the current terminal type (for example, **xterm**).
* **TZ** – your time zone.
* **USER** – your current username.

## Interesting variables for hacking

### **HISTFILESIZE**

Change the **value of this variable to 0**, so when you **end your session** the **history file** (\~/.bash\_history) **will be deleted**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Change the **value of this variable to 0**, so when you **end your session** any command will be added to the **history file** (\~/.bash\_history).

```bash
export HISTSIZE=0
```

### http\_proxy & https\_proxy

The processes will use the **proxy** declared here to connect to internet through **http or https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### SSL\_CERT\_FILE & SSL\_CERT\_DIR

The processes will trust the certificates indicated in **these env variables**.

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### PS1

Change how your prompt looks.

I have created [**this one**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808) (based on another, read the code).

Root:

![](<../.gitbook/assets/image (87).png>)

Regular user:

![](<../.gitbook/assets/image (88).png>)

One, two and three backgrounded jobs:

![](<../.gitbook/assets/image (89).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
