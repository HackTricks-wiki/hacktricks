# Linux Environment Variables

## Global variables

The **global variables** will be **inherited** by **child processes**.

You can create a Global variable for your current session doing:

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

* _**/etc/bash.bashrc**_ ****: This file is read whenever an interactive shell is started \(normal terminal\) and all the commands specified in here are executed.
* _**/etc/profile and /etc/profile.d/\***_**:** This file is read every time a user logs in. Thus all the commands executed in here will execute only once at the time of user logging in.
  * **Example:** 

    `/etc/profile.d/somescript.sh`

    ```bash
    #!/bin/bash
    TEST=$(cat /var/somefile)
    export $TEST
    ```

#### **Files that affect behavior for only a specific user:**

* _**~/.bashrc**_ **:** This file behaves the same way _/etc/bash.bashrc_ file works but it is executed only for a specific user. If you want to create an environment for yourself go ahead and modify or create this file in your home directory.
* _**~/.profile, ~/.bash\_profile, ~/.bash\_login**_**:** These files are same as _/etc/profile_. The difference comes in the way it is executed. This file is executed only when a user in whose home directory this file exists, logs in.

**Extracted from:** [**here**](https://codeburst.io/linux-environment-variables-53cea0245dc9) **and** [**here**](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)\*\*\*\*

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – the display used by **X**. This variable is usually set to **:0.0**, which means the first display on the current computer.
* **EDITOR** – the user’s preferred text editor.
* **HISTFILESIZE** – the maximum number of lines contained in the history file.
* **HISTSIZE -** Number of lines added to the history file when the user finish his session
* **HOME** – your home directory.
* **HOSTNAME** – the hostname of the computer.
* **LANG** – your current language.
* **MAIL** – the location of the user’s mail spool. Usually **/var/spool/mail/USER**.
* **MANPATH** – the list of directories to search for manual pages.
* **OSTYPE** – the type of operating system.
* **PS1** – the default prompt in bash.
* **PATH -** stores the path of all the directories which holds binary files you want to execute just by specifying the name of the file and not by relative or absolute path.
* **PWD** – the current working directory.
* **SHELL** – the path to the current command shell \(for example, **/bin/bash**\).
* **TERM** – the current terminal type \(for example, **xterm**\).
* **TZ** – your time zone.
* **USER** – your current username.

## Interesting variables for hacking

### **HISTFILESIZE**

Change the **value of this variable to 0**, so when you **end your session** the **history file** \(~/.bash\_history\) **will be deleted**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Change the **value of this variable to 0**, so when you **end your session** any command will be added to the **history file** \(~/.bash\_history\).

```bash
export HISTSIZE=0
```

### http\_proxy

The processes will use the **proxy** declared here to connect to internet through **http**.

```bash
export http_proxy="http://10.10.10.10:8080"
```

### https\_proxy

The processes will use the **proxy** declared here to connect to internet through **https**.

```bash
export https_proxy="http://10.10.10.10:8080"
```

### PS1

Change how your prompt looks.

**I have created** [**this one**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808) \(based on another, read the code\).

Root:

![](../.gitbook/assets/image%20%28177%29.png)

Regular user:

![](../.gitbook/assets/image%20%28239%29.png)

One, two and three backgrounded jobs:

![](../.gitbook/assets/image%20%28276%29.png)

One background job, one stopped and last command dind't finish correctly:

![](../.gitbook/assets/image%20%2874%29.png)

