# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

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

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – the display used by **X**. This variable is usually set to **:0.0**, which means the first display on the current computer.
- **EDITOR** – the user’s preferred text editor.
- **HISTFILESIZE** – the maximum number of lines contained in the history file.
- **HISTSIZE** – Number of lines added to the history file when the user finish his session
- **HOME** – your home directory.
- **HOSTNAME** – the hostname of the computer.
- **LANG** – your current language.
- **MAIL** – the location of the user’s mail spool. Usually **/var/spool/mail/USER**.
- **MANPATH** – the list of directories to search for manual pages.
- **OSTYPE** – the type of operating system.
- **PS1** – the default prompt in bash.
- **PATH** – stores the path of all the directories which holds binary files you want to execute just by specifying the name of the file and not by relative or absolute path.
- **PWD** – the current working directory.
- **SHELL** – the path to the current command shell (for example, **/bin/bash**).
- **TERM** – the current terminal type (for example, **xterm**).
- **TZ** – your time zone.
- **USER** – your current username.

## Interesting variables for hacking

### **HISTFILESIZE**

Change the **value of this variable to 0**, so when you **end your session** the **history file** (\~/.bash_history) **will be deleted**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Change the **value of this variable to 0**, so when you **end your session** any command will be added to the **history file** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### http_proxy & https_proxy

The processes will use the **proxy** declared here to connect to internet through **http or https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### SSL_CERT_FILE & SSL_CERT_DIR

The processes will trust the certificates indicated in **these env variables**.

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### PS1

Change how your prompt looks.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}



