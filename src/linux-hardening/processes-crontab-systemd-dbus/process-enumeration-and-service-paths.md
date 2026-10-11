# Uhesabuji wa Michakato na Njia za Huduma

{{#include ../../banners/hacktricks-training.md}}

Swali muhimu ni mchakato gani wenye mapendeleo ya juu hutumia data au msimbo ambao mtumiaji mwenye mapendeleo ya chini anaweza kuathiri. Kagua mti wa michakato, mazingira ya wakati halisi, faili zilizo wazi, na unit au script iliyoanzisha kila mgombea.

## Ramani ya michakato na umiliki

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Uhusiano wa mzazi na mtoto kati ya watumiaji tofauti unaweza kuwa wa kawaida, lakini mabadiliko yasiyotarajiwa yanahitaji ukaguzi wa amri ya mzazi, hoja, executable, saraka ya kufanya kazi na faili zilizorejelewa. Tumia [watumiaji na vipindi](../user-information/user-and-session-triage.md) kutafsiri muktadha wa mmiliki na login.

### Konsole za mashine pepe za ndani

Kagua chaguo za `-spice` za mchakato wa QEMU pamoja na anwani yake ya kusikilizia. [Nyaraka za QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) zinaeleza kuwa `disable-ticketing` huruhusu wateja wa SPICE kuunganisha bila uthibitishaji. Listener iliyofungwa kwa loopback bado inaweza kufikiwa na watumiaji wengine wa host hiyo hiyo. Thibitisha listener inayotumika, chaguo za uthibitishaji na ufikiaji wa ndani kabla ya kuchukulia command line kama console iliyo wazi. Udhibiti wa console huathiri **guest**; kupata akaunti ya guest au kubadilisha hali yake ya boot kunahitaji masharti tofauti upande wa guest, na hakukupi root kwenye host ya virtualization. Soma hoja za mchakato na metadata ya socket bila kuunganisha kwenye au kuwasha upya guest wakati wa passive enumeration.

Kiolesura cha wavuti kinachofikiwa ndani ya mfumo kinaweza kutekeleza code kwa kutumia akaunti ya huduma hata kama shell ya kwanza haiwezi kufikia faili za akaunti hiyo. Kwa mfano, CVE-2023-0297 iliathiri ushughulikiaji wa `/flash/addcrypted2` wa pyLoad wakati JavaScript isiyoaminika ilipofikia Js2Py huku Python imports zikiwa zimewashwa; [marekebisho ya upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) yalizima `pyimport`. Linganisha mmiliki wa mchakato unaoendesha, anwani ya kusikilizia, ufikivu wa endpoint na patch iliyosakinishwa au backport ya vendor kabla ya kuchukulia mchakato wa pyLoad kama njia ya escalation. Jina la mchakato, port iliyo wazi au toleo la package pekee havithibitishi kuwa mfumo uko hatarini; passive enumeration haipaswi kutuma payload ya utekelezaji.

### Interactive shells zenye ruhusa za juu zinazoshiriki terminal

Interactive shell yenye ruhusa za juu inapoendesha `su --login <user>` bila pseudo-terminal tofauti, inaweza kuacha terminal yake ikishirikiwa na login shell yenye ruhusa za chini. Ikiwa faili ya startup ya mtumiaji huyo inaweza kudhibitiwa na code iliyo ndani yake inaweza kutumia `TIOCSTI` kuingiza input ya terminal, input hiyo inaweza kufika kwenye shell yenye ruhusa za juu inapoendelea tena. [Mwongozo wa util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) unaeleza hatari ya terminal inayoshirikiwa na unapendekeza `su --pty`/`-P` kwa matumizi ya interactive; `su -c` huanzisha session tofauti bila terminal ya kuidhibiti. Hatari hii inategemea shell halisi ya mzazi, uhusiano wa terminal, faili lengwa ya startup na sera ya kernel. Jina la mchakato au hoja ya `su -l` pekee ni kidokezo cha kufanyiwa ukaguzi tu.

Kagua process tree iliyoonekana na safu wima za TTY, kisha launcher inayosomeka na umiliki/ruhusa za faili za startup. Kwenye Linux, `/proc/sys/dev/tty/legacy_tiocsti` inaweza kusaidia kutafsiri sera ikiwa ipo; kutokuwepo kwake hakuthibitishi usalama. [Mwongozo wa Linux `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) unabainisha kuwa kuanzia Linux 6.2, operesheni hii inaweza kuhitaji `CAP_SYS_ADMIN` sysctl hii ikiwa false. Usiite ioctl kwa madhumuni ya kuorodhesha host.

Akaunti ya database wakati mwingine inaweza kubadilisha faili ya startup ya mtumiaji lengwa bila kuwa na ufikiaji wa moja kwa moja wa kuandika kwenye filesystem. PostgreSQL ya upande wa server `COPY ... TO 'filename'` huandika kwa kutumia akaunti ya OS ya database server, lakini [vikwazo vya PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) huweka matumizi ya aina hii ya faili kwa database superusers au roles kama `pg_write_server_files`. Thibitisha role ya database na ruhusa za faili za OS ya server; connection string ya programu pekee haitoi mamlaka ya kuandika faili. Zichukulie uwezo wa launcher yenye ruhusa za juu na wa akaunti ya database kama vitu tofauti unapokagua mlolongo huo.

## Kagua vitu vya runtime

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Executable zilizofutwa na faili zilizofutwa lakini bado zimefunguliwa hubaki kurejelewa hadi descriptor yake ya mwisho ifungwe. Zinaweza kuhifadhi ushahidi au siri zinazoweza kufikiwa. Mazingira ya process na kumbukumbu zinaweza kuwa na credentials, lakini kusoma process nyingine kunazuiwa na umiliki, chaguo za mount za `/proc`, sera ya Yama ptrace, na vidhibiti vingine vya usalama. Angalia [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) na [uwindaji wa credentials baada ya unyonyaji](../post-exploitation/README.md) kwa mbinu zinazohusiana.

Syscall traces zilizohifadhiwa ni mpaka mwingine wa ruhusa za faili. [`strace` hurekodi arguments za syscall kwenye faili la matokeo](https://man7.org/linux/man-pages/man1/strace.1.html), kwa hiyo trace inayosomeka ya [arguments za `execve`](https://man7.org/linux/man-pages/man2/execve.2.html) inaweza kufichua password ambayo job yenye privileji ilipitisha kwenye command line yake. Kwanza thibitisha kwamba mtumiaji wa sasa anaweza kusoma trace husika na kwamba argument hiyo kweli ina credential; mabadiliko ya baadaye ya akaunti ya Unix yanahitaji uthibitisho tofauti kwamba credential hiyo inakubaliwa huko. Metadata ya faili ni kidokezo muhimu kisichohitaji kuingilia, bila kuchanganua kila trace au kuchapisha yaliyomo wakati wa enumeration ya kawaida.

## Soketi za office automation zenye privileji

LibreOffice na OpenOffice zinaweza kufichua UNO API yao kupitia argument ya `--accept=socket,host=<host>,port=<port>;urp;`. Process ya office inayomilikiwa na root yenye endpoint inayoweza kufikiwa inaweza kumruhusu mtumiaji wa ndani mwenye privileji za chini kuita huduma za API katika muktadha wa usalama wa process hiyo. Huduma ya `SystemShellExecute` inajumuisha operesheni ya kuzindua command ya mfumo. Kufunga kwenye loopback huzuia ufikikaji wa mbali lakini bado huacha soketi ikifikika kwa watumiaji wa ndani isipokuwa udhibiti mwingine uzuie ufikikaji huo.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Linganisha mmiliki wa mchakato, argumenti halisi ya `--accept`, na anwani na porti inayosikiliza kwa sasa. Acceptor iliyosanidiwa lakini imeshindwa kufunga porti ni kidokezo tu; usiunganishe wala kuita API wakati wa enumeration tulivu. Epuka kuanzisha instance ya office yenye mapendeleo ya juu kwa lengo la kujaribu hali hii tu.

## Kumbukumbu ya pamoja ya System V inayotumiwa na michakato yenye mapendeleo ya juu

Helper inayomilikiwa na root inaweza kuunda segmenti ya kumbukumbu ya pamoja ya System V ambayo mtumiaji mwingine anaweza kuiandikia. Ikiwa baadaye helper hiyo itaamini data kutoka kwenye segmenti hiyo katika amri ya shell au operesheni nyingine nyeti, segmenti hiyo inavuka mpaka wa mapendeleo hata kama executable na faili zake zinalindwa. `shmget()` hupata ruhusa za ufikiaji kutoka kwenye biti tisa za chini za flags zake; mode `0666` huruhusu watumiaji wengine kuandika, ilhali flag ya `IPC_CREAT` haipunguzi ruhusa hizo. Kagua segmenti zinazotumika kwa namna tulivu ukitumia `ipcs -m` na ulinganishe mmiliki, mode, na muda wa kuwepo kwake na mchakato wenye mapendeleo ya juu pamoja na namna unavyoshughulikia ingizo. Segmenti inayoweza kuandikwa na kila mtu peke yake haithibitishi utekelezaji wa amri.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

Sehemu za System V ni tofauti na faili za POSIX shared-memory zilizo chini ya `/dev/shm`. Segment iliyoundwa kwa muda mfupi tu huenda isiwepo kwenye matokeo ya `ipcs` ya wakati mmoja, kwa hiyo matokeo matupu hayaondoi uwezekano kwamba helper hutumia shared memory. Kagua source yake au tabia ya binary yake, pamoja na sheria yoyote ya `sudo` inayoizindua; usiendeshe helper yenye mamlaka ya juu kwa lengo la kuifanya segment ionekane wakati wa kuorodhesha. [Mwongozo wa IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) unaeleza jinsi namespaces zinavyoathiri kinachoonekana.<sup>[[2]](#references)[[3]](#references)</sup>

## Ukaguzi wa script za Consul agent

Consul inaweza kuendesha ukaguzi wa afya wa script kwa kutumia utambulisho wa mfumo wa uendeshaji wa agent wake. Ikiwa agent inaendeshwa kama root, imewasha `enable_script_checks`, na inamruhusu mtumiaji mwenye mamlaka ya chini kusajili huduma yenye ukaguzi wa script kupitia local HTTP API, mtumiaji huyo anaweza kusababisha amri zinazoendeshwa kama root. Kufunga API kwenye `127.0.0.1` pekee bado kunawawezesha watumiaji wa ndani kuifikia. Setting ya `enable_local_script_checks` ina wigo finyu zaidi: haijumuishi ukaguzi wa script unaowasilishwa kupitia usajili wa HTTP API. ACL za Consul zinapowashwa, usajili wa huduma huhitaji `service:write`; mstari wa `acl.default_policy=allow` peke yake hauthibitishi kuwa mpigaji asiye na utambulisho anaweza kusajili huduma. Kagua utambulisho halisi wa agent, settings zilizopakiwa, binding ya API, na ruhusa kwa pamoja.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Fuata hoja za `-config-dir` na `-config-file` za agent inayoendelea kufanya kazi hadi kwenye configuration husika, kisha kagua majina na mipangilio ya sehemu za script-check na ACL pekee. Faili za configuration zinaweza pia kuwa na gossip keys au tokens; epuka kuzinakili kwenye shared logs. Usisajili service au kuendesha health check kwa lengo la kuorodhesha hali hii pekee.

Njia tofauti ya kutumia faili za ndani ipo pale mtumiaji mwenye ruhusa za chini anapoweza **kuandika na kutafuta** kwenye directory iliyotajwa na `-config-dir` ya agent inayoendeshwa kama root: service definition mpya ya `.hcl` au `.json` inaweza kupakiwa kutoka kwenye directory hiyo. Ruhusa za kutafuta na kuandika kwenye directory zinaweza kuruhusu kuongeza faili hata kama ruhusa za kuorodhesha yaliyomo kwenye directory zimezuiwa. Ili kuthibitisha utekelezaji wa command kama root, hakikisha agent inapakia directory hiyo, mpangilio wake **unaotumika kwa sasa** wa script-check unaruhusu local definitions, definition hiyo imepakiwa, na agent inaendelea kuwa na ruhusa za root. [Consul inaeleza](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) mipangilio na health-check definitions zinazoweza kupakiwa upya; kuwasha script checks kunaweza kuhitaji restart, kwa hivyo thibitisha tabia ya toleo lililosakinishwa. ACLs zinapolinda agent, [`consul reload` inahitaji `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); ruhusa ya KV write pekee haitoi ruhusa hiyo. Chukulia metadata ya directory inayoweza kuandikwa kama ishara ya kuchunguza, si uthibitisho wa reload, restart au utekelezaji wa command ulioidhinishwa. Kagua paths, permissions na policy bila kuandika configuration au kuita API.

## Fuata mnyororo wa utekelezaji wa service

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Kagua unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories, na socket activation. Unit inayomilikiwa na root bado inaweza kuwa si salama ikiwa inasoma config au script inayoweza kuandikwa na mtumiaji. Ukurasa wa [arbitrary file write](../interesting-files-permissions/write-to-root.md) unaeleza njia za kawaida za kutumia vibaya service na unit. Fuatilia kazi za muda mfupi kwa [pspy](https://github.com/DominicBreuker/pspy) au telemetry ya audit/process wakati orodha ya mara moja ya `ps` inapozikosa.

Kwa service maalum ya **xinetd**, linganisha `server`, `user`, na vidhibiti vya ufikiaji vya stanza iliyowezeshwa na listener inayoendelea na executable halisi. Mpangilio wa [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) huchagua utambulisho wa process inayozinduliwa, huku set-user-ID bit kwenye executable inaweza kubadilisha kivyake utambulisho wake effective ikiwa [`execve` inaruhusu mabadiliko hayo](https://man7.org/linux/man-pages/man2/execve.2.html). Binary yenye ruhusa za juu inayoweza kufikiwa na inayokubali ingizo lisiloaminika inafaa kuchunguzwa offline kupitia source au disassembly ili kutafuta hitilafu za memory-safety, kama [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) isiyo na kikomo inayoandika kwenye buffer yenye ukubwa maalum. Ulinganifu wa service na metadata ya set-user-ID ni vidokezo vya kuchunguza, si uthibitisho wa hitilafu hiyo; usitume ingizo linalosababisha crash wala kufanya debug ya service hai yenye ruhusa za juu wakati wa enumeration tulivu.

Kwa listener maalum yenye ruhusa za juu na source inayosomeka, kagua kila urefu unaodhibitiwa na caller unaotumika kwenye operesheni ya copy kama [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Kuhakikisha tu kwamba index ya sasa ya write iko ndani ya buffer isiyobadilika hakuthibitishi kwamba **urefu wa copy** unatoshea nafasi iliyobaki; thibitisha `copy_length <= capacity - index` baada ya kuhakikisha index iko ndani ya mipaka, na kagua signedness na arithmetic overflow. Hiki ni kidokezo cha ukaguzi tu ikiwa ingizo linafika kwenye operesheni hiyo, listener inaweza kufikiwa na mtumiaji mwenye ruhusa za chini, na process inaendelea kuwa na utambulisho wa juu wa effective. Kagua source na metadata ya process offline; usitume ingizo linalosababisha crash kwenye service hai wakati wa enumeration.

Kwenye mifumo inayotumia **Upstart**, ufafanuzi wa system job unaweza kuwa chini ya `/etc/init/*.conf`. Faili ya job inayoweza kuandikwa na mtumiaji wa sasa ni muhimu pale tu ambapo init daemon inayotumika inapakia job hiyo hasa, stanza yake ya `script` au `exec` inaendeshwa kwa utambulisho wenye ruhusa za juu, na mtumiaji anaweza kuianzisha kupitia amri ya `initctl` inayoruhusiwa au trigger nyingine halisi. Ruhusa ya sudo ya `initctl` pekee haithibitishi kwamba faili yoyote ya job inaweza kuandikwa au kwamba job iliyobadilishwa itaendeshwa. Kagua ruhusa za faili husika ya job, mpangilio wa run-as unaotumika, daemon hai, na trigger bila kuhariri au kuanzisha job wakati wa enumeration. Tazama miongozo ya [usanidi wa Upstart job](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) na [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Faili ya nenosiri la autologin inayosomeka, kama `/etc/autologin/passwd` kwenye mifumo ambayo [boot job husoma njia hiyo hasa](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), ni kidokezo cha kufichuka kwa credentials. Thibitisha kwamba boot job imesakinishwa na inatumia faili hiyo, kisha hakikisha kando kama nenosiri hilo ni halali kwa akaunti au service nyingine ya ndani. Jina la faili pekee halithibitishi matumizi tena ya nenosiri; rekodi metadata ya njia na ufikiaji bila kuweka nenosiri kwenye matokeo ya enumeration yanayoshirikiwa.

`ExecStart=` ya unit au amri iliyoratibiwa inaweza kufichua pathname halisi ya script iliyo ndani ya directory isiyoweza kuorodheshwa. [Ruhusa ya kutafuta kwenye directory](https://man7.org/linux/man-pages/man7/path_resolution.7.html) bado inaweza kuruhusu utambulisho wa sasa kufuata njia hiyo inayojulikana; thibitisha ruhusa ya kutafuta kwenye kila parent na ruhusa ya kusoma faili badala ya kudhani kwamba kushindwa kuorodhesha directory kunailinda. Script inayosomeka inaweza kuwa na credential ya uhamishaji, lakini kutumia credential hiyo kwa akaunti nyingine kunahitaji ibaki halali na ikubalike kivyake huko. Rekodi njia na ushahidi wa ruhusa bila kuchapisha thamani za siri kwenye logs zinazoshirikiwa.

Kwa script ya CommonJS Node.js iliyoratibiwa, kagua bare imports kama `require('package')` hata kama script yenyewe ni ya kusoma tu. [Node hutafuta `node_modules` karibu na faili inayo-import kisha kwenye directories zake za ancestor](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), kabla ya kutumia njia za global zilizosanidiwa. Mtumiaji mwenye ruhusa za chini anayeweza **kuandika na kutafuta** kwenye mojawapo ya directories hizo za ancestor anaweza kuunda package itakayolingana mapema. Thibitisha kwamba import halisi inafikiwa, package iliyochaguliwa si built-in module, njia husika inaweza kuundwa au kubadilishwa, module inatatuliwa hapo kwenye runtime iliyosakinishwa, na job yenye ruhusa za juu itaipakia kwenye uendeshaji ujao. Metadata ya parent inayoweza kuandikwa ni kidokezo cha ukaguzi tu; kagua script na scheduler bila kuibadilisha, bila kuweka module, wala kuanzisha job.

Private Python package index ni mpaka mwingine wa uaminifu wakati job ya kiotomatiki inasakinisha packages kwa utambulisho tofauti wa OS. Linganisha job halisi na akaunti yake ya run-as na index iliyosanidiwa, majina ya packages zilizochaguliwa, na kama mtumiaji mwenye ruhusa za chini anaweza kuchapisha au kubadilisha package ambayo job itaisakinisha kweli. Kujenga source distribution kunaweza kuendesha build backend yake au `setup.py` ya zamani kwa utambulisho wa kisakinishi; ku-import package iliyosakinishwa ni njia tofauti ya utekelezaji. Listener ya index, hash ya nenosiri la upload inayosomeka, au jina la package pekee havithibitishi mnyororo huo. Kagua job, ruhusa za index, na asili ya package bila kupakia au kusakinisha chochote wakati wa enumeration. Tazama [kiolesura cha build-system cha pip](https://pip.pypa.io/en/stable/reference/build-system/) na [mwongozo wa secure-install](https://pip.pypa.io/en/stable/topics/secure-installs/).

Agent yenye ruhusa za juu inaweza kuangalia mara kwa mara task queue inayosimamiwa na web service au container tofauti. Ikiwa utambulisho wenye uaminifu mdogo unaweza kuandika database ya tasks ya service hiyo, bainisha kama rows hizo huhudumiwa kweli kwa agent hiyo na kama command task inaendeshwa kwa utambulisho wa OS wa agent. Thibitisha kando ruhusa ya kuandika database, session lengwa au routing key, polling hai, idhini ya task, na user wa effective wa agent. Kuwa root ndani ya container pekee hakumaanishi ufikiaji wa host-root; mpaka huvukwa tu ikiwa consumer yenye ruhusa za host inaendesha task data inayodhibitiwa na mshambuliaji. Kagua metadata ya process, faili ya database, na service bila kurekebisha queue wala kutuma task wakati wa enumeration.

Job inayojirudia inaweza badala yake kusoma amri kutoka kwenye row ya usanidi wa application database. Thibitisha kwamba role ya database yenye ruhusa za chini inaweza kubadilisha row hiyo hasa, kwamba job hai huisoma baada ya mabadiliko, na kwamba thamani hiyo hufika kwenye shell au command runner inayolingana chini ya utambulisho wa OS wenye ruhusa za juu. Ruhusa ya kuandika database au thamani inayofanana na amri pekee havithibitishi utekelezaji; kagua job na ruhusa bila kubadilisha row wakati wa enumeration tulivu.

Ujumbe uliowekwa kwenye queue unaweza pia kuwa na URL badala ya code. Ikiwa consumer yenye ruhusa za juu inachukua URL hiyo na kupakia jibu kama Lua au plugin nyingine inayoweza kutekelezwa, thibitisha ruhusa za publisher kwenye exchange na routing key husika, binding kwenye queue inayotumiwa, njia ya kuchukua na kupakia plugin, na utambulisho wa effective wa worker. [RabbitMQ huelekeza ujumbe uliochapishwa kupitia exchanges](https://www.rabbitmq.com/docs/exchanges); listener ya broker au login halali pekee havithibitishi kwamba ujumbe utawasilishwa kwa worker huyu. Credentials za broker zilizonaswa zikiwa wazi ni kidokezo tofauti kinachohitaji ufikiaji halisi wa packet capture na traffic inayosomeka; hazithibitishi ruhusa ya publish. Lua plugin inaweza kuendesha amri za shell kupitia [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) ikiwa tu API hiyo inapatikana kwenye runtime yake. Kagua usanidi na code bila kunasa traffic, kuchapisha ujumbe, au kuchukua plugin wakati wa enumeration tulivu.

Service ya Python yenye ruhusa za juu inapofichua endpoint ya HTTP au socket ya ndani, script inayosomeka inaweza kufichua njia kutoka ingizo hadi code hata kama ruhusa za faili haziruhusu kuibadilisha. Linganisha process na utambulisho wa unit unaotumika na script halisi, listener, idhini ya route, na fields zinazodhibitiwa na caller. Kisha fuatilia fields hizo kwenye parsing na validation hadi kwenye sink ya `eval()` au `exec()` inayobadilika. Hasa, kujenga f-string mpya kutoka kwenye maandishi ya request na kuifanyia evaluation kunaweza kutafsiri replacement fields zinazotolewa na mshambuliaji kama Python expressions ([onyo la Python kuhusu `eval`](https://docs.python.org/3/library/functions.html#eval); [semantics za f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Kulingana tu na match ya `eval` au binding ya loopback hakuthibitishi kwamba caller asiyeaminika anaifikia sink; kagua dataflow halisi na vidhibiti vya ufikiaji bila kutuma test payload wakati wa enumeration.

Lango la signed-request kwenye route hiyo linahitaji ukaguzi wake pia. Ikiwa source inayosomeka inazalisha signing key kupitia nafasi ya matokeo iliyo ndogo au inayotabirika kwa namna inayoweza kuthibitishwa, na service inatoa sample halali iliyosainiwa, huenda sahihi hiyo isiilinde tena sink ya `eval()` yenye ruhusa za juu. Thibitisha key derivation na verifier halisi, utambulisho wa service hai na ufikiaji wa caller wa ndani, na kama field iliyosainiwa hufika kwenye sink; import ya Python ya [`random` module](https://docs.python.org/3/library/random.html) au sample signature pekee havithibitishi masharti hayo. Python pia inaonya kwamba kuzuia `__builtins__` [si mpaka wa usalama kwa ingizo lisiloaminika la `eval()`](https://docs.python.org/3/library/functions.html#eval). Changanua key offline na usitume requests za kughushi wakati wa enumeration tulivu.

Directory tupu lakini inayoweza kuandikwa ya `/etc/systemd/system/<unit>.service.d` ni muhimu hata kama faili ya unit na drop-in zote zilizopo zinalindwa: mtumiaji anaweza kuunda override mpya ya `.conf`. Kagua kama directory inaweza kuandikwa na kutafutwa na utambulisho wa sasa, kama unit imepakiwa na inaendeshwa kama root, na kama daemon reload ikifuatiwa na restart itafanyika. Ruhusa ya reload au restart, timer, au boot ya baadaye inaweza kufanya mabadiliko yaanze kutumika; ruhusa ya kuandika directory pekee haiyaendeshi mara moja.

Kwa services zinazoendelea, fuata njia halisi za `EnvironmentFile=` kutoka sehemu ya `[Service]` ya unit, ikijumuisha faili ambazo majina yake hayaanzi na `.env`. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma mojawapo, orodhesha majina ya keys zinazofanana na credentials, kama `API_TOKEN` au `APP_SECRET_KEY`, bila kuchapisha thamani zake kwenye logs zinazoshirikiwa. Kagua drop-in overrides na viambishi awali vya `-` vya hiari unapobainisha unit inayotumika. Kusomeka kwake ni kidokezo cha kufichuka kwa credentials; thamani hiyo bado lazima iwe halali kwa kitendo chenye ruhusa za juu ili kuleta privilege escalation.

### Uchakataji wa uploads zisizoaminika wenye ruhusa za juu

File watcher inayoendeshwa kama root inaweza kukabidhi faili kutoka kwenye upload directory inayoweza kuandikwa na mtumiaji kwa parser au extractor ya muda mfupi. Fuata parent script au service ya watcher inayoendelea na uthibitishe directory halisi, nani anayeweza kuweka faili humo, amri ya child na arguments zake, na utambulisho ambao child inaendeshwa nao. Picha ya process inaweza kuonyesha watcher lakini ikakosa extractor inayofanya kazi kati ya uploads. Usiweke test payload wala kuanzisha watcher wakati wa enumeration tulivu.

Mfano mmoja halisi ni hali ya extraction ya Binwalk (`-e`) inayochakata data ya PFS inayodhibitiwa na mshambuliaji. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) iliruhusu PFS extractor kuandika nje ya directory iliyokusudiwa, ikijumuisha njia ya plugin ambayo Binwalk ingeweza kuipakia baadaye. Upstream ilijumuisha marekebisho hayo katika [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), lakini backports za distributions zinaweza kuhifadhi toleo la zamani linaloonyeshwa; kagua hali ya usalama ya package iliyosakinishwa, kama vile [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510), kabla ya kutathmini kama inatumika. Toleo la Binwalk lililosakinishwa pekee halithibitishi njia ya privilege escalation: extraction lazima ianzishwe kweli na process yenye ruhusa za juu zaidi kwenye ingizo ambalo mtumiaji mwenye ruhusa za chini anaweza kulidhibiti.

### Builds zilizoratibiwa zenye dependencies za ndani

`cargo run` iliyoratibiwa hukompile upya source kwa mtumiaji wa run-as wa job. Kagua dependencies za ndani za `{ path = "..." }` kwenye manifest na ruhusa za source na parent-directory za kila dependency, si crate kuu pekee. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kubadilisha dependency ambayo Cargo inakompile na job iliyoratibiwa inaendesha matokeo yake, code iliyokompilewa inaweza kuendeshwa kama mtumiaji huyo wa run-as. Thibitisha amri halisi ya scheduler, working directory, utatuzi wa dependencies, na kama rebuild itafanyika; faili ya Rust source inayoweza kuandikwa mahali pengine ni kidokezo tu. Kusoma manifest na metadata ya njia kunatosha kwa triage tulivu. Tazama [nyaraka za Cargo kuhusu path-dependency](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Faili za framebuffer za Xvfb

`Xvfb -fbdir <directory>` hutumia faili za memory-mapped zinazoitwa `Xvfb_screen<n>` kwa virtual screens zake. Ikiwa process ya Xvfb inayoendeshwa na mtumiaji mwingine inataja directory ambayo faili zake za screen zinaweza kusomwa na mtumiaji wa sasa, framebuffer inaweza kufichua maudhui ya desktop ya mtumiaji huyo. Thibitisha process, umiliki wa faili, na ruhusa zake kwa pamoja; faili inayosomeka peke yake haithibitishi kwamba kuna maudhui yenye manufaa kwenye screen. Kagua njia na metadata kwanza, bila kunakili data ya picha kwenye matokeo ya enumeration yanayoshirikiwa. [Mwongozo wa Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) unaeleza tabia ya `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Mwongozo wa Linux `shmget(2)`](https://man7.org/linux/man-pages/man/man2/shmget.2.html)
2. [Mwongozo wa Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Mwongozo wa OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Usanidi wa Consul agent: ukaguzi wa script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API ya usajili wa huduma ya Consul agent](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Usanidi wa Consul ACL](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Msaada wa LibreOffice: kufungua socket kwa wateja wa API wa nje](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
