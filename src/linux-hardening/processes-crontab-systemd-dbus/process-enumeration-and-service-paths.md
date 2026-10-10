# Uhesabuji wa Processes na Njia za Huduma

{{#include ../../banners/hacktricks-training.md}}

Swali muhimu ni process ipi yenye privileges hutumia data au code ambayo mtumiaji mwenye privileges za chini anaweza kuathiri. Kagua mti wa processes, mazingira ya sasa, files zilizo wazi, na unit au script iliyoanzisha kila mgombea.

## Panga processes na umiliki

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Uhusiano wa mzazi na mtoto kati ya watumiaji tofauti unaweza kuwa wa kawaida, lakini mabadiliko yasiyotarajiwa yanahitaji ukaguzi wa amri ya mzazi, hoja, executable, saraka ya kufanya kazi na faili zilizorejelewa. Tumia [watumiaji na vipindi vya kuingia](../user-information/user-and-session-triage.md) kutafsiri mmiliki na muktadha wa login.

### Konsoli za mashine pepe za ndani

Kagua chaguo za `-spice` za process ya QEMU pamoja na anwani yake ya kusikiliza. [Nyaraka za QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) zinaeleza kuwa `disable-ticketing` huruhusu wateja wa SPICE kuunganishwa bila uthibitishaji. Listener iliyofungwa kwenye loopback bado inaweza kufikiwa na watumiaji wengine wa ndani wa host. Thibitisha listener inayotumika, chaguo za uthibitishaji na ufikiaji wa ndani kabla ya kuichukulia command line kama konsoli iliyo wazi kwa wengine. Udhibiti wa konsoli huathiri **guest**; kupata akaunti ya guest au kubadilisha hali yake ya boot kunahitaji masharti tofauti upande wa guest, na hakukupi root kwenye host ya virtualization. Soma hoja za process na metadata ya socket bila kuunganishwa na guest au kuianzisha upya wakati wa passive enumeration.

Kiolesura cha wavuti kinachofikiwa ndani kinaweza kutekeleza code kwa kutumia akaunti yake ya service hata kama shell ya kwanza haiwezi kufikia faili za akaunti hiyo. Kwa mfano, CVE-2023-0297 iliathiri ushughulikiaji wa `/flash/addcrypted2` wa pyLoad pale JavaScript isiyoaminika ilipofikia Js2Py huku imports za Python zikiwa zimewashwa; [marekebisho ya upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) yalizima `pyimport`. Linganisha mmiliki wa process inayoendeshwa, anwani ya kusikiliza, ufichuaji wa endpoint na patch iliyosakinishwa au backport ya vendor kabla ya kuichukulia process ya pyLoad kama njia ya escalation. Jina la process, port iliyo wazi au toleo la package pekee havithibitishi ufichuaji; passive enumeration haipaswi kutuma payload ya utekelezaji.

### Shell za login zenye privileged zinazoshiriki terminal

Shell shirikishi yenye privileged inapoendesha `su --login <user>` bila pseudo-terminal huru, inaweza kuacha terminal yake ikishirikiwa na shell ya login yenye privileged ya chini. Ikiwa startup file ya mtumiaji huyo inaweza kudhibitiwa na code ndani yake inaweza kutumia `TIOCSTI` kuingiza ingizo la terminal, ingizo hilo linaweza kufikia shell yenye privileged inapoanza tena. [Mwongozo wa `su` wa util-linux](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) unaeleza hatari ya terminal inayoshirikiwa na unapendekeza `su --pty`/`-P` kwa matumizi shirikishi; `su -c` huanzisha session tofauti bila terminal inayodhibiti. Hatari hii hutegemea shell halisi ya mzazi, uhusiano wa terminal, startup file lengwa na sera ya kernel. Jina la process au hoja ya `su -l` pekee ni ishara tu inayohitaji ukaguzi.

Kagua process tree iliyoonekana na safu za TTY, kisha launcher inayosomeka na umiliki/ruhusa za startup file. Kwenye Linux, `/proc/sys/dev/tty/legacy_tiocsti` inaweza kusaidia kutafsiri sera ikiwa ipo; kutokuwepo kwake hakuthibitishi usalama. [Mwongozo wa Linux wa `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) unasema kuwa tangu Linux 6.2, operesheni hiyo inaweza kuhitaji `CAP_SYS_ADMIN` wakati sysctl hii ni false. Usiite ioctl hii kwa madhumuni ya kuorodhesha host.

Wakati mwingine akaunti ya database inaweza kubadilisha startup file ya mtumiaji lengwa bila kuwa na ufikiaji wa moja kwa moja wa kuandika kwenye filesystem. `COPY ... TO 'filename'` ya upande wa server wa PostgreSQL huandika kwa kutumia akaunti ya OS ya server ya database, lakini [vikwazo vya PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) huruhusu aina hii ya faili kwa database superusers au roles kama `pg_write_server_files` pekee. Thibitisha role ya database na ruhusa za faili za OS ya server; connection string ya application pekee haitoi mamlaka ya kuandika faili. Tathmini launcher yenye privileged na uwezo wa akaunti ya database kama vitu tofauti unapochunguza mnyororo huu.

## Kagua vitu vya runtime

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Faili zinazoweza kutekelezwa zilizofutwa na faili zilizofutwa lakini bado ziko wazi hubaki zikiwa zimerejelewa hadi descriptor yake ya mwisho ifungwe. Zinaweza kuhifadhi ushahidi au siri zinazoweza kufikiwa. Mazingira na kumbukumbu ya mchakato zinaweza kuwa na credentials, lakini kusoma mchakato mwingine huzuiliwa na umiliki, chaguo za `/proc` mount, sera ya Yama ptrace na vidhibiti vingine vya usalama. Tazama [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) na [post-exploitation credential hunting](../post-exploitation/README.md) kwa mbinu zinazohusiana.

Alama zilizohifadhiwa za syscall pia ni mpaka wa ruhusa za faili. [`strace` hurekodi hoja za syscall kwenye faili ya matokeo](https://man7.org/linux/man-pages/man1/strace.1.html), kwa hiyo alama inayoweza kusomwa ya hoja za [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) inaweza kufichua nenosiri ambalo kazi yenye mamlaka ya juu ilipitisha kwenye mstari wake wa amri. Kwanza thibitisha kuwa mtumiaji wa sasa anaweza kusoma alama hiyo mahususi na kwamba hoja hiyo ina credential kweli; mabadiliko ya baadaye ya akaunti ya Unix yanahitaji uthibitisho tofauti kwamba credential hiyo inakubaliwa huko. Metadata ya faili ni kidokezo muhimu kisichoingilia mfumo, bila kuchanganua kila alama au kuchapisha yaliyomo wakati wa enumerating ya kawaida.

## Soketi za office automation zenye mamlaka ya juu

LibreOffice na OpenOffice zinaweza kufichua UNO API yake kupitia hoja ya `--accept=socket,host=<host>,port=<port>;urp;`. Mchakato wa office unaomilikiwa na root wenye endpoint inayoweza kufikiwa unaweza kumruhusu mtumiaji wa ndani mwenye mamlaka ya chini kuita huduma za API katika muktadha wa usalama wa mchakato huo. Huduma ya `SystemShellExecute` inajumuisha operesheni ya kuzindua amri ya mfumo. Kufungia kwenye loopback hupunguza ufikikaji wa mbali, lakini bado huacha socket ikifikika kwa watumiaji wa ndani isipokuwa udhibiti mwingine uzuie ufikiaji.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Linganisha mmiliki wa mchakato, argumenti halisi ya `--accept`, na anwani pamoja na port inayosikiliza kwa sasa. Acceptor iliyosanidiwa lakini imeshindwa kufunga port ni kidokezo tu; usiunganishe wala kuita API wakati wa enumerating kwa njia passivu. Epuka kuanzisha instance ya office yenye privileges kwa lengo la kujaribu hali hii.

## System V shared memory inayotumiwa na michakato yenye privileges

Helper inayomilikiwa na root inaweza kuunda segment ya System V shared memory ambayo mtumiaji mwingine anaweza kuiandikia. Ikiwa baadaye helper hiyo itaamini data kutoka kwenye segment hiyo katika amri ya shell au operesheni nyingine nyeti, segment hiyo inavuka mpaka wa privileges hata kama executable na faili zake zinalindwa. `shmget()` hupata ruhusa za ufikiaji kutoka kwenye biti tisa za chini za flags zake; mode `0666` huruhusu watumiaji wengine kuandika, ilhali flag ya `IPC_CREAT` haipunguzi ruhusa hizo. Kagua segments zinazotumika bila kuzibadilisha kwa `ipcs -m`, kisha linganisha mmiliki, mode na muda wa kuwepo kwake na mchakato wenye privileges pamoja na jinsi unavyoshughulikia ingizo. Segment inayoweza kuandikwa na kila mtu peke yake haithibitishi utekelezaji wa amri.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments ni tofauti na faili za POSIX shared memory zilizo chini ya `/dev/shm`. Segment iliyoundwa kwa muda mfupi tu inaweza isiwepo kwenye matokeo ya `ipcs` ya wakati mmoja, kwa hivyo matokeo matupu hayathibitishi kuwa helper inayotumia shared memory haina tatizo. Kagua source code au tabia ya binary yake, pamoja na sheria yoyote ya `sudo` inayoizindua; usiendeshe helper yenye privilege ili tu kufanya segment ionekane wakati wa enumeration. [Mwongozo wa IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) unaeleza jinsi namespaces zinavyoathiri kinachoonekana.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul inaweza kuendesha script za health check kwa utambulisho wa mfumo wa uendeshaji wa agent wake. Ikiwa agent inaendeshwa kama root, imewasha `enable_script_checks`, na inamruhusu mtumiaji asiye na privilege kubwa kusajili service yenye script check kupitia local HTTP API, mtumiaji huyo anaweza kusababisha amri zinazoendeshwa kama root. Kufunga API kwenye `127.0.0.1` pekee bado kunaruhusu watumiaji wa ndani kuifikia. Setting ya `enable_local_script_checks` ina wigo mwembamba zaidi: haijumuishi script checks zinazotumwa kupitia usajili wa HTTP API. ACL za Consul zikiwashwa, usajili wa service unahitaji `service:write`; mstari wa `acl.default_policy=allow` peke yake hauthibitishi kuwa caller asiye na uthibitishaji anaweza kusajili service. Kagua utambulisho halisi wa agent, settings zilizopakiwa, binding ya API, na authorization kwa pamoja.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Fuata hoja za `-config-dir` na `-config-file` za agent inayoendesha hadi kwenye usanidi husika, kisha kagua majina na mipangilio ya sehemu za script-check na ACL pekee. Faili za usanidi zinaweza pia kuwa na funguo au tokeni za gossip; epuka kuzinakili kwenye kumbukumbu zinazoshirikiwa. Usisajili huduma wala kuendesha ukaguzi wa afya kwa lengo la kuorodhesha hali hii pekee.

Kuna njia tofauti kupitia faili za ndani wakati mtumiaji mwenye mapendeleo ya chini anaweza **kuandika na kutafuta ndani ya** saraka iliyotajwa na `-config-dir` ya agent inayoendeshwa kama root: ufafanuzi mpya wa huduma wa `.hcl` au `.json` unaweza kupakiwa kutoka kwenye saraka hiyo. Ruhusa za kutafuta ndani ya saraka na kuandika zinaweza kuruhusu kuongeza faili hata kama ruhusa ya kuorodhesha saraka imekataliwa. Ili kuthibitisha utekelezaji wa amri kama root, thibitisha kwamba agent kwa kweli hupakia saraka hiyo, mpangilio wake **halisi** wa script-check huruhusu ufafanuzi wa ndani, ufafanuzi huo umepakiwa, na agent huhifadhi mapendeleo ya root. [Nyaraka za Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) zinaeleza mipangilio na ufafanuzi wa ukaguzi wa afya unaoweza kupakiwa upya; kuwezesha script checks yenyewe kunaweza kuhitaji kuwasha upya, kwa hiyo thibitisha tabia ya toleo lililosakinishwa. ACL zinapolinda agent, [`consul reload` inahitaji `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); ruhusa ya kuandika kwenye KV pekee haitoi ruhusa hiyo. Chukulia metadata ya saraka inayoweza kuandikwa kuwa ishara ya kukagua, si uthibitisho wa ruhusa ya kupakia upya, kuwasha upya, au kutekeleza amri. Kagua njia, ruhusa na sera bila kuandika usanidi au kuita API.

## Fuata mnyororo wa utekelezaji wa huduma

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Kagua unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories, na socket activation. Unit inayomilikiwa na root bado inaweza kuwa si salama ikiwa inasoma config au script inayoweza kuandikwa na mtumiaji. Ukurasa wa [arbitrary file write](../interesting-files-permissions/write-to-root.md) unaeleza njia za kawaida za kutumia vibaya service na unit. Fuatilia jobs za muda mfupi kwa kutumia [pspy](https://github.com/DominicBreuker/pspy) au audit/process telemetry wakati orodha ya mara moja ya `ps` inapozikosa.

Kwa service maalum ya **xinetd**, linganisha `server`, `user`, na vidhibiti vya ufikiaji vya stanza iliyowezeshwa na listener inayotumika na executable halisi. Mpangilio wa [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) huchagua utambulisho wa mchakato unaoanzishwa, ilhali set-user-ID bit kwenye executable inaweza kubadilisha utambulisho wake unaotumika kando ikiwa [`execve` inaruhusu mabadiliko hayo](https://man7.org/linux/man-pages/man2/execve.2.html). Binary yenye ruhusa za juu inayoweza kufikiwa na inayokubali ingizo lisiloaminika inafaa kuchunguzwa kupitia source au disassembly nje ya mtandao ili kutafuta bugs za memory-safety, kama [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) isiyo na kikomo inayoandika kwenye buffer yenye ukubwa maalum. Ulinganifu wa service na metadata ya set-user-ID ni vidokezo tu, si uthibitisho wa bug hiyo; usitume ingizo linalosababisha crash wala kutatua hitilafu za service hai yenye ruhusa za juu wakati wa enumeration tulivu.

Kwa listener maalum yenye ruhusa za juu na source inayosomeka, kagua kila urefu unaodhibitiwa na caller unaotumiwa na operesheni ya kunakili kama [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Kuhakikisha tu kwamba faharasa ya sasa ya kuandika iko ndani ya buffer yenye ukubwa maalum hakuthibitishi kwamba **urefu wa kunakili** unatoshea kwenye nafasi iliyobaki; thibitisha `copy_length <= capacity - index` baada ya kuhakikisha faharasa iko ndani ya mipaka, na kagua signedness na arithmetic overflow. Hiki ni kidokezo cha ukaguzi tu ikiwa ingizo linafika kwenye operesheni hiyo, listener inafikiwa na mtumiaji mwenye ruhusa za chini, na mchakato unahifadhi utambulisho unaotumika wenye ruhusa za juu zaidi. Kagua source na metadata ya mchakato nje ya mtandao; usitume ingizo linalosababisha crash kwenye service hai wakati wa enumeration.

Kwenye mifumo inayotumia **Upstart**, ufafanuzi wa system jobs unaweza kupatikana chini ya `/etc/init/*.conf`. Faili ya job inayoweza kuandikwa na mtumiaji wa sasa ni muhimu pale tu ambapo init daemon inayotumika hupakia job hiyo hasa, stanza yake ya `script` au `exec` huendeshwa kwa utambulisho wenye ruhusa za juu zaidi, na mtumiaji anaweza kuianzisha kupitia amri ya `initctl` iliyoruhusiwa au kichocheo kingine halisi. Ruhusa ya sudo ya `initctl` pekee haithibitishi kwamba faili yoyote ya job inaweza kuandikwa au kwamba job iliyobadilishwa itaendeshwa. Kagua ruhusa za faili husika ya job, mpangilio halisi wa run-as, daemon inayotumika, na kichocheo bila kuhariri au kuanzisha job wakati wa enumeration. Tazama miongozo ya [usanidi wa Upstart job](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) na [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Faili ya nenosiri la autologin inayosomeka, kama `/etc/autologin/passwd` kwenye mifumo ambayo [boot job husoma njia hiyo hasa](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), ni kidokezo cha kufichuka kwa credential. Thibitisha kwamba boot job imesakinishwa na inatumia faili hiyo, kisha hakikisha kivyake ikiwa nenosiri hilo ni halali kwa akaunti au service nyingine ya ndani. Jina la faili pekee halithibitishi matumizi tena ya nenosiri; rekodi njia na metadata ya ufikiaji bila kuweka nenosiri kwenye matokeo ya enumeration yanayoshirikiwa.

`ExecStart=` ya unit au amri iliyoratibiwa inaweza kufichua jina kamili la njia ya script iliyo ndani ya directory isiyoweza kuorodheshwa. [Ruhusa ya kutafuta directory](https://man7.org/linux/man-pages/man7/path_resolution.7.html) bado inaweza kuruhusu utambulisho wa sasa kufuata njia hiyo inayojulikana; thibitisha ufikiaji wa kutafuta kwenye kila parent na ruhusa ya kusoma faili badala ya kudhani kuwa kushindwa kuorodhesha directory kunailinda. Script inayosomeka inaweza kuwa na credential ya uhamishaji, lakini kuingia kwenye akaunti nyingine kunahitaji credential hiyo iwe bado halali na ikubaliwe huko kivyake. Rekodi njia na ushahidi wa ruhusa bila kuchapisha thamani za siri kwenye logs zinazoshirikiwa.

Kwa script ya CommonJS Node.js iliyoratibiwa, kagua imports zisizo na njia maalum kama `require('package')` hata ikiwa script yenyewe ni ya kusoma tu. [Node hutafuta `node_modules` karibu na faili inayo-import na kisha kwenye ancestor directories zake](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), kabla ya kutumia njia za global zilizosanidiwa. Mtumiaji mwenye ruhusa za chini anayeweza **kuandika na kutafuta** mojawapo ya ancestor directories hizo anaweza kuunda package itakayolingana mapema. Thibitisha kwamba import hiyo hasa inafikiwa, package iliyochaguliwa si built-in module, njia husika inaweza kuundwa au kubadilishwa, module inapatikana hapo katika runtime iliyosakinishwa, na job yenye ruhusa za juu itapakia module hiyo itakapoendeshwa baadaye. Metadata ya parent inayoweza kuandikwa ni kidokezo cha ukaguzi tu; kagua script na scheduler bila kuanzisha module wala kuchochea job.

Private Python package index ni mpaka mwingine wa uaminifu wakati job ya kiotomatiki inaposakinisha packages kwa utambulisho tofauti wa OS. Linganisha job halisi na akaunti yake ya run-as na index iliyosanidiwa, majina ya packages yaliyochaguliwa, na ikiwa mtumiaji mwenye ruhusa za chini anaweza kuchapisha au kubadilisha package ambayo job itasakinisha kweli. Kuunda source distribution kunaweza kuendesha build backend yake au `setup.py` ya zamani kwa utambulisho wa kisakinishi; ku-import package iliyosakinishwa ni njia tofauti ya utekelezaji. Listener ya index, hash ya nenosiri la kupakia inayosomeka, au jina la faili la package pekee havithibitishi mnyororo huo. Kagua job, ruhusa za index, na asili ya package bila kupakia au kusakinisha chochote wakati wa enumeration. Tazama [kiolesura cha build-system cha pip](https://pip.pypa.io/en/stable/reference/build-system/) na [mwongozo wa usakinishaji salama](https://pip.pypa.io/en/stable/topics/secure-installs/).

Agent yenye ruhusa za juu inaweza kuangalia task queue inayosimamiwa na web service au container tofauti. Ikiwa utambulisho wenye kiwango cha chini cha uaminifu unaweza kuandika kwenye task database ya service, bainisha ikiwa rows hizo hutolewa kweli kwa agent hiyo na ikiwa command task huendeshwa kwa utambulisho wa OS wa agent. Thibitisha kivyake ruhusa ya kuandika kwenye database, session lengwa au routing key, polling inayotumika, ruhusa za task, na mtumiaji halisi wa agent. Root ndani ya container haimaanishi yenyewe ufikiaji wa host-root; mpaka huvukwa tu ikiwa consumer mwenye ruhusa za host hutekeleza data ya task inayodhibitiwa na mshambulizi. Kagua metadata ya mchakato, database file na service bila kubadilisha queue wala kutuma task wakati wa enumeration.

Job inayojirudia inaweza badala yake kusoma amri kutoka kwenye row ya usanidi wa application database. Thibitisha kwamba database role yenye ruhusa za chini inaweza kubadilisha row hiyo hasa, kwamba job inayotumika huisoma baada ya mabadiliko, na kwamba thamani hiyo hufika kwenye shell au command runner sawa chini ya utambulisho wa OS wenye ruhusa za juu zaidi. Ruhusa ya kuandika kwenye database au thamani inayoonekana kama amri pekee havithibitishi utekelezaji; kagua job na ruhusa bila kubadilisha row wakati wa enumeration tulivu.

Ujumbe ulio kwenye queue unaweza pia kuwa na URL badala ya code. Ikiwa consumer mwenye ruhusa za juu huchukua URL hiyo na kupakia jibu kama Lua au plugin nyingine inayotekelezeka, thibitisha ruhusa ya publisher kwenye exchange na routing key husika, binding kwa queue inayotumiwa, njia ya kuchukua na kupakia plugin, na utambulisho halisi wa worker. [RabbitMQ huelekeza ujumbe uliochapishwa kupitia exchanges](https://www.rabbitmq.com/docs/exchanges); listener ya broker au login halali pekee havithibitishi kwamba ujumbe utamfikia worker huyu. Broker credentials zilizonaswa zikiwa cleartext ni kidokezo tofauti kinachohitaji ufikiaji halisi wa packet capture na traffic inayosomeka; hazithibitishi ruhusa ya kuchapisha. Lua plugin inaweza kuendesha amri za shell kupitia [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) ikiwa API hiyo inapatikana kwenye runtime yake pekee. Kagua usanidi na code bila kunasa traffic, kuchapisha ujumbe, au kuchukua plugin wakati wa enumeration tulivu.

Service ya Python yenye ruhusa za juu inapoweka endpoint ya HTTP au socket ya ndani wazi, script inayosomeka inaweza kufichua njia kutoka ingizo hadi code hata ikiwa ruhusa za faili huzuia kuibadilisha. Linganisha utambulisho wa mchakato na unit inayotumika na script, listener, uidhinishaji wa route, na sehemu za data zinazodhibitiwa na caller. Kisha fuatilia sehemu hizo kupitia uchanganuzi na uthibitishaji hadi kwenye sehemu ya `eval()` au `exec()` inayotekeleza code inayobadilika. Hasa, kuunda f-string mpya kutoka kwenye maandishi ya request na kuifanyia evaluation kunaweza kutafsiri replacement fields zilizotolewa na mshambulizi kama Python expressions ([onyo la Python kuhusu `eval`](https://docs.python.org/3/library/functions.html#eval); [maana ya f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Kupata `eval` pekee au binding ya loopback hakuthibitishi kwamba caller asiyeaminika anaifikia sehemu hiyo; kagua mtiririko halisi wa data na vidhibiti vya ufikiaji bila kutuma test payload wakati wa enumeration.

Kizuizi cha signed-request kwenye route hiyo kinahitaji kukaguliwa kivyake. Ikiwa source inayosomeka inaonyesha kwamba signing key hutokana na nafasi ya matokeo ambayo ni ndogo au inaweza kutabirika, na service inatoa mfano halali uliosainiwa, sahihi hiyo huenda isiweze tena kulinda sehemu ya `eval()` yenye ruhusa za juu. Thibitisha derivation halisi ya key na verifier, utambulisho wa service inayotumika na ufikiaji wa caller wa ndani, na ikiwa sehemu iliyosainiwa hufika kwenye sehemu ya utekelezaji; ku-import [`random` module](https://docs.python.org/3/library/random.html) ya Python au kuwa na mfano wa sahihi hakuthibitishi mojawapo ya masharti hayo. Python pia inaonya kwamba kuzuia `__builtins__` [si mpaka wa usalama kwa ingizo lisiloaminika la `eval()`](https://docs.python.org/3/library/functions.html#eval). Changanua key nje ya mtandao na usitume requests bandia wakati wa enumeration tulivu.

Directory tupu lakini inayoweza kuandikwa ya `/etc/systemd/system/<unit>.service.d` ni muhimu hata ikiwa unit file na drop-in zote zilizopo zinalindwa: mtumiaji anaweza kuunda override mpya ya `.conf`. Kagua ikiwa directory inaweza kuandikwa na kutafutwa na utambulisho wa sasa, unit imepakiwa na inaendeshwa kama root, na ikiwa daemon reload kisha restart itafanyika. Ruhusa ya reload au restart, timer, au boot inayofuata inaweza kufanya mabadiliko yaanze kutumika; ufikiaji wa kuandika kwenye directory pekee hauyaanzishi mara moja.

Kwa services zinazoendeshwa, fuata njia halisi za `EnvironmentFile=` kutoka sehemu ya `[Service]` ya unit, pamoja na faili ambazo majina yake hayaanzi na `.env`. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma mojawapo, orodhesha majina ya key yanayofanana na credentials kama `API_TOKEN` au `APP_SECRET_KEY` bila kuchapisha thamani zake kwenye logs zinazoshirikiwa. Kagua drop-in overrides na viambishi awali vya `-` vinavyoweza kutumika unapobaini unit inayotumika. Uwezo wa kusoma ni kidokezo cha kufichuka kwa credential; thamani hiyo lazima bado iwe halali kwa kitendo chenye ruhusa za juu ili kusababisha privilege escalation.

### Uchakataji wenye ruhusa za juu wa uploads zisizoaminika

File watcher inayoendeshwa kama root inaweza kupitisha faili kutoka kwenye upload directory inayoweza kuandikwa na mtumiaji hadi kwa parser au extractor ya muda mfupi. Fuatilia parent script au service ya watcher inayotumika na uthibitishe directory halisi, nani anayeweza kuweka faili humo, child command na arguments zake, na utambulisho ambao child huendeshwa nao. Picha ya hali ya michakato inaweza kuonyesha watcher huku ikikosa extractor kati ya uploads. Usiweke test payload wala kuchochea watcher wakati wa enumeration tulivu.

Mfano halisi ni hali ya extraction ya Binwalk (`-e`) inayochakata data ya PFS inayodhibitiwa na mshambulizi. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) iliruhusu PFS extractor kuandika nje ya directory iliyokusudiwa, ikijumuisha njia ya plugin ambayo Binwalk ingeweza kupakia baadaye. Upstream ilijumuisha marekebisho katika [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), lakini backports za distribution zinaweza kuhifadhi toleo la zamani linaloonyeshwa; kagua hali ya usalama ya package iliyosakinishwa, kama vile [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510), kabla ya kuamua kama inahusika. Kuwa na toleo la Binwalk lililosakinishwa pekee hakuthibitishi njia ya privilege escalation: extraction lazima ianzishwe kweli na mchakato wenye ruhusa za juu zaidi, ikitumia ingizo ambalo mtumiaji mwenye ruhusa za chini anaweza kudhibiti.

### Builds zilizoratibiwa zenye dependencies za ndani

`cargo run` iliyoratibiwa hucompile source upya kama mtumiaji wa run-as wa job. Kagua dependencies za ndani za `{ path = "..." }` kwenye manifest na ruhusa za source na parent directory za kila dependency, si crate kuu pekee. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kubadilisha dependency ambayo Cargo hucompile na job iliyoratibiwa huendesha matokeo yake, code iliyocompile inaweza kuendeshwa kama mtumiaji huyo wa run-as. Thibitisha amri halisi ya scheduler, working directory, dependency resolution, na ikiwa rebuild itafanyika; faili ya source ya Rust inayoweza kuandikwa mahali pengine ni kidokezo tu. Kusoma manifest na metadata ya njia kunatosha kwa uchunguzi wa awali tulivu. Tazama [nyaraka za Cargo kuhusu path-dependency](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Faili za framebuffer za Xvfb

`Xvfb -fbdir <directory>` hutumia faili zilizowekwa kwenye memory-mapped zinazoitwa `Xvfb_screen<n>` kwa skrini zake pepe. Ikiwa mchakato wa Xvfb unaoendeshwa na mtumiaji mwingine umetaja directory ambayo faili zake za skrini zinaweza kusomwa na mtumiaji wa sasa, framebuffer inaweza kufichua maudhui ya desktop ya mtumiaji huyo. Thibitisha mchakato, umiliki wa faili na ruhusa zake kwa pamoja; faili inayosomeka peke yake haithibitishi kwamba maudhui yenye manufaa yanaonekana kwenye skrini. Kagua njia na metadata kwanza, bila kunakili data ya picha kwenye matokeo ya enumeration yanayoshirikiwa. [Mwongozo wa Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) unaeleza tabia ya `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Mwongozo wa Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Mwongozo wa Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Mwongozo wa OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Usanidi wa Consul agent: ukaguzi wa script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API ya usajili wa huduma ya Consul agent](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Usanidi wa Consul ACL](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Msaada wa LibreOffice: kufungua socket kwa wateja wa API wa nje](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
