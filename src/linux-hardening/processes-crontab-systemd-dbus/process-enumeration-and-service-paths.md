# Uorodheshaji wa Michakato na Njia za Huduma

{{#include ../../banners/hacktricks-training.md}}

Swali muhimu ni ni mchakato gani wenye upendeleo hutumia data au code ambayo mtumiaji mwenye upendeleo mdogo anaweza kuathiri. Kagua mti wa michakato, mazingira ya wakati halisi, faili zilizo wazi, na unit au script iliyoanzisha kila mgombea.

## Ramani ya michakato na umiliki

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Uhusiano wa parent-child kati ya watumiaji tofauti unaweza kuwa wa kawaida, lakini mabadiliko yasiyotarajiwa yanastahili kukaguliwa kwa kuangalia amri ya parent, arguments, executable, working directory na faili zinazorejelewa. Tumia [users and sessions](../user-information/user-and-session-triage.md) kutafsiri muktadha wa mmiliki na login.

### Konsoli za mashine pepe za ndani

Kagua chaguo za `-spice` za mchakato wa QEMU pamoja na anwani yake ya kusikilizia. [Nyaraka za QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) zinaeleza kuwa `disable-ticketing` huruhusu wateja wa SPICE kuunganisha bila uthibitishaji. Listener iliyofungwa kwa loopback bado inaweza kufikiwa na watumiaji wengine wa ndani wa host. Thibitisha listener inayotumika, chaguo za uthibitishaji na ufikiaji wa ndani kabla ya kuhitimisha kuwa command line inaonyesha konsoli iliyo wazi. Udhibiti wa konsoli huathiri **guest**; kupata akaunti ya guest au kubadilisha hali yake ya boot kunahitaji masharti tofauti upande wa guest na hakukupi root kwenye host ya virtualization. Soma arguments za mchakato na metadata ya socket bila kuunganisha kwenye guest au kuianzisha upya wakati wa enumeration tulivu.

Kiolesura cha wavuti kinachofikika ndani ya mashine kinaweza kutekeleza code kwa akaunti ya huduma hata kama shell ya kwanza haiwezi kufikia faili za akaunti hiyo. Kwa mfano, CVE-2023-0297 iliathiri ushughulikiaji wa pyLoad wa `/flash/addcrypted2` wakati JavaScript isiyoaminika ilipofika Js2Py huku Python imports zikiwa zimewashwa; [marekebisho ya upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) yalizima `pyimport`. Linganisha mmiliki wa mchakato unaoendesha, anwani ya kusikilizia, ufichuaji wa endpoint na patch iliyosakinishwa au backport ya vendor kabla ya kuchukulia mchakato wa pyLoad kuwa njia ya escalation. Jina la mchakato, port iliyo wazi au toleo la package pekee havithibitishi kuwa kuna ufichuaji; enumeration tulivu haipaswi kutuma payload ya utekelezaji.

### Login shells zenye privileged zinazoshiriki terminal

Shell inayoingiliana yenye privileged inapoendesha `su --login <user>` bila pseudo-terminal huru, terminal yake inaweza kubaki ikishirikiwa na login shell yenye privileged ndogo. Ikiwa startup file ya mtumiaji huyo inaweza kudhibitiwa na code iliyomo inaweza kutumia `TIOCSTI` kuingiza input ya terminal, input hiyo inaweza kufika kwenye shell yenye privileged inapoendelea tena. [Mwongozo wa util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) unaeleza hatari ya terminal inayoshirikiwa na unapendekeza `su --pty`/`-P` kwa matumizi ya kuingiliana; `su -c` huanzisha session tofauti bila controlling terminal. Hatari hii hutegemea shell halisi ya parent, uhusiano wa terminal, startup file lengwa na sera ya kernel. Jina la mchakato au argument ya `su -l` pekee ni kidokezo cha kufanya ukaguzi zaidi.

Kagua process tree iliyoonekana na safu za TTY, kisha launcher inayosomeka na umiliki/ruhusa za startup file. Kwenye Linux, `/proc/sys/dev/tty/legacy_tiocsti` inaweza kusaidia kutafsiri sera inapokuwepo; kutokuwepo kwake hakuthibitishi usalama. [Mwongozo wa Linux `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) unaeleza kuwa tangu Linux 6.2, operesheni hii inaweza kuhitaji `CAP_SYS_ADMIN` wakati sysctl hii ni false. Usiite ioctl hii kwa madhumuni ya kuorodhesha host.

Wakati mwingine akaunti ya database inaweza kubadilisha startup file ya mtumiaji lengwa bila kuwa na ufikiaji wa moja kwa moja wa kuandika kwenye filesystem. `COPY ... TO 'filename'` ya upande wa server wa PostgreSQL huandika kwa kutumia akaunti ya OS ya server ya database, lakini [vikwazo vya PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) vinaweka matumizi ya aina hii ya faili kwa superuser wa database au roles kama `pg_write_server_files`. Thibitisha role ya database na ruhusa za faili za OS ya server; connection string ya application pekee haitoi mamlaka ya kuandika faili. Tathmini launcher yenye privileged na uwezo wa akaunti ya database kama sehemu tofauti za mnyororo.

## Kagua runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Executable zilizofutwa na faili zilizofutwa lakini bado ziko wazi hubaki zikirejelewa hadi descriptor yao ya mwisho ifungwe. Zinaweza kuhifadhi ushahidi au siri zinazoweza kufikiwa. Mazingira na kumbukumbu ya mchakato zinaweza kuwa na credentials, lakini kusoma mchakato mwingine kunazuiwa na umiliki, chaguo za `/proc` za mount, sera ya Yama ptrace, na vidhibiti vingine vya usalama. Tazama [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) na [kutafuta credentials wakati wa post-exploitation](../post-exploitation/README.md) kwa mbinu zinazohusiana.

Traces za syscall zilizohifadhiwa ni mpaka mwingine wa ruhusa za faili. [`strace` huhifadhi hoja za syscall kwenye faili ya matokeo](https://man7.org/linux/man-pages/man1/strace.1.html), kwa hiyo trace inayoweza kusomwa ya hoja za [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) inaweza kufichua password ambayo job yenye ruhusa za juu ilipitisha kwenye command line yake. Kwanza thibitisha kwamba mtumiaji wa sasa anaweza kusoma trace husika na kwamba hoja hiyo ina credential; uthibitisho tofauti unahitajika ili kuthibitisha baadaye kwamba credential hiyo inakubaliwa wakati wa kubadili akaunti ya Unix. Metadata ya faili ni kidokezo cha maana kinachopatikana bila kupekua kila trace au kuchapisha yaliyomo wakati wa uorodheshaji wa kawaida.

## Sockets za automation ya ofisi zenye ruhusa za juu

LibreOffice na OpenOffice zinaweza kufichua API yao ya UNO kupitia hoja ya `--accept=socket,host=<host>,port=<port>;urp;`. Mchakato wa office unaomilikiwa na root wenye endpoint inayofikika unaweza kumruhusu mtumiaji wa karibu mwenye ruhusa za chini kuita huduma za API ndani ya mchakato huo kwa kutumia muktadha wake wa usalama. Huduma ya `SystemShellExecute` inajumuisha operesheni ya kuzindua command ya mfumo. Kufunga kwenye loopback huzuia ufikiaji wa mbali lakini bado huacha socket ikifikika kwa watumiaji wa karibu isipokuwa kidhibiti kingine kizuie ufikiaji.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Linganisha mmiliki wa mchakato, hoja halisi ya `--accept`, na anwani na port inayosikilizwa kwa sasa. Acceptor iliyosanidiwa lakini imeshindwa kufunga port ni kidokezo tu; usiunganishe au kuita API wakati wa enumeration tuli. Epuka kuanzisha instance ya office yenye ruhusa za juu kwa lengo la kujaribu hali hii.

## Kumbukumbu ya pamoja ya System V inayotumiwa na michakato yenye ruhusa za juu

Helper inayomilikiwa na root inaweza kuunda segment ya kumbukumbu ya pamoja ya System V ambayo mtumiaji mwingine anaweza kuandika. Ikiwa baadaye helper itaamini data kutoka kwenye segment hiyo katika shell command au operesheni nyingine nyeti, segment hiyo huvuka mpaka wa ruhusa hata kama executable na faili zake zimelindwa. `shmget()` huchukua ruhusa za ufikiaji kutoka kwenye biti tisa za chini za flags zake; mode `0666` huruhusu watumiaji wengine kuandika, ilhali flag ya `IPC_CREAT` haipunguzi ruhusa hizo. Kagua segments zinazotumika kwa njia tuli ukitumia `ipcs -m`, kisha linganisha mmiliki wake, mode, na muda wa kuwepo na mchakato wenye ruhusa za juu pamoja na namna unavyoshughulikia ingizo. Segment inayoweza kuandikwa na kila mtu pekee haithibitishi utekelezaji wa amri.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments ni tofauti na faili za POSIX shared-memory zilizo chini ya `/dev/shm`. Segment iliyoundwa kwa muda mfupi tu huenda isiwepo kwenye picha moja ya `ipcs`, kwa hiyo matokeo tupu hayathibitishi kuwa helper haitumii shared memory. Kagua chanzo chake au tabia ya binary na sheria zozote za `sudo` zinazoizindua; usiendeshe helper yenye ruhusa za juu ili tu kufanya segment ionekane wakati wa enumeration. [Mwongozo wa IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) unaeleza jinsi namespaces zinavyoathiri kinachoonekana.<sup>[[2]](#references)[[3]](#references)</sup>

## Ukaguzi wa script wa agent wa Consul

Consul inaweza kuendesha ukaguzi wa afya wa script kwa utambulisho wa mfumo wa uendeshaji wa agent wake. Ikiwa agent inaendeshwa kama root, imewasha `enable_script_checks`, na inamruhusu mtumiaji mwenye ruhusa za chini kusajili service yenye ukaguzi wa script kupitia local HTTP API, mtumiaji huyo anaweza kusababisha amri zinazoendeshwa kama root. Kufunga API kwenye `127.0.0.1` pekee bado kunawawezesha watumiaji wa ndani kuifikia. Mpangilio wa `enable_local_script_checks` una wigo finyu zaidi: unazuia ukaguzi wa script unaowasilishwa kupitia usajili wa HTTP API. ACL za Consul zikiwashwa, usajili wa service unahitaji `service:write`; mstari wa `acl.default_policy=allow` pekee hauonyeshi kuwa mpigaji asiyejulikana anaweza kusajili. Kagua pamoja utambulisho halisi wa agent, mipangilio iliyopakiwa, ufungamanisho wa API na uidhinishaji.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Fuata hoja za `-config-dir` na `-config-file` za agent inayoendesha hadi kwenye usanidi husika, na kagua tu majina na mipangilio ya sehemu za script-check na ACL. Faili za usanidi zinaweza pia kuwa na funguo au tokeni za gossip; epuka kuzinakili kwenye kumbukumbu zinazoshirikiwa. Usisajili huduma wala kuendesha ukaguzi wa afya kwa lengo la kubaini tu hali hii.

Kuna pia njia tofauti kupitia faili ya ndani pale mtumiaji mwenye ruhusa ndogo anapoweza **kuandika na kutafuta** katika saraka iliyotajwa na `-config-dir` ya agent inayoendeshwa kama root: ufafanuzi mpya wa huduma wa `.hcl` au `.json` unaweza kupakiwa kutoka kwenye saraka hiyo. Ruhusa ya kutafuta na kuandika kwenye saraka zinaweza kuruhusu kuongeza faili hata kama ruhusa ya kuorodhesha saraka imekataliwa. Kwa ajili ya utekelezaji wa amri kama root, thibitisha kwamba agent hupakia saraka hiyo, mpangilio wake **halisi** wa script-check huruhusu ufafanuzi wa ndani, ufafanuzi umepakiwa, na agent huhifadhi ruhusa za root. [Consul documents](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) huonyesha mipangilio na ufafanuzi wa health-check unaoweza kupakiwa upya; kuwezesha script checks huenda kukahitaji kuwasha upya, kwa hivyo thibitisha tabia ya toleo lililosakinishwa. ACL zinapolinda agent, [`consul reload` requires `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); ruhusa ya kuandika kwenye KV pekee haitoi ruhusa hiyo. Chukulia metadata ya saraka inayoweza kuandikwa kama kidokezo cha kukagua, si uthibitisho wa reload, restart, au utekelezaji wa amri ulioidhinishwa. Kagua njia, ruhusa na sera bila kuandika usanidi wala kupiga API.

## Fuatilia mnyororo wa utekelezaji wa huduma

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Kagua unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories, na socket activation. Unit inayomilikiwa na root bado inaweza kuwa si salama ikiwa inasoma config au script inayoweza kuandikwa na mtumiaji. Ukurasa wa [arbitrary file write](../interesting-files-permissions/write-to-root.md) unaeleza njia za kawaida za kutumia vibaya service na unit. Fuatilia jobs za muda mfupi kwa kutumia [pspy](https://github.com/DominicBreuker/pspy) au audit/process telemetry pale ambapo orodha ya `ps` ya mara moja haiwezi kuziona.

Kwa service maalum ya **xinetd**, linganisha `server`, `user`, na vidhibiti vya ufikiaji vilivyo kwenye stanza iliyowezeshwa na listener hai pamoja na executable halisi. Mpangilio wa [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) huchagua utambulisho wa process itakayozalishwa, ilhali set-user-ID bit kwenye executable inaweza kubadilisha kando utambulisho wake halisi ikiwa [`execve` inaruhusu mabadiliko hayo](https://man7.org/linux/man-pages/man2/execve.2.html). Binary yenye mamlaka ya juu inayoweza kufikiwa na inayokubali input isiyoaminika inafaa kukaguliwa offline kwenye source au disassembly ili kutafuta bugs za memory-safety, kama [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) isiyo na kikomo inayoandika kwenye buffer yenye ukubwa maalum. Ulinganifu wa service na metadata ya set-user-ID ni dalili za kuchunguza, si uthibitisho wa bug hiyo; usitume input za kusababisha crash wala ku-debug service hai yenye mamlaka ya juu wakati wa enumeration tulivu.

Kwa listener maalum yenye mamlaka ya juu na source inayosomeka, kagua kila urefu unaodhibitiwa na caller unaotumika kwenye operesheni ya kunakili kama [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Kuhakikisha tu kwamba index ya sasa ya uandishi iko ndani ya buffer yenye ukubwa maalum hakuthibitishi kuwa **urefu wa nakala** unatoshea kwenye nafasi iliyobaki; thibitisha `copy_length <= capacity - index` baada ya kuhakikisha kwamba index iko kwenye mipaka, na kagua signedness na arithmetic overflow. Hili ni dokezo la ukaguzi tu ikiwa input inafika kwenye operesheni hiyo, listener inaweza kufikiwa na mtumiaji mwenye mamlaka ya chini, na process inabaki na utambulisho halisi wenye mamlaka ya juu zaidi. Kagua source na metadata ya process offline; usitume input za kusababisha crash kwa service hai wakati wa enumeration.

Kwenye mifumo inayotumia **Upstart**, ufafanuzi wa system job unaweza kuwa chini ya `/etc/init/*.conf`. Faili ya job inayoweza kuandikwa na mtumiaji wa sasa ni muhimu pale ambapo init daemon hai inapakia job hiyo hasa, stanza yake ya `script` au `exec` inaendeshwa kwa utambulisho wenye mamlaka ya juu zaidi, na mtumiaji anaweza kuianzisha kupitia amri ya `initctl` inayoruhusiwa au kichochezi kingine halisi. Ruhusa ya sudo ya `initctl` pekee haithibitishi kwamba faili yoyote ya job inaweza kuandikwa au kwamba job iliyorekebishwa itaendeshwa. Kagua ruhusa za faili husika ya job, mpangilio halisi wa run-as, daemon hai, na kichochezi bila kuhariri au kuanzisha job wakati wa enumeration. Tazama miongozo ya [usanidi wa Upstart job](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) na [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Faili ya nenosiri la autologin inayosomeka, kama `/etc/autologin/passwd` kwenye mifumo ambayo [boot job husoma path hiyo hasa](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), ni dalili ya kufichuka kwa credentials. Thibitisha kuwa boot job imesakinishwa na inatumia faili hiyo, kisha hakikisha kando kama nenosiri hilo ni halali kwa akaunti au service nyingine ya ndani. Jina la faili pekee halithibitishi matumizi tena ya nenosiri; rekodi path na metadata ya ufikiaji bila kuweka nenosiri kwenye matokeo ya enumeration yanayoshirikiwa.

`ExecStart=` ya unit au amri iliyopangwa inaweza kufichua pathname halisi ya script iliyo ndani ya directory isiyoweza kuorodheshwa. [Ruhusa ya kutafuta kwenye directory](https://man7.org/linux/man-pages/man7/path_resolution.7.html) bado inaweza kuruhusu utambulisho wa sasa kupita kwenye path hiyo inayojulikana; thibitisha ruhusa ya kutafuta kwenye kila directory ya mzazi na ruhusa ya kusoma faili badala ya kudhani kwamba kushindwa kuorodhesha directory kunalilinda. Script inayosomeka inaweza kuwa na credential ya kuhamisha data, lakini kufikia akaunti nyingine kunahitaji credential hiyo iwe bado halali na ikubalike huko kando. Rekodi path na ushahidi wa ruhusa bila kuchapisha siri kwenye logs zinazoshirikiwa.

Kwa script ya CommonJS Node.js iliyopangwa, kagua imports zisizo na path kama `require('package')` hata kama script yenyewe ni ya kusomwa tu. [Node hutafuta `node_modules` karibu na faili inayo-import na kisha kwenye directories zake za mababu](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), kabla ya kutumia njia za global zilizosanidiwa. Mtumiaji mwenye mamlaka ya chini anayeweza **kuandika na kutafuta** kwenye mojawapo ya directories hizo za mababu anaweza kuunda package itakayolingana mapema. Thibitisha kuwa import halisi inafikiwa, package iliyochaguliwa si module iliyojengewa ndani, path husika inaweza kuundwa au kubadilishwa, module inasuluhishwa hapo kwenye runtime iliyosakinishwa, na job yenye mamlaka ya juu itaipakia itakapoendeshwa tena. Metadata ya directory ya mzazi inayoweza kuandikwa ni kidokezo cha ukaguzi tu; kagua script na scheduler bila kufanya mabadiliko, wala kupanda module au kuanzisha job.

Private Python package index ni mpaka mwingine wa uaminifu wakati job otomatiki inaposakinisha packages kwa utambulisho tofauti wa OS. Linganisha job halisi na akaunti ya run-as na index yake iliyosanidiwa, majina ya packages zilizochaguliwa, na kama mtumiaji mwenye mamlaka ya chini anaweza kuchapisha au kubadilisha package ambayo job itasakinisha kweli. Kujenga source distribution kunaweza kuendesha build backend yake au `setup.py` ya zamani kwa utambulisho wa kisakinishi; ku-import package iliyosakinishwa ni njia tofauti ya utekelezaji. Listener ya index, hash ya nenosiri la upload inayosomeka, au jina la faili la package pekee havithibitishi mnyororo huo. Kagua job, ruhusa za index, na chanzo cha package bila kupakia au kusakinisha chochote wakati wa enumeration. Tazama [kiolesura cha build-system cha pip](https://pip.pypa.io/en/stable/reference/build-system/) na [mwongozo wa secure-install](https://pip.pypa.io/en/stable/topics/secure-installs/).

Agent yenye mamlaka ya juu inaweza kuchunguza mara kwa mara task queue inayosimamiwa na web service au container tofauti. Ikiwa utambulisho wenye kiwango cha chini cha uaminifu unaweza kuandika kwenye task database ya service hiyo, bainisha kama agent huyo hupokea rows hizo kweli na kama command task inaendeshwa kwa utambulisho wa OS wa agent. Thibitisha kando ruhusa ya kuandika database, session lengwa au routing key, polling hai, ruhusa za task, na mtumiaji halisi wa agent. Root ndani ya container haimaanishi yenyewe ufikiaji wa host-root; mpaka huvukwa tu ikiwa consumer mwenye mamlaka ya host anaendesha task data inayodhibitiwa na mshambuliaji. Kagua metadata ya process, faili ya database, na service bila kurekebisha queue au kutuma task wakati wa enumeration.

Badala yake, job inayojirudia inaweza kusoma amri kutoka kwenye row ya usanidi wa application database. Thibitisha kuwa role ya database yenye mamlaka ya chini inaweza kubadilisha row hiyo hasa, job hai huisoma baada ya mabadiliko hayo, na thamani hiyo hufikishwa kwenye shell au command runner inayolingana inayoendeshwa kwa utambulisho wa OS wenye mamlaka ya juu zaidi. Ruhusa ya kuandika database au thamani inayoonekana kama amri pekee havithibitishi utekelezaji; kagua job na ruhusa bila kubadilisha row wakati wa enumeration tulivu.

Ujumbe uliowekwa kwenye queue pia unaweza kuwa na URL badala ya code. Ikiwa consumer mwenye mamlaka ya juu anachukua URL hiyo na kupakia jibu kama Lua au plugin nyingine inayoweza kutekelezwa, thibitisha ruhusa ya publisher kwenye exchange na routing key husika, binding kwenye queue inayotumiwa, njia ya kuchukua na kupakia plugin, na utambulisho halisi wa worker. [RabbitMQ huelekeza ujumbe uliochapishwa kupitia exchanges](https://www.rabbitmq.com/docs/exchanges); listener ya broker au login halali pekee havithibitishi kuwa ujumbe utamfikia worker huyu. Credentials za broker zilizonaswa zikiwa cleartext ni dalili tofauti inayohitaji ufikiaji halisi wa packet capture na traffic inayosomeka; hazithibitishi ruhusa ya kuchapisha. Plugin ya Lua inaweza kuendesha amri za shell kupitia [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) tu ikiwa API hiyo inapatikana kwenye runtime yake. Kagua usanidi na code bila kunasa traffic, kuchapisha ujumbe, au kuchukua plugin wakati wa enumeration tulivu.

Wakati Python service yenye mamlaka ya juu inaweka wazi endpoint ya ndani ya HTTP au socket, script inayosomeka inaweza kufichua njia ya input hadi code hata kama ruhusa za faili zinaizuia kurekebishwa. Linganisha process hai na utambulisho wa unit na script halisi, listener, idhini ya route, na fields zinazodhibitiwa na caller. Kisha fuatilia fields hizo kupitia uchakataji na uthibitishaji hadi kwenye sink ya dynamic `eval()` au `exec()`. Hasa, kuunda f-string mpya kutoka kwenye maandishi ya request na kuitathmini kunaweza kutafsiri replacement fields zilizotolewa na mshambuliaji kama Python expressions ([onyo la Python kuhusu `eval`](https://docs.python.org/3/library/functions.html#eval); [semantics za f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Kulingana na matokeo ya `eval` pekee au binding ya loopback hakuthibitishi kuwa caller asiyeaminika anafikia sink; kagua mtiririko halisi wa data na vidhibiti vya ufikiaji bila kutuma test payload wakati wa enumeration.

Kizuizi cha signed-request kwenye route hiyo kinahitaji ukaguzi wake pia. Ikiwa source inayosomeka inapata signing key kupitia nafasi ya matokeo iliyo ndogo au inayotabirika kwa namna inayoweza kuthibitishwa, na service inatoa mfano halali uliotiwa saini, saini hiyo huenda isiilinde tena sink ya `eval()` yenye mamlaka ya juu. Thibitisha derivation halisi ya key na verifier, utambulisho wa service hai na ufikiaji wa caller wa ndani, na kama field iliyotiwa saini inafika kwenye sink; import ya Python ya [`random` module](https://docs.python.org/3/library/random.html) au mfano wa saini pekee havithibitishi masharti hayo. Python pia inaonya kuwa kuweka kikomo kwa `__builtins__` [si mpaka wa usalama kwa input ya `eval()` isiyoaminika](https://docs.python.org/3/library/functions.html#eval). Changanua key offline na usitume requests zilizoghushiwa wakati wa enumeration tulivu.

Directory tupu lakini inayoweza kuandikwa ya `/etc/systemd/system/<unit>.service.d` ni muhimu hata kama faili ya unit na drop-in zote zilizopo zinalindwa: mtumiaji anaweza kuunda override mpya ya `.conf`. Kagua kama directory inaweza kuandikwa na kutafutwa na utambulisho wa sasa, unit imepakiwa na inaendeshwa kama root, na kama daemon reload ikifuatiwa na restart itafanyika. Ruhusa ya reload au restart, timer, au boot ya baadaye inaweza kufanya mabadiliko yaanze kutumika; ruhusa ya kuandika kwenye directory pekee haiyatekelezi mara moja.

Kwa services zinazoendeshwa, fuata paths halisi za `EnvironmentFile=` kutoka sehemu ya `[Service]` ya unit, ikijumuisha faili ambazo majina yake hayaanzi na `.env`. Ikiwa mtumiaji mwenye mamlaka ya chini anaweza kusoma mojawapo, orodhesha majina ya key yanayofanana na credentials kama `API_TOKEN` au `APP_SECRET_KEY` bila kuchapisha thamani zake kwenye logs zinazoshirikiwa. Kagua drop-in overrides na viambishi awali vya `-` vilivyo hiari unapobainisha unit inayotumika. Uwezo wa kusoma ni dalili ya kufichuka kwa credentials; thamani hiyo bado lazima iwe halali ili kitendo chenye mamlaka ya juu kiweze kusababisha privilege escalation.

### Uchakataji wa uploads zisizoaminika kwa mamlaka ya juu

File watcher inayoendeshwa na root inaweza kupitisha faili kutoka kwenye upload directory inayoweza kuandikwa na mtumiaji kwenda kwa parser au extractor inayoendeshwa kwa muda mfupi. Fuatilia parent script au service ya watcher inayoendeshwa na uthibitishe directory halisi, nani anaweza kuweka faili humo, amri ya child na arguments zake, na utambulisho ambao child inaendeshwa nao. Muhtasari wa process unaweza kuonyesha watcher lakini ukakosa extractor kati ya uploads. Usiweke test payload wala kuanzisha watcher wakati wa enumeration tulivu.

Mfano mmoja mahususi ni extraction mode ya Binwalk (`-e`) inayochakata data ya PFS inayodhibitiwa na mshambuliaji. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) iliruhusu PFS extractor kuandika nje ya directory iliyokusudiwa, ikijumuisha plugin path ambayo Binwalk ingeweza kupakia baadaye. Upstream ilijumuisha marekebisho hayo katika [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), lakini backports za distribution zinaweza kuhifadhi toleo la zamani linaloonyeshwa; kagua hali ya usalama ya package iliyosakinishwa, kama vile [tracker ya Debian](https://security-tracker.debian.org/tracker/CVE-2022-4510), kabla ya kuamua kama inahusika. Toleo la Binwalk lililosakinishwa pekee halithibitishi njia ya privilege escalation: extraction lazima ianzishwe kweli na process yenye mamlaka ya juu zaidi kwenye input ambayo mtumiaji mwenye mamlaka ya chini anaweza kudhibiti.

### Builds zilizopangwa zenye dependencies za ndani

`cargo run` iliyopangwa hukompile upya source kwa mtumiaji wa run-as wa job. Kagua dependencies za ndani za manifest zenye `{ path = "..." }` na ruhusa za source pamoja na directories zake za wazazi kwa kila dependency, si crate kuu tu. Ikiwa mtumiaji mwenye mamlaka ya chini anaweza kurekebisha dependency ambayo Cargo inakompile na job iliyopangwa ikaendesha matokeo yake, code iliyokompile inaweza kuendeshwa kama mtumiaji huyo wa run-as. Thibitisha amri halisi ya scheduler, working directory, usuluhishaji wa dependency, na kama build upya itafanyika; faili ya source ya Rust inayoweza kuandikwa mahali pengine ni dalili tu. Kusoma manifest na metadata ya path kunatosha kwa triage tulivu. Tazama [nyaraka za Cargo kuhusu path-dependency](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Faili za framebuffer za Xvfb

`Xvfb -fbdir <directory>` hutumia faili zilizowekwa kwenye memory-map zinazoitwa `Xvfb_screen<n>` kwa skrini zake za virtual. Ikiwa process ya Xvfb inayoendeshwa na mtumiaji mwingine inataja directory ambayo faili zake za screen zinaweza kusomwa na mtumiaji wa sasa, framebuffer inaweza kufichua maudhui ya desktop ya mtumiaji huyo. Thibitisha process, umiliki wa faili, na ruhusa kwa pamoja; faili inayosomeka pekee haithibitishi kuwa kuna maudhui yenye manufaa kwenye skrini. Kagua paths na metadata kwanza, bila kunakili data ya picha kwenye matokeo ya enumeration yanayoshirikiwa. [Mwongozo wa Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) unaeleza utendaji wa `-fbdir`.

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
6. [Usanidi wa ACL ya Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Msaada wa LibreOffice: kufungua socket kwa wateja wa API wa nje](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
