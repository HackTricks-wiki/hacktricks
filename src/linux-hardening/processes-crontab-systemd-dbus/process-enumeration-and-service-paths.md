# Uorodheshaji wa Process na Njia za Huduma

{{#include ../../banners/hacktricks-training.md}}

Swali muhimu ni process ipi yenye ruhusa za juu inayotumia data au code ambayo mtumiaji mwenye ruhusa za chini anaweza kuathiri. Kagua mti wa process, mazingira ya wakati huu, faili zilizo wazi, na unit au script iliyoanzisha kila process inayoweza kuhusika.

## Chora ramani ya process na umiliki

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Uhusiano wa parent-child kati ya watumiaji tofauti unaweza kuwa wa kawaida, lakini mabadiliko yasiyotarajiwa yanahitaji kukagua amri ya parent, arguments, executable, working directory na faili zilizorejelewa. Tumia [watumiaji na sessions](../user-information/user-and-session-triage.md) kutafsiri muktadha wa mmiliki na login.

### Konsoli za mashine pepe za ndani

Kagua chaguo za `-spice` za mchakato wa QEMU pamoja na anwani yake ya kusikilizia. [Nyaraka za QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) zinaeleza kuwa `disable-ticketing` huruhusu SPICE clients kuunganishwa bila authentication. Listener iliyofungwa kwenye loopback bado inaweza kufikiwa na watumiaji wengine wa ndani wa host. Thibitisha listener inayotumika, chaguo za authentication na ufikiaji wa ndani kabla ya kuichukulia command line kama konsoli iliyo wazi. Udhibiti wa konsoli huathiri **guest**; kupata akaunti ya guest au kubadilisha hali yake ya boot kunahitaji masharti tofauti upande wa guest na hakukupi root kwenye host ya virtualization. Soma process arguments na socket metadata bila kuunganishwa na guest au kuiwasha upya wakati wa enumeration tulivu.

Web interface inayoweza kufikiwa ndani ya mfumo inaweza kutekeleza code kwa kutumia akaunti yake ya service, hata wakati shell ya kwanza haiwezi kufikia faili za akaunti hiyo. Kwa mfano, CVE-2023-0297 iliathiri ushughulikiaji wa `/flash/addcrypted2` wa pyLoad wakati JavaScript isiyoaminika ilipofikia Js2Py huku Python imports zikiwa zimewashwa; [marekebisho ya upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) yalizima `pyimport`. Linganisha mmiliki wa process inayoendeshwa, anwani ya kusikilizia, ufikivu wa endpoint na patch iliyosakinishwa au backport ya vendor kabla ya kuichukulia process ya pyLoad kama njia ya escalation. Jina la process, port iliyo wazi au toleo la package pekee havithibitishi kuwa mfumo uko hatarini; enumeration tulivu haipaswi kutuma execution payload.

### Privileged login shells zinazoshiriki terminal

Interactive shell yenye privileges inayotekeleza `su --login <user>` bila pseudo-terminal huru inaweza kuacha terminal yake ikishirikiwa na login shell yenye privileges za chini. Ikiwa startup file ya huyo mtumiaji inaweza kudhibitiwa na code iliyo ndani yake inaweza kutumia `TIOCSTI` kuingiza terminal input, input hiyo inaweza kufika kwenye privileged shell inapoendelea tena. [Mwongozo wa util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) unaeleza hatari ya terminal inayoshirikiwa na unapendekeza `su --pty`/`-P` kwa matumizi ya interactive; `su -c` huanzisha session tofauti bila controlling terminal. Hatari hii hutegemea parent shell halisi, uhusiano wa terminal, startup file lengwa na sera ya kernel. Jina la process au argument ya `su -l` pekee ni kidokezo cha kuchunguza.

Kagua process tree iliyoonekana na safu wima za TTY, kisha launcher inayosomeka na umiliki/permissions za startup file. Kwenye Linux, `/proc/sys/dev/tty/legacy_tiocsti` inaweza kusaidia kutafsiri sera inapokuwepo; kutokuwepo kwake hakuthibitishi usalama. [Mwongozo wa Linux `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) unaeleza kuwa tangu Linux 6.2, operesheni hiyo inaweza kuhitaji `CAP_SYS_ADMIN` sysctl hii ikiwa `false`. Usiite ioctl hiyo kwa madhumuni ya enumeration ya host.

Wakati mwingine akaunti ya database inaweza kubadilisha startup file ya mtumiaji lengwa bila kuwa na ufikiaji wa moja kwa moja wa kuandika kwenye filesystem. PostgreSQL server-side `COPY ... TO 'filename'` huandika kwa kutumia akaunti ya OS ya database server, lakini [vikwazo vya PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) huruhusu aina hii ya faili kwa database superusers au roles kama `pg_write_server_files` pekee. Thibitisha role ya database pamoja na permissions za faili za OS upande wa server; connection string ya application pekee haitoi ruhusa ya kuandika faili. Tathmini launcher yenye privileges na uwezo wa akaunti ya database kama vitu tofauti unapochunguza mnyororo huo.

## Kagua runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Programu zinazoweza kutekelezwa zilizofutwa na faili zilizofutwa lakini bado ziko wazi huendelea kurejelewa hadi descriptor yake ya mwisho ifungwe. Zinaweza kuhifadhi ushahidi au siri zinazoweza kufikiwa. Mazingira ya process na memory yanaweza kuwa na credentials, lakini kusoma process nyingine kunadhibitiwa na umiliki, chaguo za `/proc` mount, sera ya Yama ptrace, na vidhibiti vingine vya usalama. Tazama [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) na [post-exploitation credential hunting](../post-exploitation/README.md) kwa mbinu zinazohusiana.

Trace za syscall zilizohifadhiwa ni mpaka mwingine wa ruhusa za faili. [`strace` huandika hoja za syscall kwenye faili ya matokeo](https://man7.org/linux/man-pages/man1/strace.1.html), kwa hivyo trace inayosomeka ya hoja za [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) inaweza kufichua password ambayo job yenye mamlaka ya juu ilipitisha kwenye mstari wake wa amri. Kwanza thibitisha kuwa mtumiaji wa sasa anaweza kusoma trace husika na kwamba hoja hiyo kwa kweli ina credential; hatua ya baadaye ya kubadili akaunti ya Unix inahitaji uthibitisho tofauti kwamba credential hiyo inakubaliwa huko. Metadata ya faili ni kidokezo tulivu kinachofaa, bila kuchanganua kila trace au kuchapisha yaliyomo wakati wa uchunguzi wa kawaida.

## Soketi za uendeshaji otomatiki wa ofisi zenye mamlaka ya juu

LibreOffice na OpenOffice zinaweza kufichua API yao ya UNO kupitia hoja ya `--accept=socket,host=<host>,port=<port>;urp;`. Process ya office inayomilikiwa na root na yenye endpoint inayoweza kufikiwa inaweza kumruhusu mtumiaji wa ndani mwenye mamlaka ya chini kuita huduma za API katika muktadha wa usalama wa process hiyo. Huduma ya `SystemShellExecute` inajumuisha operesheni ya kuzindua amri ya mfumo. Kufunga kwenye loopback hupunguza ufikikaji wa mbali, lakini bado huacha soketi ikifikika kwa watumiaji wa ndani isipokuwa kidhibiti kingine kizuiye ufikiaji.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Linganisha mmiliki wa mchakato, hoja kamili ya `--accept`, na anwani pamoja na port inayosikilizwa kwa sasa. Acceptor iliyosanidiwa lakini imeshindwa kufunga port ni kidokezo tu; usiunganishe na API wala kuitekeleza wakati wa uchunguzi tuli. Epuka kuanzisha instance ya office yenye haki za juu kwa lengo la kujaribu hali hii.

## Kumbukumbu ya pamoja ya System V inayotumiwa na michakato yenye haki za juu

Helper inayomilikiwa na root inaweza kuunda segment ya kumbukumbu ya pamoja ya System V ambayo mtumiaji mwingine anaweza kuandikia. Ikiwa helper baadaye itaamini data kutoka kwenye segment hiyo katika amri ya shell au operesheni nyingine nyeti, segment hiyo huvuka mpaka wa haki hata kama executable na faili zake zimelindwa. `shmget()` hupata ruhusa za ufikiaji kutoka kwenye bits tisa za chini za flags zake; mode `0666` huruhusu watumiaji wengine kuandika, ilhali flag ya `IPC_CREAT` haipunguzi ruhusa hizo. Kagua segmenti zinazotumika kwa njia tuli ukitumia `ipcs -m`, kisha linganisha mmiliki, mode na muda wa kuwepo kwake na mchakato wenye haki za juu pamoja na jinsi unavyoshughulikia ingizo. Segment inayoweza kuandikwa na kila mtu peke yake haithibitishi utekelezaji wa amri.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments ni tofauti na faili za POSIX shared-memory zilizo chini ya `/dev/shm`. Segment iliyoundwa kwa muda mfupi tu huenda isiwepo kwenye picha moja ya `ipcs`, kwa hivyo matokeo tupu hayathibitishi kuwa helper inayotumia shared memory haipo. Kagua source code au tabia ya binary yake, pamoja na sheria yoyote ya `sudo` inayoizindua; usiendeshe helper yenye ruhusa za juu ili tu kufanya segment ionekane wakati wa kuorodhesha. [Mwongozo wa IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) unaeleza jinsi namespaces zinavyoathiri kinachoonekana.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul inaweza kuendesha script health checks kwa utambulisho wa mfumo wa uendeshaji wa agent wake. Ikiwa agent inaendeshwa kama root, imewasha `enable_script_checks`, na inamruhusu mtumiaji mwenye ruhusa za chini kusajili service yenye script check kupitia local HTTP API, mtumiaji huyo anaweza kusababisha amri zinazoendeshwa kama root. Kufunga API kwenye `127.0.0.1` pekee bado kunaruhusu watumiaji wa ndani kuifikia. Mpangilio wa `enable_local_script_checks` una wigo finyu zaidi: unazuia script checks zinazowasilishwa kupitia usajili wa HTTP API. ACL za Consul zikiwa zimewashwa, usajili wa service unahitaji `service:write`; mstari wa `acl.default_policy=allow` pekee hauonyeshi kuwa caller asiye na utambulisho anaweza kusajili service. Kagua utambulisho halisi wa agent, mipangilio iliyopakiwa, API binding na authorization kwa pamoja.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Fuata hoja za `-config-dir` na `-config-file` za agent inayoendesha ili upate usanidi husika, kisha kagua tu majina na mipangilio ya sehemu za script-check na ACL. Faili za usanidi zinaweza pia kuwa na gossip keys au tokens; epuka kuzinakili kwenye kumbukumbu zinazoshirikiwa. Usisajili service wala kuendesha health check kwa lengo la kuorodhesha hali hii pekee.

Njia tofauti kupitia faili za ndani ipo ikiwa mtumiaji mwenye ruhusa za chini anaweza **kuandika na kutafuta** kwenye directory iliyotajwa na `-config-dir` ya agent inayoendeshwa na root: service definition mpya ya `.hcl` au `.json` inaweza kupakiwa kutoka kwenye directory hiyo. Ruhusa za kutafuta na kuandika kwenye directory zinaweza kuruhusu kuongeza faili hata kama ruhusa za kuorodhesha yaliyomo kwenye directory zimekataliwa. Ili kuthibitisha utekelezaji wa command kama root, thibitisha kuwa agent inapakia directory hiyo, mpangilio wake **unaotumika** wa script-check unaruhusu local definitions, definition imepakiwa, na agent inaendelea kuwa na ruhusa za root. [Consul documents](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) which settings and health-check definitions can reload; enabling script checks itself may require a restart, so verify the installed version's behavior. Agent inapolindwa na ACLs, [`consul reload` requires `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); ruhusa ya kuandika KV pekee haitoi ruhusa hiyo. Chukulia metadata ya directory inayoweza kuandikwa kama kidokezo cha kukagua, si uthibitisho wa reload, restart, au utekelezaji wa command ulioidhinishwa. Kagua paths, ruhusa, na policy bila kuandika configuration wala kuita API.

## Fuata mnyororo wa utekelezaji wa service

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Angalia unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories, na socket activation. Unit inayomilikiwa na root bado inaweza kuwa si salama ikiwa inasoma config au script inayoweza kuandikwa na mtumiaji. Ukurasa wa [arbitrary file write](../interesting-files-permissions/write-to-root.md) unaeleza njia za kawaida za kutumia vibaya service na unit. Fuatilia jobs za muda mfupi kwa kutumia [pspy](https://github.com/DominicBreuker/pspy) au audit/process telemetry wakati orodha ya mara moja ya `ps` inapozikosa.

Kwa service maalum ya **xinetd**, linganisha `server`, `user`, na access controls za stanza iliyowezeshwa na listener inayotumika na executable halisi. Mpangilio wa [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) huchagua utambulisho wa process itakayoanzishwa, ilhali set-user-ID bit kwenye executable inaweza kubadilisha utambulisho wake effective kivyake ikiwa [`execve` inaruhusu mabadiliko hayo](https://man7.org/linux/man-pages/man2/execve.2.html). Binary yenye privileges inayoweza kufikiwa na inayokubali input isiyoaminika inafaa kukaguliwa offline kwenye source au disassembly ili kutafuta memory-safety bugs, kama [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) isiyo na kikomo inayoandika kwenye buffer yenye ukubwa maalum. Ulinganifu wa service na metadata ya set-user-ID ni dalili za kufuatilia, si uthibitisho wa bug hiyo; usitume crash inputs wala kufanya debug ya service hai yenye privileges wakati wa passive enumeration.

Kwa listener maalum yenye privileges na source inayosomeka, kagua kila urefu unaodhibitiwa na caller unaotumika katika copy operation kama [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Kuhakikisha tu kwamba write index ya sasa iko ndani ya buffer yenye ukubwa maalum hakuthibitishi kwamba **urefu wa copy** unatoshea kwenye nafasi iliyobaki; thibitisha `copy_length <= capacity - index` baada ya kuhakikisha index iko ndani ya range, na kagua signedness na arithmetic overflow. Hii ni dalili ya kufuatilia wakati tu input inafika kwenye operation hiyo, listener inaweza kufikiwa na mtumiaji mwenye privileges za chini, na process inaendelea kuwa na utambulisho wa juu wa effective. Kagua source na metadata ya process offline; usitume crash inputs kwa service hai wakati wa enumeration.

Kwenye mifumo inayotumia **Upstart**, ufafanuzi wa system jobs unaweza kuwa chini ya `/etc/init/*.conf`. Faili ya job ambayo mtumiaji wa sasa anaweza kuandika ni muhimu ikiwa init daemon inayotumika inapakia job hiyo hasa, stanza yake ya `script` au `exec` inaendeshwa kwa utambulisho wenye privileges za juu, na mtumiaji anaweza kuianzisha kupitia amri ya `initctl` iliyoruhusiwa au trigger nyingine halisi. Ruhusa ya sudo ya `initctl` pekee haithibitishi kwamba faili yoyote ya job inaweza kuandikwa au kwamba job iliyobadilishwa itaendeshwa. Kagua ruhusa za faili husika ya job, mpangilio effective wa run-as, daemon inayotumika, na trigger bila kuhariri au kuanzisha job wakati wa enumeration. Tazama miongozo ya [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) na [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Faili ya password ya autologin inayosomeka, kama `/etc/autologin/passwd` kwenye mifumo ambayo [boot job husoma path hiyo hasa](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), ni dalili ya uwezekano wa credential exposure. Thibitisha kwamba boot job imesakinishwa na inatumia faili hiyo, kisha hakikisha kivyake kama password ni halali kwa akaunti au service nyingine ya ndani. Jina la faili pekee halithibitishi matumizi tena ya password; rekodi path na metadata ya access bila kuweka password kwenye matokeo ya enumeration yanayoshirikiwa.

`ExecStart=` ya unit au amri iliyoratibiwa inaweza kufichua pathname halisi ya script iliyo ndani ya directory isiyoorodheshwa. [Ruhusa ya kutafuta directory](https://man7.org/linux/man-pages/man7/path_resolution.7.html) bado inaweza kuruhusu utambulisho wa sasa kufuata path hiyo inayojulikana; thibitisha ruhusa ya search kwenye kila parent na ruhusa ya kusoma faili badala ya kudhani kuwa kushindwa kuorodhesha directory kunailinda. Script inayosomeka inaweza kuwa na transfer credential, lakini kufikia akaunti nyingine kunahitaji credential hiyo iwe bado halali na ikubalike huko kivyake. Rekodi path na ushahidi wa permissions bila kuchapisha thamani za siri kwenye logs zinazoshirikiwa.

Kwa script ya CommonJS Node.js iliyoratibiwa, kagua bare imports kama `require('package')` hata kama script yenyewe ni read-only. [Node hutafuta `node_modules` karibu na faili inayo-import na kisha kwenye directories zake za ancestor](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), kabla ya kutumia global paths zilizosanidiwa. Mtumiaji mwenye privileges za chini anayeweza **kuandika na kutafuta** mojawapo ya directories hizo za ancestor anaweza kuunda package itakayolingana mapema kwenye utafutaji. Thibitisha kwamba import hiyo hasa inafikiwa, package iliyochaguliwa si built-in module, path husika inaweza kuundwa au kubadilishwa, module inatatuliwa hapo kwenye runtime iliyosakinishwa, na job yenye privileges za juu itai-load kwenye invocation ya baadaye. Metadata ya parent inayoweza kuandikwa ni kidokezo tu cha kukagua; kagua script na scheduler bila kuingilia, bila kuweka module au kuanzisha job.

Private Python package index ni mpaka mwingine wa uaminifu wakati job ya kiotomatiki inaposakinisha packages chini ya utambulisho tofauti wa OS. Linganisha job husika na akaunti ya run-as na index iliyosanidiwa, majina ya packages zilizochaguliwa, na kama mtumiaji mwenye privileges za chini anaweza kuchapisha au kubadilisha package ambayo job itasakinisha kweli. Kuunda source distribution kunaweza kuendesha build backend yake au `setup.py` ya zamani chini ya utambulisho wa kisakinishi; ku-import package iliyosakinishwa ni njia tofauti ya kuendesha code. Listener ya index, hash ya upload password inayosomeka, au jina la package pekee havithibitishi mnyororo huo. Kagua job, uidhinishaji wa index, na asili ya package bila kupakia au kusakinisha chochote wakati wa enumeration. Tazama [pip's build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) na [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/).

Agent yenye privileges inaweza kukagua task queue inayosimamiwa na web service au container tofauti. Ikiwa utambulisho wenye trust ya chini unaweza kuandika task database ya service hiyo, bainisha kama agent hiyo hupokea rows hizo kweli na kama command task huendeshwa kwa utambulisho wa OS wa agent. Thibitisha kivyake ruhusa ya kuandika database, session lengwa au routing key, polling inayotumika, uidhinishaji wa task, na effective user wa agent. Kuwa root ndani ya container hakumaanishi moja kwa moja kuwa na ufikiaji wa host-root; mpaka huvukwa tu ikiwa consumer yenye privileges za host inaendesha task data inayodhibitiwa na mshambuliaji. Kagua metadata ya process, faili ya database, na service bila kubadilisha queue au kutuma task wakati wa enumeration.

Job inayojirudia inaweza badala yake kusoma amri kutoka kwenye configuration row ya application database. Thibitisha kwamba database role yenye privileges za chini inaweza kubadilisha row hiyo hasa, kwamba job inayotumika huisoma baada ya mabadiliko, na kwamba thamani hiyo hufikishwa kwenye shell au command runner inayolingana inayoendeshwa chini ya utambulisho wa juu wa OS. Ruhusa ya kuandika database au thamani inayofanana na amri pekee havithibitishi utekelezaji; kagua job na permissions bila kubadilisha row wakati wa passive enumeration.

Ujumbe uliowekwa kwenye queue unaweza pia kuwa na URL badala ya code. Ikiwa consumer yenye privileges huchukua URL hiyo na kupakia jibu kama Lua au plugin nyingine inayoweza kutekelezwa, thibitisha ruhusa ya publisher kwenye exchange na routing key husika, binding kwenye queue inayotumiwa, njia ya kuchukua na kupakia plugin, na effective identity ya worker. [RabbitMQ huelekeza ujumbe uliochapishwa kupitia exchanges](https://www.rabbitmq.com/docs/exchanges); listener ya broker au login halali pekee havithibitishi kwamba ujumbe utaletwa kwa worker huyu. Broker credentials za cleartext zilizokamatwa ni dalili tofauti inayohitaji ufikiaji halisi wa packet capture na traffic inayosomeka; hazithibitishi ruhusa ya publish. Lua plugin inaweza kuita shell commands kupitia [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) ikiwa tu API hiyo inapatikana kwenye runtime yake. Kagua configuration na code bila kukamata traffic, kuchapisha ujumbe, au kuchukua plugin wakati wa passive enumeration.

Wakati Python service yenye privileges inaonyesha HTTP au socket endpoint ya ndani, script inayosomeka inaweza kufichua njia ya input-to-code hata kama ruhusa za faili zinazuia kuibadilisha. Linganisha utambulisho wa process na unit inayotumika na script, listener, idhini ya route, na fields zinazodhibitiwa na caller. Kisha fuatilia fields hizo kupitia parsing na validation hadi kwenye dynamic `eval()` au `exec()` sink. Hasa, kutengeneza f-string mpya kutoka kwenye request text na kuifanyia evaluation kunaweza kutafsiri replacement fields zilizotolewa na mshambuliaji kama Python expressions ([onyo la Python `eval`](https://docs.python.org/3/library/functions.html#eval); [maana ya f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Kuona `eval` pekee au binding ya loopback hakuthibitishi kwamba caller asiyeaminika anaifikia sink; kagua mtiririko halisi wa data na access controls bila kutuma test payload wakati wa enumeration.

Kizuizi cha signed-request kwenye route hiyo kinahitaji kukaguliwa kivyake. Ikiwa source inayosomeka inaonyesha kwamba signing key inatokana na output space ndogo au inayotabirika, na service inatoa signed sample halali, signature huenda isiwe tena kinga ya `eval()` sink yenye privileges. Thibitisha key derivation na verifier halisi, utambulisho wa service hai na ufikiaji wa caller wa ndani, na kama field iliyosainiwa inafika kwenye sink; ku-import Python [`random` module](https://docs.python.org/3/library/random.html) au kuwa na signature sample pekee hakuthibitishi masharti hayo yoyote. Python pia inaonya kwamba kuzuia `__builtins__` [si mpaka wa usalama kwa input isiyoaminika ya `eval()`](https://docs.python.org/3/library/functions.html#eval). Fanya uchanganuzi wa key offline na usitume forged requests wakati wa passive enumeration.

Directory ya `/etc/systemd/system/<unit>.service.d` iliyo tupu lakini inayoweza kuandikwa ni muhimu hata kama unit file na drop-ins zote zilizopo zinalindwa: mtumiaji anaweza kuunda override mpya ya `.conf`. Kagua kama utambulisho wa sasa unaweza kuandika na kutafuta kwenye directory hiyo, kama unit imepakiwa na inaendeshwa kama root, na kama daemon reload ikifuatiwa na restart itatokea. Ruhusa ya reload au restart, timer, au boot ya baadaye inaweza kufanya mabadiliko hayo yaanze kutumika; ruhusa ya kuandika directory pekee haitekelezi mabadiliko mara moja.

Kwa services zinazoendeshwa, fuata literal `EnvironmentFile=` paths kutoka sehemu ya `[Service]` ya unit, pamoja na faili ambazo majina yake hayaanzi na `.env`. Ikiwa mtumiaji mwenye privileges za chini anaweza kusoma faili, orodhesha majina ya keys yanayofanana na credentials kama `API_TOKEN` au `APP_SECRET_KEY` bila kuchapisha thamani zake kwenye logs zinazoshirikiwa. Kagua drop-in overrides na prefixes za hiari za `-` unapobainisha unit inayotumika. Uwezo wa kusoma ni dalili ya credential exposure; ili kupata escalation, thamani hiyo lazima bado iwe halali kwa kitendo chenye privileges.

### Usindikaji wenye privileges wa uploads zisizoaminika

File watcher inayoendeshwa kama root inaweza kupitisha faili kutoka kwenye upload directory inayoweza kuandikwa na mtumiaji kwenda kwa parser au extractor inayodumu kwa muda mfupi. Fuata parent script au service ya watcher inayoendeshwa na uthibitishe directory halisi, nani anayeweza kuweka faili humo, child command na arguments zake, na utambulisho ambao child inaendeshwa nao. Picha ya process inaweza kuonyesha watcher huku ikikosa extractor kati ya uploads. Usiweke test payload wala kuanzisha watcher wakati wa passive enumeration.

Mfano mmoja halisi ni extraction mode ya Binwalk (`-e`) inapochakata PFS data inayodhibitiwa na mshambuliaji. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) iliruhusu PFS extractor kuandika nje ya directory iliyokusudiwa, ikijumuisha plugin path ambayo Binwalk ingeweza kupakia baadaye. Upstream ilijumuisha marekebisho katika [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), lakini backports za distribution zinaweza kuhifadhi toleo la zamani linaloonyeshwa; kagua hali ya usalama ya package iliyosakinishwa, kama kwenye [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510), kabla ya kubaini kama inahusika. Toleo la Binwalk lililosakinishwa pekee halithibitishi njia ya privilege escalation: mchakato wenye privileges zaidi lazima uanzishe extraction kwenye input ambayo mtumiaji mwenye privileges za chini anaweza kudhibiti.

### Builds zilizoratibiwa zenye dependencies za ndani

`cargo run` iliyoratibiwa hukompile upya source kama mtumiaji wa run-as wa job. Kagua local `{ path = "..." }` dependencies za manifest na permissions za source na parent directories za kila dependency, si crate kuu pekee. Ikiwa mtumiaji mwenye privileges za chini anaweza kurekebisha dependency ambayo Cargo inakompile na job iliyoratibiwa inaendesha matokeo yake, code iliyokompilewa inaweza kutekelezwa kama mtumiaji huyo wa run-as. Thibitisha amri halisi ya scheduler, working directory, utatuzi wa dependencies, na kama build upya itafanyika; faili ya Rust source inayoweza kuandikwa mahali pengine ni dalili tu. Kusoma manifest na metadata ya path kunatosha kwa passive triage. Tazama [nyaraka za Cargo kuhusu path dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Faili za framebuffer za Xvfb

`Xvfb -fbdir <directory>` hutumia faili zilizowekwa kwenye memory-mapped zenye majina ya `Xvfb_screen<n>` kwa virtual screens zake. Ikiwa process ya Xvfb inayoendeshwa na mtumiaji mwingine inataja directory ambayo screen files zake zinaweza kusomwa na mtumiaji wa sasa, framebuffer inaweza kufichua maudhui ya desktop ya mtumiaji huyo. Thibitisha process, umiliki wa faili na permissions kwa pamoja; faili inayosomeka pekee haithibitishi kwamba kuna maudhui yenye manufaa kwenye skrini. Kagua paths na metadata kwanza, bila kunakili image data kwenye matokeo ya enumeration yanayoshirikiwa. [Mwongozo wa Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) unaeleza tabia ya `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Mwongozo wa Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Mwongozo wa Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Mwongozo wa OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Usanidi wa wakala wa Consul: ukaguzi wa script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API ya usajili wa huduma ya wakala wa Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Usanidi wa ACL wa Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Msaada wa LibreOffice: kufungua socket kwa wateja wa API wa nje](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [SDK ya LibreOffice: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
