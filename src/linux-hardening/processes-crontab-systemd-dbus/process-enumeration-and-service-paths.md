# Process Enumeration और Service Paths

{{#include ../../banners/hacktricks-training.md}}

उपयोगी सवाल यह है कि कौन-सा privileged process ऐसा data या code इस्तेमाल करता है जिसे कम privileged user प्रभावित कर सकता है। Process tree, live environment, open files, और उस unit या script की जाँच करें जिसने हर संभावित process को launch किया।

## Processes और ownership का मानचित्र बनाएँ

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

एक cross-user parent-child संबंध सामान्य हो सकता है, लेकिन किसी अप्रत्याशित बदलाव की स्थिति में parent command, arguments, executable, working directory और संदर्भित files की समीक्षा करना उचित है। स्वामी और login संदर्भ को समझने के लिए [users and sessions](../user-information/user-and-session-triage.md) का उपयोग करें।

### Local virtual-machine consoles

QEMU process के `-spice` options की समीक्षा उसके listening address के साथ करें। [QEMU documents](https://www.qemu.org/docs/master/system/qemu-manpage.html) के अनुसार, `disable-ticketing` SPICE clients को authentication के बिना connect करने देता है। Loopback से bound listener तक भी अन्य local host users की संभावित पहुँच हो सकती है। Command line को exposed console मानने से पहले live listener, authentication options और local access की पुष्टि करें। Console का नियंत्रण **guest** को प्रभावित करता है; guest account प्राप्त करने या उसकी boot state बदलने के लिए guest-side की अलग शर्तें पूरी करनी पड़ती हैं, और इससे virtualization host पर root access नहीं मिलता। Passive enumeration के दौरान guest से connect किए बिना या उसे reboot किए बिना process arguments और socket metadata पढ़ें।

कोई locally reachable web interface अपने service account के रूप में code चला सकता है, भले ही पहली shell उस account की files तक पहुँच न पा रही हो। उदाहरण के लिए, CVE-2023-0297 में pyLoad का `/flash/addcrypted2` handling प्रभावित था, जब untrusted JavaScript Python imports सक्षम होने पर Js2Py तक पहुँचता था; [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) ने `pyimport` को disable कर दिया। किसी pyLoad process को escalation path मानने से पहले running process के owner, listening address, endpoint exposure और installed patch या vendor backport का मिलान करें। केवल process name, open port या package version exposure साबित नहीं करता; passive enumeration में execution payload न भेजें।

### Privileged login shells sharing a terminal

कोई privileged interactive shell, जो बिना independent pseudo-terminal के `su --login <user>` चलाता है, अपना terminal कम privilege वाले login shell के साथ साझा कर सकता है। यदि उस user की startup file को नियंत्रित किया जा सकता है और उसमें मौजूद code `TIOCSTI` का उपयोग करके terminal input inject कर सकता है, तो privileged shell के फिर से सक्रिय होने पर वह input वहाँ पहुँच सकता है। [The util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) shared-terminal risk का वर्णन करता है और interactive use के लिए `su --pty`/`-P` की सिफारिश करता है; `su -c` controlling terminal के बिना एक अलग session शुरू करता है। इस जोखिम के लिए वास्तविक parent shell, terminal संबंध, target startup file और kernel policy का होना आवश्यक है। केवल process name या `su -l` argument समीक्षा का संकेत है।

देखे गए process tree और TTY columns की जाँच करें, फिर पढ़े जा सकने वाले launcher और startup file के ownership/permissions की जाँच करें। Linux पर, यदि मौजूद हो, तो `/proc/sys/dev/tty/legacy_tiocsti` policy को समझने में मदद कर सकता है; इसका न होना सुरक्षा का प्रमाण नहीं है। [The Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) के अनुसार, Linux 6.2 से, यदि यह sysctl false हो तो इस operation के लिए `CAP_SYS_ADMIN` की आवश्यकता हो सकती है। Host की enumeration के लिए ioctl न चलाएँ।

कभी-कभी database account, सीधे filesystem write access के बिना target user की startup file बदल सकता है। PostgreSQL का server-side `COPY ... TO 'filename'` database server के OS account के रूप में लिखता है, लेकिन [PostgreSQL limits](https://www.postgresql.org/docs/current/sql-copy.html) के अनुसार, इस file form का उपयोग केवल database superusers या `pg_write_server_files` जैसी roles कर सकती हैं। Database role और server OS file permissions, दोनों की पुष्टि करें; application connection string अकेले file-write authority नहीं देती। इस chain का आकलन करते समय privileged launcher और database account की capabilities को अलग-अलग रखें।

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

हटाए गए executables और हटाई गई लेकिन खुली files तब तक referenced रहती हैं, जब तक उनका आखिरी descriptor बंद नहीं हो जाता। वे सबूत या उपलब्ध secrets को सुरक्षित रख सकती हैं। Process environments और memory में credentials हो सकते हैं, लेकिन किसी दूसरे process को पढ़ना ownership, `/proc` mount options, Yama ptrace policy और अन्य security controls से सीमित होता है। संबंधित techniques के लिए [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) और [post-exploitation credential hunting](../post-exploitation/README.md) देखें।

सहेजे गए syscall traces भी file-permission की एक सीमा हैं। [`strace` syscall arguments को एक output file में रिकॉर्ड करता है](https://man7.org/linux/man-pages/man1/strace.1.html), इसलिए [`execve` arguments](https://man7.org/linux/man-pages/man2/execve.2.html) वाला कोई पढ़ने योग्य trace ऐसा password उजागर कर सकता है, जिसे किसी privileged job ने अपनी command line पर पास किया हो। पहले पुष्टि करें कि मौजूदा user उस विशेष trace को पढ़ सकता है और argument में वास्तव में कोई credential है; बाद में Unix-account में बदलाव करने के लिए अलग से साबित करना होगा कि वहाँ वह credential स्वीकार किया जाता है। Routine enumeration के दौरान हर trace को scan किए बिना या उसकी सामग्री दिखाए बिना, file metadata एक उपयोगी passive lead है।

## Privileged office automation sockets

LibreOffice और OpenOffice अपने UNO API को `--accept=socket,host=<host>,port=<port>;urp;` argument के ज़रिए उपलब्ध करा सकते हैं। किसी reachable endpoint वाला root-owned office process, कम privilege वाले local user को उस process के security context में API services invoke करने दे सकता है। `SystemShellExecute` service में system command launch करने का एक operation शामिल है। Loopback से bind करने पर remote reachability सीमित होती है, लेकिन जब तक कोई अन्य control access को रोकता नहीं, socket local users के लिए reachable रहता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

प्रक्रिया के owner, सटीक `--accept` argument और वर्तमान listening address तथा port का मिलान करें। ऐसा configured acceptor जो bind करने में विफल रहा हो, केवल एक सुराग है; passive enumeration के दौरान API से connect न करें और न ही उसे invoke करें। केवल इस स्थिति की जाँच के लिए privileged office instance शुरू करने से बचें।

## Privileged processes द्वारा उपयोग की जाने वाली System V shared memory

Root-owned helper ऐसा System V shared-memory segment बना सकता है जिसमें कोई अन्य user लिख सके। यदि helper बाद में उस segment के data पर shell command या किसी अन्य sensitive operation में भरोसा करता है, तो executable और उसकी files सुरक्षित होने पर भी वह segment privilege boundary को पार करता है। `shmget()` अपने flags के निचले नौ bits से access permissions लेता है; mode `0666` अन्य users को लिखने की अनुमति देता है, जबकि `IPC_CREAT` flag उन permissions को सीमित नहीं करता। `ipcs -m` से active segments का निरीक्षण passive रूप से करें और उनके owner, mode तथा lifetime का privileged process और उसके input handling से मिलान करें। केवल world-writable segment होने से command execution सिद्ध नहीं होता।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments, `/dev/shm` के अंतर्गत POSIX shared-memory files से अलग होते हैं। केवल कुछ क्षणों के लिए बनाया गया segment, `ipcs` के एक snapshot में मौजूद न हो सकता है, इसलिए खाली output से यह साबित नहीं होता कि shared memory का उपयोग करने वाला कोई helper नहीं है। इसके source या binary behavior और उसे launch करने वाले किसी भी `sudo` rule की समीक्षा करें; enumeration के दौरान segment दिखाने के लिए privileged helper को न चलाएं। [IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) बताती है कि namespaces visibility को कैसे प्रभावित करते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul, अपने agent की operating-system identity के साथ script health checks चला सकता है। यदि कोई agent root के रूप में चलता है, `enable_script_checks` सक्षम करता है, और कम privileged user को local HTTP API के माध्यम से script check वाली service register करने देता है, तो वह user root के रूप में चलने वाले commands चला सकता है। API को केवल `127.0.0.1` से bind करने पर भी local users उस तक पहुंच सकते हैं। `enable_local_script_checks` setting अधिक सीमित है: यह HTTP API registrations के माध्यम से सबमिट किए गए script checks को बाहर रखती है। Consul ACLs सक्षम होने पर service registration के लिए `service:write` आवश्यक है; केवल `acl.default_policy=allow` वाली line यह साबित नहीं करती कि कोई anonymous caller registration कर सकता है। Agent की वास्तविक identity, loaded settings, API binding और authorization की एक साथ समीक्षा करें।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

चल रहे agent के `-config-dir` और `-config-file` arguments के ज़रिए संबंधित configuration तक पहुँचें, और केवल script-check तथा ACL field names और settings की जाँच करें। Configuration files में gossip keys या tokens भी हो सकते हैं; उन्हें shared logs में paste न करें। केवल इस स्थिति का पता लगाने के लिए service register न करें या health check न चलाएँ।

एक अलग local-file path तब मौजूद होता है, जब कम privileges वाला user root-run agent के `-config-dir` द्वारा नामित directory को **लिख और search** कर सकता हो: उस directory से नई `.hcl` या `.json` service definition लोड हो सकती है। Directory को list करने की अनुमति न होने पर भी, उसमें search और write की अनुमति से file जोड़ी जा सकती है। Root command execution के लिए पुष्टि करें कि agent वास्तव में उस directory को load करता है, उसकी **effective** script-check setting local definitions की अनुमति देती है, definition load होती है, और agent root privileges बनाए रखता है। [Consul के दस्तावेज़](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) बताते हैं कि कौन-सी settings और health-check definitions reload हो सकती हैं; script checks को enable करने के लिए restart की आवश्यकता हो सकती है, इसलिए installed version के व्यवहार की पुष्टि करें। जब ACLs agent को protect करते हों, तब [`consul reload` के लिए `agent:write` आवश्यक है](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); केवल KV write permission से यह अनुमति नहीं मिलती। Writable directory metadata को जाँच के संकेत के रूप में लें, authorized reload, restart या command execution के प्रमाण के रूप में नहीं। Configuration लिखे बिना या API call किए बिना paths, permissions और policy की जाँच करें।

## Service execution chain का अनुसरण करें

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories और socket activation की जाँच करें। Root-owned unit भी unsafe हो सकती है, अगर वह user-writable config या script पढ़ती है। [arbitrary file write](../interesting-files-permissions/write-to-root.md) पेज में service और unit के आम abuse paths शामिल हैं। जब एक बार की `ps` listing से short-lived jobs छूट जाएँ, तो उन्हें [pspy](https://github.com/DominicBreuker/pspy) या audit/process telemetry से monitor करें।

किसी custom **xinetd** service के लिए, enabled stanza के `server`, `user` और access controls का live listener तथा exact executable से मिलान करें। [`user` setting](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) spawned process की identity चुनती है, जबकि executable पर set-user-ID bit उसकी effective identity अलग से बदल सकता है, अगर [`execve` उस बदलाव की अनुमति देता है](https://man7.org/linux/man-pages/man2/execve.2.html)। ऐसा reachable privileged binary जो untrusted input स्वीकार करता हो, उसमें memory-safety bugs के लिए offline source या disassembly review करना उचित है, जैसे fixed buffer में unbounded [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)। Service mapping और set-user-ID metadata ऐसे bug के संकेत हैं, उसका प्रमाण नहीं; passive enumeration के दौरान crash inputs न भेजें और live privileged service को debug न करें।

Readable source वाले custom privileged listener में, copy operation जैसे [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) में इस्तेमाल होने वाली हर caller-controlled length की समीक्षा करें। केवल यह जाँचना कि मौजूदा write index fixed buffer के भीतर है, यह साबित नहीं करता कि **copy length** बची हुई जगह में फिट होती है; index के range में होने की पुष्टि के बाद `copy_length <= capacity - index` सत्यापित करें, और signedness तथा arithmetic overflow भी जाँचें। यह review lead तभी है जब input उस operation तक पहुँचता हो, lower-privileged user के लिए listener accessible हो, और process higher effective identity बनाए रखता हो। Source और process metadata को offline inspect करें; enumeration के दौरान live service को crash inputs न भेजें।

**Upstart** इस्तेमाल करने वाले systems पर, system job definitions `/etc/init/*.conf` के तहत हो सकती हैं। Current user द्वारा writable job file तभी मायने रखती है जब active init daemon उसी exact job को load करता हो, उसका `script` या `exec` stanza higher-privileged identity के रूप में चलता हो, और user किसी allowed `initctl` command या दूसरे वास्तविक trigger से उसे start कर सकता हो। अकेला sudo `initctl` grant यह साबित नहीं करता कि कोई job file writable है या modified job चलेगी। Enumeration के दौरान job को edit या start किए बिना exact job file permissions, effective run-as setting, active daemon और trigger जाँचें। [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) और [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) manuals देखें।

Readable autologin password file, जैसे `/etc/autologin/passwd` उन systems पर जिनका [boot job उसी exact path को पढ़ता है](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), credential-exposure lead है। पुष्टि करें कि boot job installed है और file का उपयोग करता है, फिर अलग से सत्यापित करें कि password किसी दूसरे local account या service के लिए valid है या नहीं। केवल filename से password reuse साबित नहीं होता; password को shared enumeration output में डाले बिना path और access metadata दर्ज करें।

किसी unit का `ExecStart=` या scheduled command, unlistable directory के भीतर script का exact pathname दिखा सकता है। [Directory search permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html) फिर भी current identity को उस ज्ञात path से गुज़रने दे सकती है; यह मानने के बजाय कि असफल directory listing उसे सुरक्षित रखती है, हर parent पर search access और file पर read permission की पुष्टि करें। Readable script में transfer credential हो सकता है, लेकिन दूसरे account तक पहुँचने के लिए वह credential valid रहना और वहाँ अलग से स्वीकार किया जाना ज़रूरी है। Shared logs में secret values छापे बिना path और permission evidence दर्ज करें।

Scheduled CommonJS Node.js script के लिए, bare imports जैसे `require('package')` की समीक्षा करें, भले ही script read-only हो। [Node, importing file के पास `node_modules` और फिर उसकी ancestor directories में खोजता है](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), और उसके बाद configured global paths पर जाता है। ऐसा lower-privileged user जो उन ancestor directories में से किसी एक को **write और search** कर सकता है, पहले match होने वाला package बना सकता है। पुष्टि करें कि exact import तक execution पहुँचता है, चुना गया package built-in module नहीं है, संबंधित path बनाया या बदला जा सकता है, installed runtime में module वहाँ resolve होता है, और higher-privileged job उसे भविष्य में load करेगी। Writable parent metadata केवल review का संकेत है; module रखे या job trigger किए बिना script और scheduler को passively inspect करें।

जब automated job packages को किसी अलग OS identity के तहत install करती है, तो private Python package index एक अन्य trust boundary है। Exact job और run-as account का configured index, चुने गए package names और इस बात से मिलान करें कि क्या lower-privileged user ऐसा package publish या replace कर सकता है जिसे job वास्तव में install करेगी। Source distribution बनाते समय build backend या legacy `setup.py` installer की identity के तहत चल सकता है; installed package को import करना execution का अलग रास्ता है। Index listener, readable upload password hash या package filename अकेले इस chain को साबित नहीं करते। Enumeration के दौरान कुछ upload या install किए बिना job, index authorization और package provenance की समीक्षा करें। [pip's build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) और [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/) देखें।

कोई privileged agent, अलग web service या container द्वारा managed task queue को poll कर सकता है। अगर lower-trust identity service के task database में लिख सकती है, तो पता करें कि क्या वे rows वास्तव में उस agent को serve की जाती हैं और क्या command task agent की OS identity के तहत चलती है। Database write access, target session या routing key, active polling, task authorization और agent के effective user की अलग-अलग पुष्टि करें। Container के भीतर root होना अपने-आप host-root access नहीं दर्शाता; boundary तभी पार होती है जब host-privileged consumer attacker-controlled task data execute करता है। Enumeration के दौरान queue में बदलाव या task भेजे बिना process, database-file और service metadata inspect करें।

इसके बजाय कोई recurring job application database configuration row से command पढ़ सकती है। पुष्टि करें कि lower-privileged database role उस exact row को बदल सकती है, active job बदलाव के बाद उसे पढ़ती है, और value higher OS identity के तहत shell या equivalent command runner तक पहुँचती है। Database write access या command जैसी दिखने वाली value अकेले execution साबित नहीं करती; passive enumeration के दौरान row बदले बिना job और permissions inspect करें।

Queued message में code के बजाय URL भी हो सकता है। अगर privileged consumer उस URL को fetch करके response को Lua या किसी अन्य executable plugin के रूप में load करता है, तो exact exchange और routing key पर publisher की permission, consumed queue की binding, fetch और plugin-load path, तथा worker की effective identity सत्यापित करें। [RabbitMQ exchanges के ज़रिए published messages route करता है](https://www.rabbitmq.com/docs/exchanges); broker listener या valid login अकेले इस worker तक delivery साबित नहीं करते। Captured cleartext broker credentials एक अलग lead हैं, जिसके लिए वास्तविक packet-capture access और readable traffic चाहिए; वे publish authorization साबित नहीं करते। Lua plugin shell commands तभी चला सकता है जब उसके runtime में [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) API उपलब्ध हो। Passive enumeration के दौरान traffic capture, messages publish या plugin fetch किए बिना configuration और code की समीक्षा करें।

जब privileged Python service local HTTP या socket endpoint expose करती है, तो readable script input-to-code path दिखा सकती है, भले ही उसकी file permissions बदलाव रोकती हों। Active process और unit identity का exact script, listener, route authorization और caller-controlled fields से मिलान करें। फिर parsing और validation के बाद उन fields को dynamic `eval()` या `exec()` sink तक trace करें। विशेष रूप से, request text से नया f-string बनाकर उसे evaluate करने पर attacker-supplied replacement fields Python expressions के रूप में interpret हो सकते हैं ([Python `eval` warning](https://docs.python.org/3/library/functions.html#eval); [f-string semantics](https://docs.python.org/3/reference/lexical_analysis.html#f-strings))। केवल `eval` match या loopback binding यह साबित नहीं करती कि untrusted caller sink तक पहुँचता है; enumeration के दौरान test payload भेजे बिना वास्तविक dataflow और access controls की समीक्षा करें।

उस route पर signed-request gate की भी अलग समीक्षा ज़रूरी है। अगर readable source signing key को demonstrably छोटे या predictable output space से प्राप्त करती है, और service एक valid signed sample expose करती है, तो signature शायद privileged `eval()` sink की सुरक्षा न करे। Exact key derivation और verifier, live service identity और local caller access, तथा signed field के sink तक पहुँचने की पुष्टि करें; Python के [`random` module](https://docs.python.org/3/library/random.html) का import या sample signature इनमें से किसी भी condition को साबित नहीं करता। Python यह भी चेतावनी देता है कि `__builtins__` को सीमित करना untrusted `eval()` input के लिए [security boundary नहीं है](https://docs.python.org/3/library/functions.html#eval)। Key analysis offline रखें और passive enumeration के दौरान forged requests न भेजें।

खाली लेकिन writable `/etc/systemd/system/<unit>.service.d` directory तब भी मायने रखती है जब unit file और सभी मौजूदा drop-ins सुरक्षित हों: user नई `.conf` override बना सकता है। जाँचें कि directory current identity के लिए writable और searchable है, unit loaded है और root के रूप में चलती है, तथा daemon reload के बाद restart होगा या नहीं। Reload या restart की permission, timer या बाद का boot बदलाव को प्रभावी बना सकता है; केवल directory write access से वह तुरंत execute नहीं होता।

Running services के लिए, unit के `[Service]` section में दिए literal `EnvironmentFile=` paths देखें, उन files सहित जिनके नाम `.env` से शुरू नहीं होते। अगर low-privilege user उनमें से कोई file पढ़ सकता है, तो values को shared logs में छापे बिना `API_TOKEN` या `APP_SECRET_KEY` जैसे credential-सरीखे key names की सूची बनाएँ। Effective unit का आकलन करते समय drop-in overrides और optional `-` prefixes जाँचें। Readability credential-exposure lead है; escalation के लिए उस value का privileged action के लिए valid होना भी ज़रूरी है।

### Untrusted uploads की privileged processing

Root के रूप में चलने वाला file watcher, user-writable upload directory से files को short-lived parser या extractor तक पहुँचा सकता है। Running watcher की parent script या service का पता लगाएँ और exact directory, वहाँ files कौन रख सकता है, child command और उसके arguments, तथा child जिस identity के तहत चलता है—इनकी पुष्टि करें। Process snapshot watcher दिखा सकता है, लेकिन uploads के बीच चलने वाले extractor को छोड़ सकता है। Passive enumeration के दौरान test payload न रखें और watcher को trigger न करें।

एक ठोस उदाहरण Binwalk का extraction mode (`-e`) है, जो attacker-controlled PFS data process करता है। [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) के कारण PFS extractor अपने intended directory के बाहर लिख सकता था, जिसमें ऐसा plugin path भी शामिल था जिसे Binwalk बाद में load कर सकता था। Upstream ने fix [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) में शामिल किया, लेकिन distribution backports के कारण प्रदर्शित version पुराना दिख सकता है; लागू होने का आकलन करने से पहले installed package की security status जाँचें, जैसे [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)। केवल Binwalk version installed होना privilege-escalation path साबित नहीं करता: extraction वास्तव में किसी अधिक privileged process द्वारा ऐसे input पर invoke होना चाहिए जिसे lower-privileged user नियंत्रित कर सके।

### Local dependencies के साथ scheduled builds

Scheduled `cargo run` job के run-as user के रूप में source को फिर से compile करता है। केवल main crate नहीं, manifest की local `{ path = "..." }` dependencies और हर dependency के source तथा parent-directory permissions inspect करें। अगर lower-privileged user ऐसी dependency बदल सकता है जिसे Cargo compile करता है और scheduled job उसका result चलाती है, तो compiled code उस run-as user के रूप में execute हो सकता है। Effective scheduler command, working directory, dependency resolution और rebuild होने की पुष्टि करें; कहीं और writable Rust source file होना केवल एक lead है। Passive triage के लिए manifest और path metadata पढ़ना पर्याप्त है। [Cargo path-dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) देखें।

## Xvfb framebuffer files

`Xvfb -fbdir <directory>` अपने virtual screens के लिए `Xvfb_screen<n>` नाम की memory-mapped files इस्तेमाल करता है। अगर किसी अन्य user की running Xvfb process ऐसी directory बताती है जिसकी screen files current user पढ़ सकता है, तो framebuffer उस user के desktop content को उजागर कर सकता है। Process, file ownership और permissions की एक साथ पुष्टि करें; केवल readable file यह साबित नहीं करती कि screen पर उपयोगी content है। Shared enumeration output में image data copy किए बिना पहले paths और metadata inspect करें। [Xvfb manual](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) में `-fbdir` का व्यवहार बताया गया है।

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` मैनुअल](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` मैनुअल](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` मैनुअल](https://man.openbsd.org/ipcs.1)
4. [Consul agent कॉन्फ़िगरेशन: script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent service registration API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL कॉन्फ़िगरेशन](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice सहायता: बाहरी API clients के लिए socket खोलना](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
