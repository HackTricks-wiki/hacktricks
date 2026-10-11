# Process Enumeration और Service Paths

{{#include ../../banners/hacktricks-training.md}}

उपयोगी सवाल यह है कि कौन-सा privileged process ऐसा data या code इस्तेमाल करता है जिसे कम privileged user प्रभावित कर सकता है। Process tree, live environment, open files, और उस unit या script की जाँच करें जिसने हर candidate को लॉन्च किया।

## Processes और ownership का मानचित्र बनाएँ

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Cross-user parent-child संबंध सामान्य हो सकता है, लेकिन किसी अप्रत्याशित बदलाव पर parent command, arguments, executable, working directory और संदर्भित files की समीक्षा करें। owner और login context को समझने के लिए [users and sessions](../user-information/user-and-session-triage.md) देखें।

### Local virtual-machine consoles

QEMU process के `-spice` options की समीक्षा उसके listening address के साथ करें। [QEMU दस्तावेज़](https://www.qemu.org/docs/master/system/qemu-manpage.html) के अनुसार, `disable-ticketing` SPICE clients को authentication के बिना connect करने देता है। Loopback पर bind किया गया listener भी अन्य local host users के लिए संभावित रूप से reachable हो सकता है। Command line को exposed console मानने से पहले live listener, authentication options और local access की पुष्टि करें। Console control **guest** को प्रभावित करता है; guest account प्राप्त करने या उसकी boot state बदलने के लिए guest-side की अलग शर्तें पूरी होनी चाहिए, और इससे virtualization host पर root access नहीं मिलता। Passive enumeration के दौरान guest से connect किए या उसे reboot किए बिना process arguments और socket metadata पढ़ें।

भले ही पहला shell उस account की files तक पहुँच न सके, locally reachable web interface अपने service account के रूप में code execute कर सकता है। उदाहरण के लिए, CVE-2023-0297 ने pyLoad के `/flash/addcrypted2` handling को प्रभावित किया, जब untrusted JavaScript, Python imports enabled होने पर Js2Py तक पहुँचा; [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) ने `pyimport` को disable किया। किसी pyLoad process को escalation path मानने से पहले running process owner, listening address, endpoint exposure और installed patch या vendor backport का मिलान करें। केवल process name, open port या package version exposure साबित नहीं करते; passive enumeration में execution payload न भेजें।

### Privileged login shells sharing a terminal

ऐसा privileged interactive shell, जो स्वतंत्र pseudo-terminal के बिना `su --login <user>` चलाता है, अपना terminal कम-privileged login shell के साथ साझा कर सकता है। यदि उस user की startup file को नियंत्रित किया जा सकता है और उसमें मौजूद code terminal input inject करने के लिए `TIOCSTI` का उपयोग कर सकता है, तो privileged shell के फिर से सक्रिय होने पर input उस तक पहुँच सकता है। [util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) साझा terminal के जोखिम का वर्णन करता है और interactive उपयोग के लिए `su --pty`/`-P` की अनुशंसा करता है; `su -c` controlling terminal के बिना एक अलग session शुरू करता है। इस जोखिम के लिए वास्तविक parent shell, terminal संबंध, target startup file और kernel policy की पुष्टि आवश्यक है। केवल process name या `su -l` argument समीक्षा का संकेत भर है।

देखे गए process tree और TTY columns की जाँच करें, फिर readable launcher तथा startup-file के ownership/permissions देखें। Linux पर, मौजूद होने पर `/proc/sys/dev/tty/legacy_tiocsti` policy को समझने में मदद कर सकता है; इसका न होना safety का प्रमाण नहीं है। [Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) के अनुसार, Linux 6.2 से यह sysctl false होने पर इस operation के लिए `CAP_SYS_ADMIN` की आवश्यकता हो सकती है। Host की enumeration के लिए ioctl invoke न करें।

कभी-कभी database account, सीधे filesystem write access के बिना target user की startup file बदल सकता है। PostgreSQL server-side `COPY ... TO 'filename'` database server के OS account के रूप में लिखता है, लेकिन [PostgreSQL की सीमाएँ](https://www.postgresql.org/docs/current/sql-copy.html) इस file form को database superusers या `pg_write_server_files` जैसी roles तक सीमित करती हैं। Database role और server OS file permissions, दोनों की पुष्टि करें; application connection string अपने आप file-write authority नहीं देती। इस chain का आकलन करते समय privileged launcher और database account की capabilities को अलग रखें।

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

हटाए गए executables और हटाई गईं लेकिन खुली files, अपने आखिरी descriptor के बंद होने तक referenced रहती हैं। वे सबूत या accessible secrets को बनाए रख सकती हैं। Process environments और memory में credentials हो सकते हैं, लेकिन किसी दूसरे process को पढ़ना ownership, `/proc` mount options, Yama ptrace policy और अन्य security controls से सीमित होता है। संबंधित techniques के लिए [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) और [post-exploitation credential hunting](../post-exploitation/README.md) देखें।

सहेजे गए syscall traces भी file-permission की सीमा होते हैं। [`strace` syscall arguments को एक output file में रिकॉर्ड करता है](https://man7.org/linux/man-pages/man1/strace.1.html), इसलिए [`execve` arguments](https://man7.org/linux/man-pages/man2/execve.2.html) वाला readable trace ऐसा password उजागर कर सकता है जिसे किसी privileged job ने अपनी command line पर पास किया हो। पहले पुष्टि करें कि मौजूदा user उस खास trace को पढ़ सकता है और argument में वास्तव में credential मौजूद है; बाद में Unix account में बदलाव के लिए अलग से साबित करना होगा कि credential वहाँ स्वीकार किया जाता है। Routine enumeration के दौरान हर trace को scan किए या उसका content दिखाए बिना, file metadata एक उपयोगी passive lead है।

## Privileged office automation sockets

LibreOffice और OpenOffice, `--accept=socket,host=<host>,port=<port>;urp;` argument के ज़रिए अपना UNO API उपलब्ध करा सकते हैं। किसी reachable endpoint वाला root-owned office process, कम privileges वाले local user को उस process के security context में API services invoke करने दे सकता है। `SystemShellExecute` service में system command launch करने का operation शामिल है। Loopback से bind करने पर remote reachability सीमित होती है, लेकिन जब तक कोई अन्य control access को न रोके, socket local users के लिए reachable रहता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

प्रक्रिया के owner, सटीक `--accept` argument और मौजूदा listening address और port का मिलान करें। ऐसा configured acceptor जो bind करने में विफल रहा हो, केवल एक सुराग है; passive enumeration के दौरान API से connect न करें और न ही उसे invoke करें। केवल इस स्थिति की जाँच करने के लिए कोई privileged office instance शुरू करने से बचें।

## Privileged processes द्वारा उपयोग की गई System V shared memory

Root-owned helper एक System V shared-memory segment बना सकता है, जिसमें कोई अन्य user लिख सकता है। यदि helper बाद में उस segment के data पर किसी shell command या अन्य संवेदनशील operation में भरोसा करता है, तो यह segment privilege boundary पार करता है, भले ही executable और उसकी files सुरक्षित हों। `shmget()` अपनी access permissions flags के निचले नौ bits से लेता है; mode `0666` अन्य users को लिखने की अनुमति देता है, जबकि `IPC_CREAT` flag उन permissions को सीमित नहीं करता। `ipcs -m` से सक्रिय segments का passive रूप से निरीक्षण करें और उनके owner, mode और lifetime का privileged process तथा उसके input handling से मिलान करें। केवल world-writable segment होना command execution का प्रमाण नहीं है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments, `/dev/shm` के अंतर्गत POSIX shared-memory files से अलग होते हैं। केवल कुछ पल के लिए बनाया गया segment, `ipcs` के एक snapshot में न दिखे; इसलिए खाली output से यह साबित नहीं होता कि shared memory इस्तेमाल करने वाला helper मौजूद नहीं है। उसके source या binary के व्यवहार और उसे चलाने वाले किसी भी `sudo` rule की समीक्षा करें; enumeration के दौरान segment दिखाने के लिए privileged helper को न चलाएँ। [IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) बताती है कि namespaces visibility को कैसे प्रभावित करते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul, अपने agent की operating-system identity के साथ script health checks चला सकता है। यदि कोई agent root के रूप में चलता है, `enable_script_checks` सक्षम करता है, और किसी कम-privileged user को local HTTP API के ज़रिए script check वाली service register करने देता है, तो वह user root के रूप में चलने वाले commands चला सकता है। API को केवल `127.0.0.1` से bind करने पर भी local users उस तक पहुँच सकते हैं। `enable_local_script_checks` setting का दायरा सीमित है: यह HTTP API registrations के ज़रिए submit किए गए script checks को रोकती है। Consul ACLs सक्षम होने पर service registration के लिए `service:write` आवश्यक है; केवल `acl.default_policy=allow` वाली line यह साबित नहीं करती कि कोई anonymous caller registration कर सकता है। Agent की वास्तविक identity, loaded settings, API binding और authorization—इन सभी की एक साथ समीक्षा करें।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

चल रहे agent के `-config-dir` और `-config-file` arguments के ज़रिए संबंधित configuration तक पहुँचें, और केवल script-check तथा ACL field names और settings की जाँच करें। Configuration files में gossip keys या tokens भी हो सकते हैं; उन्हें साझा logs में paste करने से बचें। केवल इस स्थिति को enumerate करने के लिए कोई service register न करें या health check न चलाएँ।

एक अलग local-file path तब मौजूद होता है, जब कम privileges वाला user root-run agent के `-config-dir` द्वारा निर्दिष्ट directory में **write और search** कर सकता है: उस directory से नई `.hcl` या `.json` service definition load हो सकती है। Directory listing की अनुमति न होने पर भी, directory में search और write की अनुमति file जोड़ने के लिए पर्याप्त हो सकती है। Root command execution के लिए पुष्टि करें कि agent वास्तव में उस directory को load करता है, उसकी **effective** script-check setting local definitions की अनुमति देती है, definition load हो चुकी है, और agent के पास root privileges बने हुए हैं। [Consul के दस्तावेज़](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) बताते हैं कि किन settings और health-check definitions को reload किया जा सकता है; script checks को enable करने के लिए स्वयं restart की आवश्यकता हो सकती है, इसलिए installed version का behavior सत्यापित करें। जब ACLs agent की सुरक्षा करते हैं, तब [`consul reload` के लिए `agent:write` आवश्यक है](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); केवल KV write permission से यह अनुमति नहीं मिलती। Writable directory metadata को review का संकेत मानें, अधिकृत reload, restart या command execution का प्रमाण नहीं। Configuration लिखे बिना या API call किए बिना paths, permissions और policy की जाँच करें।

## Service execution chain का अनुसरण करें

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories और socket activation की जाँच करें। Root-owned unit भी असुरक्षित हो सकती है, अगर वह user-writable config या script पढ़ती है। [arbitrary file write](../interesting-files-permissions/write-to-root.md) पेज में service और unit के आम abuse paths शामिल हैं। जब एक बार की `ps` listing से short-lived jobs छूट जाएँ, तो उन्हें [pspy](https://github.com/DominicBreuker/pspy) या audit/process telemetry से monitor करें।

Custom **xinetd** service के लिए, enabled stanza के `server`, `user` और access controls का मिलान live listener और सटीक executable से करें। [`user` setting](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) spawned process की identity चुनती है, जबकि executable पर set-user-ID bit उसकी effective identity अलग से बदल सकता है, यदि [`execve` उस बदलाव की अनुमति देता है](https://man7.org/linux/man-pages/man2/execve.2.html)। Untrusted input स्वीकार करने वाला reachable privileged binary, memory-safety bugs के लिए offline source या disassembly review का कारण है—जैसे fixed buffer में बिना सीमा वाला [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)। Service mapping और set-user-ID metadata ऐसे bug के संकेत हैं, उसका प्रमाण नहीं; passive enumeration के दौरान crash inputs न भेजें और live privileged service को debug न करें।

Readable source वाले custom privileged listener के लिए, copy operation जैसे [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) में इस्तेमाल होने वाली हर caller-controlled length की समीक्षा करें। सिर्फ यह जाँचना कि मौजूदा write index fixed buffer के भीतर है, यह साबित नहीं करता कि **copy length** बची हुई जगह में फिट होती है; index के range में होने की पुष्टि के बाद `copy_length <= capacity - index` सत्यापित करें, और signedness तथा arithmetic overflow भी जाँचें। यह review lead तभी है, जब input उस operation तक पहुँचता हो, lower-privileged user के लिए listener accessible हो, और process की higher effective identity बनी रहती हो। Source और process metadata को offline जाँचें; enumeration के दौरान live service को crash inputs न भेजें।

**Upstart** इस्तेमाल करने वाले systems पर, system job definitions `/etc/init/*.conf` में हो सकती हैं। Current user के लिए writable job file तभी मायने रखती है, जब active init daemon वही job load करता हो, उसका `script` या `exec` stanza higher-privileged identity के रूप में चलता हो, और user उसे किसी अनुमत `initctl` command या अन्य वास्तविक trigger से शुरू कर सकता हो। अकेला sudo `initctl` grant यह साबित नहीं करता कि कोई job file writable है या modified job चलेगी। Enumeration के दौरान job को edit या start किए बिना, सटीक job file की permissions, effective run-as setting, active daemon और trigger जाँचें। [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) और [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) manuals देखें।

Readable autologin password file—जैसे `/etc/autologin/passwd`, उन systems पर जिनका [boot job ठीक इसी path को पढ़ता है](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)—credential exposure का संकेत है। पुष्टि करें कि boot job installed है और उसी file का उपयोग करती है; फिर अलग से जाँचें कि password किसी अन्य local account या service के लिए valid है या नहीं। सिर्फ filename से password reuse साबित नहीं होता; password को shared enumeration output में डाले बिना path और access metadata दर्ज करें।

किसी unit का `ExecStart=` या scheduled command, unlistable directory के अंदर मौजूद script का सटीक pathname दिखा सकता है। [Directory search permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html) के कारण current identity उस ज्ञात path से फिर भी गुजर सकती है; यह मानने के बजाय कि असफल directory listing से file सुरक्षित है, हर parent पर search access और file पर read permission की पुष्टि करें। Readable script में transfer credential हो सकता है, लेकिन दूसरे account तक पहुँचने के लिए वह credential valid रहना चाहिए और वहाँ स्वतंत्र रूप से स्वीकार भी होना चाहिए। Secret values को shared logs में छापे बिना path और permission evidence दर्ज करें।

Scheduled CommonJS Node.js script के लिए, bare imports जैसे `require('package')` की समीक्षा करें, भले ही script खुद read-only हो। [Node, importing file के पास और फिर उसके ancestor directories में `node_modules` खोजता है](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), और उसके बाद configured global paths पर जाता है। इनमें से किसी ancestor directory पर **write और search** कर सकने वाला lower-privileged user, पहले match होने वाला package बना सकता है। पुष्टि करें कि सटीक import तक execution पहुँचता है, चुना गया package built-in module नहीं है, संबंधित path बनाया या बदला जा सकता है, installed runtime में module वहीं resolve होता है, और higher-privileged job उसे भविष्य के invocation में load करेगी। Writable parent metadata केवल review का संकेत है; module रखे या job trigger किए बिना script और scheduler की passive समीक्षा करें।

जब automated job किसी अलग OS identity के तहत packages install करती है, तो private Python package index भी एक trust boundary है। सटीक job और run-as account का मिलान उसके configured index, चुने गए package names और इस बात से करें कि lower-privileged user उस package को publish या replace कर सकता है या नहीं जिसे job वास्तव में install करेगी। Source distribution बनाने के दौरान installer's identity के तहत उसका build backend या legacy `setup.py` चल सकता है; installed package import करना execution का अलग path है। Index listener, readable upload password hash या package filename अकेले इस chain को साबित नहीं करते। Enumeration के दौरान कुछ upload या install किए बिना job, index authorization और package provenance की समीक्षा करें। [pip's build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) और [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/) देखें।

एक privileged agent, अलग web service या container द्वारा managed task queue को poll कर सकता है। यदि lower-trust identity service के task database में लिख सकती है, तो पता करें कि वे rows वास्तव में उस agent को serve होती हैं या नहीं और command task agent की OS identity के तहत चलती है या नहीं। Database write access, target session या routing key, active polling, task authorization और agent के effective user की अलग-अलग पुष्टि करें। Container के अंदर root होने का मतलब अपने-आप host-root access नहीं होता; boundary तभी पार होती है जब host-privileged consumer attacker-controlled task data execute करे। Enumeration के दौरान queue में बदलाव या task भेजे बिना process, database-file और service metadata जाँचें।

किसी recurring job में command, application database की configuration row से भी पढ़ी जा सकती है। पुष्टि करें कि lower-privileged database role उस सटीक row को बदल सकती है, active job बदलाव के बाद उसे पढ़ती है, और value higher OS identity के तहत shell या equivalent command runner तक पहुँचती है। Database write access या command जैसी दिखने वाली value अकेले execution साबित नहीं करती; passive enumeration के दौरान row बदले बिना job और permissions जाँचें।

Queued message में code के बजाय URL भी हो सकता है। यदि privileged consumer उस URL को fetch करके response को Lua या किसी अन्य executable plugin के रूप में load करता है, तो exact exchange और routing key पर publisher की permission, consumed queue से binding, fetch और plugin-load path, तथा worker की effective identity सत्यापित करें। [RabbitMQ, published messages को exchanges के ज़रिए route करता है](https://www.rabbitmq.com/docs/exchanges); broker listener या valid login अकेले इस worker तक delivery साबित नहीं करते। Captured cleartext broker credentials अलग संकेत हैं, जिनके लिए वास्तविक packet-capture access और readable traffic जरूरी है; वे publish authorization साबित नहीं करते। Lua plugin shell commands तभी चला सकता है, जब उसके runtime में [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) API उपलब्ध हो। Passive enumeration के दौरान traffic capture, message publish या plugin fetch किए बिना configuration और code की समीक्षा करें।

जब privileged Python service local HTTP या socket endpoint expose करती है, तो readable script input-to-code path दिखा सकती है, भले ही उसकी file permissions बदलाव रोकती हों। Active process और unit identity का मिलान exact script, listener, route authorization और caller-controlled fields से करें। फिर parsing और validation से dynamic `eval()` या `exec()` sink तक उन fields को trace करें। खासकर, request text से नया f-string बनाकर उसे evaluate करने पर attacker-supplied replacement fields को Python expressions के रूप में interpret किया जा सकता है ([Python `eval` warning](https://docs.python.org/3/library/functions.html#eval); [f-string semantics](https://docs.python.org/3/reference/lexical_analysis.html#f-strings))। सिर्फ `eval` का match या loopback binding यह साबित नहीं करता कि untrusted caller sink तक पहुँचता है; enumeration के दौरान test payload भेजे बिना वास्तविक dataflow और access controls की समीक्षा करें।

उस route पर signed-request gate की अलग से समीक्षा करें। यदि readable source से साबित हो कि signing key बहुत छोटे या predictable output space से निकाली जाती है, और service एक valid signed sample expose करती है, तो signature privileged `eval()` sink की सुरक्षा नहीं कर सकती। सटीक key derivation और verifier, live service identity तथा local caller access, और signed field के sink तक पहुँचने की पुष्टि करें; Python के [`random` module](https://docs.python.org/3/library/random.html) का import या sample signature इनमें से किसी भी शर्त को साबित नहीं करता। Python यह भी चेतावनी देता है कि `__builtins__` को सीमित करना, untrusted `eval()` input के लिए [security boundary नहीं है](https://docs.python.org/3/library/functions.html#eval)। Key analysis offline रखें और passive enumeration के दौरान forged requests न भेजें।

खाली लेकिन writable `/etc/systemd/system/<unit>.service.d` directory मायने रखती है, भले ही unit file और सभी मौजूदा drop-ins सुरक्षित हों: user नया `.conf` override बना सकता है। जाँचें कि directory current identity के लिए writable और searchable है, unit loaded है और root के रूप में चलती है, और daemon reload के बाद restart होगा या नहीं। Reload या restart की permission, timer या बाद का boot बदलाव को प्रभावी बना सकता है; केवल directory में write access से वह तुरंत execute नहीं होता।

चल रही services के लिए, unit के `[Service]` section में दिए literal `EnvironmentFile=` paths देखें, उन files समेत जिनके नाम `.env` से शुरू नहीं होते। यदि low-privilege user उनमें से कोई file पढ़ सकता है, तो `API_TOKEN` या `APP_SECRET_KEY` जैसे credential-जैसे key names को values को shared logs में छापे बिना सूचीबद्ध करें। Effective unit जाँचते समय drop-in overrides और वैकल्पिक `-` prefixes देखें। Readability credential exposure का संकेत है; escalation के लिए उस value का privileged action के लिए valid होना अभी भी जरूरी है।

### Untrusted uploads की privileged processing

Root के रूप में चलने वाला file watcher, user-writable upload directory से files को short-lived parser या extractor तक पहुँचा सकता है। Running watcher की parent script या service का पता लगाएँ और exact directory, उसमें files कौन रख सकता है, child command और उसके arguments, तथा child जिस identity के तहत चलता है—इनकी पुष्टि करें। Process snapshot में watcher दिख सकता है, लेकिन uploads के बीच चलने वाला extractor छूट सकता है। Passive enumeration के दौरान test payload न रखें और watcher trigger न करें।

एक ठोस उदाहरण Binwalk का extraction mode (`-e`) है, जो attacker-controlled PFS data process करता है। [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) के कारण PFS extractor intended directory के बाहर लिख सकता था, जिसमें ऐसा plugin path भी शामिल था जिसे Binwalk बाद में load कर सकता था। Upstream ने fix [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) में शामिल किया, लेकिन distribution backports के कारण प्रदर्शित version पुराना हो सकता है; लागू होने का आकलन करने से पहले installed package की security status जाँचें, जैसे [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)। सिर्फ Binwalk version installed होना privilege-escalation path साबित नहीं करता: extraction को वास्तव में किसी अधिक privileged process द्वारा ऐसे input पर invoke किया जाना चाहिए जिसे lower-privileged user नियंत्रित कर सके।

### Local dependencies वाले scheduled builds

Scheduled `cargo run`, job के run-as user के रूप में source को दोबारा compile करता है। Manifest में मौजूद local `{ path = "..." }` dependencies और हर dependency के source तथा parent-directory permissions जाँचें—सिर्फ main crate नहीं। यदि lower-privileged user ऐसी dependency बदल सकता है जिसे Cargo compile करता है और scheduled job उसका result चलाती है, तो compiled code उस run-as user के रूप में execute हो सकता है। Effective scheduler command, working directory, dependency resolution और rebuild होगा या नहीं—इनकी पुष्टि करें; कहीं और मौजूद writable Rust source file केवल एक संकेत है। Passive triage के लिए manifest और path metadata पढ़ना पर्याप्त है। [Cargo path-dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) देखें।

## Xvfb framebuffer files

`Xvfb -fbdir <directory>` अपने virtual screens के लिए `Xvfb_screen<n>` नाम की memory-mapped files इस्तेमाल करता है। यदि किसी अन्य user की running Xvfb process ऐसी directory बताती है जिसकी screen files current user पढ़ सकता है, तो framebuffer उस user के desktop content को उजागर कर सकता है। Process, file ownership और permissions—तीनों की एक साथ पुष्टि करें; सिर्फ readable file से यह साबित नहीं होता कि screen पर उपयोगी content है। Shared enumeration output में image data copy किए बिना पहले paths और metadata देखें। [Xvfb manual](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) में `-fbdir` का व्यवहार बताया गया है।

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` मैनुअल](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` मैनुअल](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` मैनुअल](https://man.openbsd.org/ipcs.1)
4. [Consul एजेंट कॉन्फ़िगरेशन: script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul एजेंट service registration API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL कॉन्फ़िगरेशन](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice सहायता: बाहरी API clients के लिए socket खोलना](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
