# प्रोसेसों की गणना और सर्विस पाथ

{{#include ../../banners/hacktricks-training.md}}

उपयोगी सवाल यह है कि कौन-सी privileged process ऐसा डेटा या कोड इस्तेमाल करती है जिसे कम privileges वाला user प्रभावित कर सकता है। प्रोसेस ट्री, live environment, खुली फ़ाइलों और हर संभावित प्रक्रिया को शुरू करने वाली unit या script की जाँच करें।

## प्रोसेस और स्वामित्व का मानचित्र बनाएँ

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Cross-user parent-child संबंध सामान्य हो सकता है, लेकिन किसी अप्रत्याशित बदलाव की स्थिति में parent command, arguments, executable, working directory और संदर्भित files की समीक्षा करें। owner और login context को समझने के लिए [users and sessions](../user-information/user-and-session-triage.md) का उपयोग करें।

### Local virtual-machine consoles

QEMU process के `-spice` options की उसके listening address के साथ समीक्षा करें। [QEMU documents](https://www.qemu.org/docs/master/system/qemu-manpage.html) के अनुसार, `disable-ticketing` SPICE clients को authentication के बिना connect करने देता है। Loopback पर bound listener भी अन्य local host users के लिए संभावित रूप से reachable हो सकता है। Command line को exposed console मानने से पहले live listener, authentication options और local access की पुष्टि करें। Console control **guest** को प्रभावित करता है; guest account प्राप्त करने या उसकी boot state बदलने के लिए guest-side की अलग शर्तें पूरी होनी चाहिए, और इससे virtualization host पर root access नहीं मिलता। Passive enumeration के दौरान guest से connect किए बिना या उसे reboot किए बिना process arguments और socket metadata पढ़ें।

एक locally reachable web interface अपने service account के रूप में code execute कर सकता है, भले ही पहली shell उस account की files तक पहुँच न सके। उदाहरण के लिए, CVE-2023-0297 ने pyLoad के `/flash/addcrypted2` handling को प्रभावित किया था, जब untrusted JavaScript, Python imports enabled होने पर, Js2Py तक पहुँचा; [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) ने `pyimport` को disabled कर दिया। किसी pyLoad process को escalation path मानने से पहले running process के owner, listening address, endpoint exposure और installed patch या vendor backport का मिलान करें। केवल process name, open port या package version से exposure सिद्ध नहीं होता; passive enumeration में execution payload न भेजें।

### एक terminal साझा करने वाले privileged login shells

ऐसा privileged interactive shell, जो independent pseudo-terminal के बिना `su --login <user>` चलाता है, अपना terminal lower-privileged login shell के साथ साझा कर सकता है। यदि उस user की startup file को नियंत्रित किया जा सकता है और उसमें मौजूद code `TIOCSTI` का उपयोग करके terminal input inject कर सकता है, तो privileged shell के फिर से सक्रिय होने पर वह input उस तक पहुँच सकता है। [The util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) shared-terminal के जोखिम का वर्णन करता है और interactive use के लिए `su --pty`/`-P` की अनुशंसा करता है; `su -c` controlling terminal के बिना एक अलग session शुरू करता है। इस जोखिम के लिए actual parent shell, terminal संबंध, target startup file और kernel policy की पुष्टि आवश्यक है। केवल process name या `su -l` argument समीक्षा का संकेत है।

देखे गए process tree और TTY columns का निरीक्षण करें, फिर readable launcher तथा startup file के ownership/permissions की जाँच करें। Linux पर, मौजूद होने पर `/proc/sys/dev/tty/legacy_tiocsti` policy को समझने में मदद कर सकता है; इसका न होना सुरक्षा का प्रमाण नहीं है। [The Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) बताता है कि Linux 6.2 से, जब यह sysctl false हो, तो इस operation के लिए `CAP_SYS_ADMIN` आवश्यक हो सकता है। Host की enumeration करने के लिए ioctl invoke न करें।

कभी-कभी database account बिना direct filesystem write access के target user की startup file बदल सकता है। PostgreSQL server-side `COPY ... TO 'filename'` database server के OS account के रूप में लिखता है, लेकिन [PostgreSQL limits](https://www.postgresql.org/docs/current/sql-copy.html) इस file form को database superusers या `pg_write_server_files` जैसी roles तक सीमित करता है। Database role और server OS file permissions, दोनों की पुष्टि करें; केवल application connection string से file-write authority नहीं मिलती। Chain का आकलन करते समय privileged launcher और database account की capabilities को अलग-अलग रखें।

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

हटाए गए executables और हटाई गईं लेकिन खुली फ़ाइलें, अपने आख़िरी descriptor के बंद होने तक संदर्भित रहती हैं। वे साक्ष्य या सुलभ secrets को बनाए रख सकती हैं। Process environments और memory में credentials हो सकते हैं, लेकिन किसी अन्य process को पढ़ना ownership, `/proc` mount options, Yama ptrace policy और अन्य security controls से सीमित होता है। संबंधित techniques के लिए [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) और [post-exploitation credential hunting](../post-exploitation/README.md) देखें।

सहेजे गए syscall traces भी file-permission की एक सीमा हैं। [`strace` syscall arguments को एक output file में रिकॉर्ड करता है](https://man7.org/linux/man-pages/man1/strace.1.html), इसलिए [`execve` arguments](https://man7.org/linux/man-pages/man2/execve.2.html) वाला कोई पढ़ा जा सकने वाला trace ऐसा password उजागर कर सकता है जिसे किसी privileged job ने अपनी command line पर पास किया हो। पहले पुष्टि करें कि मौजूदा user उस विशेष trace को पढ़ सकता है और argument में सचमुच credential मौजूद है; बाद में Unix-account transition के लिए अलग से साबित करना होगा कि वहाँ वह credential स्वीकार किया जाता है। Routine enumeration के दौरान हर trace को scan किए या उसकी सामग्री दिखाए बिना, file metadata एक उपयोगी passive lead है।

## विशेषाधिकार-प्राप्त office automation sockets

LibreOffice और OpenOffice अपने UNO API को `--accept=socket,host=<host>,port=<port>;urp;` argument के ज़रिए उपलब्ध करा सकते हैं। Reachable endpoint वाला root-owned office process, कम विशेषाधिकार वाले किसी local user को उस process के security context में API services invoke करने दे सकता है। `SystemShellExecute` service में system command launch करने का एक operation शामिल है। Loopback से bind करने पर remote reachability सीमित होती है, लेकिन जब तक कोई अन्य control access को रोक न दे, local users उस socket तक पहुँच सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

process owner, exact `--accept` argument, और current listening address तथा port का correlation करें। ऐसा configured acceptor जो bind करने में विफल रहा हो, केवल एक सुराग है; passive enumeration के दौरान API से connect न करें और न ही उसे invoke करें। केवल इस स्थिति को जाँचने के लिए privileged office instance शुरू करने से बचें।

## Privileged processes द्वारा उपयोग की गई System V shared memory

Root-owned helper ऐसा System V shared-memory segment बना सकता है जिसमें कोई दूसरा user लिख सके। यदि helper बाद में उस segment के data पर किसी shell command या अन्य sensitive operation में भरोसा करता है, तो segment privilege boundary पार करता है—भले ही executable और उसकी files सुरक्षित हों। `shmget()` अपनी access permissions flags के निचले नौ bits से लेता है; mode `0666` अन्य users को लिखने की अनुमति देता है, जबकि `IPC_CREAT` flag उन permissions को सीमित नहीं करता। `ipcs -m` से active segments का passive निरीक्षण करें और उनके owner, mode तथा lifetime का privileged process और उसके input handling से correlation करें। केवल world-writable segment से command execution साबित नहीं होता।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments, `/dev/shm` के अंतर्गत POSIX shared-memory files से अलग होते हैं। केवल कुछ पल के लिए बनाया गया segment किसी एक `ipcs` snapshot में मौजूद न हो, इसलिए खाली output से यह साबित नहीं होता कि shared memory का उपयोग करने वाला helper मौजूद नहीं है। उसके source या binary के व्यवहार की समीक्षा करें और यह भी देखें कि उसे launch करने वाला कोई `sudo` rule है या नहीं; enumeration के दौरान segment दिखाने के लिए privileged helper को invoke न करें। [IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) बताती है कि namespaces visibility को कैसे प्रभावित करते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent के script checks

Consul, अपने agent की operating-system identity के साथ script health checks चला सकता है। अगर कोई agent root के रूप में चलता है, `enable_script_checks` को enable करता है, और कम privileges वाले user को local HTTP API के ज़रिए script check के साथ service register करने देता है, तो वह user root के रूप में चलने वाले commands चला सकता है। API को केवल `127.0.0.1` से bind करने पर भी local users उस तक पहुँच सकते हैं। `enable_local_script_checks` setting का दायरा सीमित है: यह HTTP API registrations के ज़रिए submit किए गए script checks को बाहर रखती है। Consul ACLs enable होने पर, service registration के लिए `service:write` आवश्यक है; केवल `acl.default_policy=allow` वाली line से यह साबित नहीं होता कि कोई anonymous caller registration कर सकता है। Agent की वास्तविक identity, loaded settings, API binding और authorization—इन सबकी एक साथ समीक्षा करें।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

चल रहे agent के `-config-dir` और `-config-file` arguments को संबंधित configuration तक फ़ॉलो करें, और केवल script-check तथा ACL field names और settings की जाँच करें। Configuration files में gossip keys या tokens भी हो सकते हैं; उन्हें shared logs में paste करने से बचें। केवल इस स्थिति को enumerate करने के लिए service register न करें या health check न चलाएँ।

एक अलग local-file path तब मौजूद होता है, जब कम विशेषाधिकार वाला user root-run agent के `-config-dir` द्वारा नामित directory में **write और search** कर सकता है: उस directory से नई `.hcl` या `.json` service definition load हो सकती है। Directory में search और write की अनुमति, directory की listing से इनकार होने पर भी, file जोड़ने की अनुमति दे सकती है। Root command execution के लिए पुष्टि करें कि agent वास्तव में उस directory को load करता है, उसकी **effective** script-check setting local definitions की अनुमति देती है, definition load हो गई है, और agent root privileges बनाए रखता है। [Consul documents](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) बताते हैं कि कौन-सी settings और health-check definitions reload हो सकती हैं; script checks को enable करने के लिए स्वयं restart की आवश्यकता हो सकती है, इसलिए installed version का behavior verify करें। जब ACLs agent को सुरक्षित रखते हैं, [`consul reload` requires `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); केवल KV write permission से यह अनुमति नहीं मिलती। Writable directory metadata को review cue मानें, अधिकृत reload, restart या command execution का प्रमाण नहीं। Configuration लिखे बिना या API call किए बिना paths, permissions और policy की जाँच करें।

## Service execution chain को फ़ॉलो करें

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories और socket activation की जाँच करें। Root-owned unit भी असुरक्षित हो सकती है, अगर वह user-writable config या script पढ़ती है। [arbitrary file write](../interesting-files-permissions/write-to-root.md) पेज में service और unit के दुरुपयोग के आम रास्ते दिए गए हैं। जब एक बार की `ps` listing से कम समय तक चलने वाले jobs न दिखें, तो उन्हें [pspy](https://github.com/DominicBreuker/pspy) या audit/process telemetry से monitor करें।

किसी custom **xinetd** service के लिए, enabled stanza के `server`, `user` और access controls का live listener और सटीक executable से मिलान करें। [`user` setting](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) शुरू किए गए process की identity चुनती है, जबकि executable पर set-user-ID bit उसकी effective identity को अलग से बदल सकता है, यदि [`execve` उस बदलाव की अनुमति देता है](https://man7.org/linux/man-pages/man2/execve.2.html)। Untrusted input स्वीकार करने वाला कोई accessible privileged binary memory-safety bugs की offline source या disassembly review के योग्य है—जैसे fixed buffer में बिना सीमा वाला [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)। Service mapping और set-user-ID metadata ऐसे bug के संकेत हैं, उनका प्रमाण नहीं; passive enumeration के दौरान crash inputs न भेजें और live privileged service को debug न करें।

यदि किसी custom privileged listener का source readable है, तो copy operation, जैसे [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html), में इस्तेमाल होने वाली caller-controlled हर length की समीक्षा करें। सिर्फ यह जाँचना कि मौजूदा write index fixed buffer के भीतर है, यह साबित नहीं करता कि **copy length** बची हुई जगह में फिट होती है; index के दायरे में होने की पुष्टि के बाद `copy_length <= capacity - index` जाँचें, और signedness तथा arithmetic overflow भी जाँचें। यह समीक्षा-संकेत तभी प्रासंगिक है जब input उस operation तक पहुँचता हो, listener lower-privileged user के लिए accessible हो, और process की higher effective identity बनी रहती हो। Source और process metadata को offline जाँचें; enumeration के दौरान live service को crash inputs न भेजें।

**Upstart** इस्तेमाल करने वाले systems पर system job definitions `/etc/init/*.conf` के अंतर्गत हो सकती हैं। मौजूदा user द्वारा writable job file तभी मायने रखती है, जब active init daemon वही job load करता हो, उसका `script` या `exec` stanza higher-privileged identity के रूप में चलता हो, और user किसी अनुमत `initctl` command या किसी अन्य वास्तविक trigger से उसे शुरू कर सकता हो। केवल sudo `initctl` grant से यह साबित नहीं होता कि कोई job file writable है या modified job चलेगी। Enumeration के दौरान job को edit या start किए बिना, सटीक job file permissions, effective run-as setting, active daemon और trigger जाँचें। [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) और [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) manuals देखें।

Readable autologin password file, जैसे `/etc/autologin/passwd`—उन systems पर जिनका [boot job इसी exact path को पढ़ता है](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)—credential exposure का संकेत है। पुष्टि करें कि boot job installed है और file का इस्तेमाल करता है, फिर अलग से जाँचें कि password किसी अन्य local account या service के लिए valid है या नहीं। केवल filename से password reuse साबित नहीं होता; password को shared enumeration output में डाले बिना path और access metadata दर्ज करें।

किसी unit का `ExecStart=` या scheduled command, unlistable directory के अंदर मौजूद script का exact pathname दिखा सकता है। [Directory search permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html) से मौजूदा identity उस ज्ञात path पर जा सकती है; यह मानने के बजाय कि failed directory listing से file सुरक्षित है, हर parent पर search access और file पर read permission की पुष्टि करें। Readable script में transfer credential हो सकता है, लेकिन किसी अन्य account तक पहुँचने के लिए वह credential valid रहना चाहिए और उस account पर अलग से स्वीकार किया जाना चाहिए। Secret values को shared logs में डाले बिना path और permission evidence दर्ज करें।

Scheduled CommonJS Node.js script में bare imports, जैसे `require('package')`, की समीक्षा करें, भले ही script खुद read-only हो। [Node पहले importing file के पास और फिर उसकी ancestor directories में `node_modules` खोजता है](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), और उसके बाद configured global paths पर जाता है। ऐसा lower-privileged user जो इन ancestor directories में से किसी एक को **write और search** कर सकता है, पहले match होने वाला package बना सकता है। पुष्टि करें कि exact import तक पहुँचा जाता है, चुना गया package built-in module नहीं है, संबंधित path बनाया या बदला जा सकता है, installed runtime में module वहीं resolve होता है, और higher-privileged job भविष्य में उसे load करेगी। Writable parent metadata सिर्फ समीक्षा का संकेत है; module रखे या job trigger किए बिना script और scheduler की passive जाँच करें।

जब कोई automated job अलग OS identity के तहत packages install करती है, तो private Python package index एक और trust boundary होता है। Exact job और run-as account का उसके configured index, चुने गए package names, और इस बात से मिलान करें कि lower-privileged user ऐसा package publish या replace कर सकता है या नहीं जिसे job वास्तव में install करेगी। Source distribution बनाने के दौरान installer's identity के तहत उसका build backend या legacy `setup.py` चल सकता है; installed package को import करना execution का अलग रास्ता है। Index listener, readable upload password hash या package filename अकेले इस chain को साबित नहीं करते। Enumeration के दौरान कुछ upload या install किए बिना job, index authorization और package provenance की समीक्षा करें। [pip का build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) और [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/) देखें।

Privileged agent, अलग web service या container द्वारा managed task queue को poll कर सकता है। यदि lower-trust identity उस service का task database लिख सकती है, तो पता करें कि क्या वे rows वास्तव में उस agent को serve की जाती हैं और क्या command task agent की OS identity के तहत चलती है। Database write access, target session या routing key, active polling, task authorization और agent के effective user की अलग-अलग पुष्टि करें। Container के अंदर root होने का अर्थ अपने-आप host-root access नहीं है; boundary तभी पार होती है जब host-privileged consumer attacker-controlled task data execute करता है। Enumeration के दौरान queue बदले या task भेजे बिना process, database-file और service metadata की जाँच करें।

इसके बजाय, recurring job application database configuration row से command पढ़ सकती है। पुष्टि करें कि lower-privileged database role उस exact row को बदल सकती है, active job बदलाव के बाद उसे पढ़ती है, और value higher OS identity के तहत shell या equivalent command runner तक पहुँचती है। Database write access या command-जैसी value अकेले execution साबित नहीं करती; passive enumeration के दौरान row बदले बिना job और permissions की जाँच करें।

Queued message में code के बजाय URL भी हो सकता है। यदि privileged consumer उस URL को fetch करके response को Lua या किसी अन्य executable plugin के रूप में load करता है, तो exact exchange और routing key पर publisher की permission, consumed queue से binding, fetch और plugin-load path, और worker की effective identity की पुष्टि करें। [RabbitMQ published messages को exchanges के ज़रिए route करता है](https://www.rabbitmq.com/docs/exchanges); broker listener या valid login अकेले इस worker तक message पहुँचने का प्रमाण नहीं हैं। Captured cleartext broker credentials अलग संकेत हैं, जिनके लिए actual packet-capture access और readable traffic की ज़रूरत होती है; वे publish authorization साबित नहीं करते। Lua plugin shell commands तभी चला सकता है जब उसके runtime में [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) API उपलब्ध हो। Passive enumeration के दौरान traffic capture, message publish या plugin fetch किए बिना configuration और code की समीक्षा करें।

जब कोई privileged Python service local HTTP या socket endpoint expose करती है, तो readable script input-to-code path दिखा सकती है, भले ही उसकी file permissions बदलाव रोकती हों। Active process और unit identity का exact script, listener, route authorization और caller-controlled fields से मिलान करें। फिर parsing और validation से होते हुए उन fields को dynamic `eval()` या `exec()` sink तक trace करें। खास तौर पर, request text से नया f-string बनाकर उसे evaluate करने पर attacker-supplied replacement fields Python expressions के रूप में interpret हो सकते हैं ([Python `eval` warning](https://docs.python.org/3/library/functions.html#eval); [f-string semantics](https://docs.python.org/3/reference/lexical_analysis.html#f-strings))। `eval` का अकेला match या loopback binding यह साबित नहीं करता कि untrusted caller sink तक पहुँच सकता है; enumeration के दौरान test payload भेजे बिना actual dataflow और access controls की समीक्षा करें।

उस route के signed-request gate की भी अलग समीक्षा ज़रूरी है। यदि readable source से पता चलता है कि signing key का output space स्पष्ट रूप से छोटा या predictable है, और service एक valid signed sample expose करती है, तो signature शायद privileged `eval()` sink की सुरक्षा न कर पाए। Exact key derivation और verifier, live service identity और local caller access, तथा यह पुष्टि करें कि signed field sink तक पहुँचता है या नहीं; Python के [`random` module](https://docs.python.org/3/library/random.html) का import या sample signature अकेले इनमें से कोई भी शर्त साबित नहीं करते। Python यह भी चेतावनी देता है कि `__builtins__` को सीमित करना [untrusted `eval()` input के लिए security boundary नहीं है](https://docs.python.org/3/library/functions.html#eval)। Key analysis offline करें और passive enumeration के दौरान forged requests submit न करें।

खाली लेकिन writable `/etc/systemd/system/<unit>.service.d` directory तब भी मायने रखती है, जब unit file और हर मौजूदा drop-in सुरक्षित हों: user नई `.conf` override बना सकता है। जाँचें कि मौजूदा identity उस directory को write और search कर सकती है या नहीं, unit loaded है और root के रूप में चलती है या नहीं, और daemon reload के बाद restart होगा या नहीं। Reload या restart की permission, timer या बाद का boot बदलाव को प्रभावी बना सकता है; केवल directory write access से वह तुरंत execute नहीं होता।

Running services के लिए unit के `[Service]` section में दिए literal `EnvironmentFile=` paths का पता लगाएँ, जिनमें वे files भी शामिल हैं जिनके नाम `.env` से शुरू नहीं होते। यदि low-privilege user कोई file पढ़ सकता है, तो values को shared logs में डाले बिना `API_TOKEN` या `APP_SECRET_KEY` जैसे credential-जैसे key names सूचीबद्ध करें। Effective unit का आकलन करते समय drop-in overrides और वैकल्पिक `-` prefixes जाँचें। Readability credential exposure का संकेत है; escalation के लिए उस value का privileged action में valid होना भी ज़रूरी है।

### Untrusted uploads की privileged processing

Root के रूप में चलने वाला file watcher, user-writable upload directory की files को short-lived parser या extractor तक पहुँचा सकता है। Running watcher की parent script या service का पता लगाएँ और exact directory, वहाँ files कौन रख सकता है, child command और उसके arguments, तथा child किस identity के तहत चलता है—इनकी पुष्टि करें। Process snapshot में watcher दिख सकता है, लेकिन uploads के बीच चलने वाला extractor छूट सकता है। Passive enumeration के दौरान test payload न रखें और watcher को trigger न करें।

एक ठोस उदाहरण Binwalk का extraction mode (`-e`) है, जो attacker-controlled PFS data process करता है। [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) के कारण PFS extractor intended directory से बाहर लिख सकता था, जिसमें वह plugin path भी शामिल था जिसे Binwalk बाद में load कर सकता था। Upstream ने fix [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) में शामिल किया, लेकिन distribution backports के कारण displayed version पुराना हो सकता है; लागू होने की संभावना का आकलन करने से पहले installed package का security status, जैसे [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510), जाँचें। केवल Binwalk version installed होना privilege-escalation path साबित नहीं करता: extraction को वास्तव में किसी अधिक privileged process द्वारा ऐसे input पर invoke किया जाना चाहिए जिसे lower-privileged user control कर सके।

### Local dependencies के साथ scheduled builds

Scheduled `cargo run`, job के run-as user के रूप में source को फिर से compile करता है। सिर्फ main crate नहीं, manifest की local `{ path = "..." }` dependencies और हर dependency की source तथा parent-directory permissions की जाँच करें। यदि lower-privileged user ऐसी dependency बदल सकता है जिसे Cargo compile करता है और scheduled job उसका result चलाती है, तो compiled code उस run-as user के रूप में execute हो सकता है। Effective scheduler command, working directory, dependency resolution और rebuild होगा या नहीं—इनकी पुष्टि करें; कहीं और writable Rust source file होना केवल एक संकेत है। Passive triage के लिए manifest और path metadata पढ़ना पर्याप्त है। [Cargo path-dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) देखें।

## Xvfb framebuffer files

`Xvfb -fbdir <directory>` अपने virtual screens के लिए `Xvfb_screen<n>` नाम की memory-mapped files का उपयोग करता है। यदि किसी अन्य user की running Xvfb process ऐसी directory बताती है जिसकी screen files मौजूदा user पढ़ सकता है, तो framebuffer उस user के desktop content को उजागर कर सकता है। Process, file ownership और permissions की एक साथ पुष्टि करें; केवल readable file से यह साबित नहीं होता कि screen पर उपयोगी content है। Shared enumeration output में image data copy किए बिना पहले paths और metadata की जाँच करें। [Xvfb manual](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) में `-fbdir` का व्यवहार बताया गया है।

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
7. [LibreOffice सहायता: external API clients के लिए socket खोलना](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
