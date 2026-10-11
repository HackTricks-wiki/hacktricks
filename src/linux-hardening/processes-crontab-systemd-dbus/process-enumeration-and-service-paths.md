# Process Enumeration and Service Paths

{{#include ../../banners/hacktricks-training.md}}

İşe yarar soru, hangi ayrıcalıklı sürecin daha düşük ayrıcalıklı bir kullanıcının etkileyebileceği verileri veya kodu kullandığıdır. Süreç ağacını, canlı ortamı, açık dosyaları ve her aday süreci başlatan unit'i veya script'i inceleyin.

## Süreçleri ve sahipliklerini eşleyin

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Farklı kullanıcılar arasındaki bir ebeveyn-çocuk ilişkisi normal olabilir, ancak beklenmeyen bir geçişte ebeveyn komutu, argümanları, çalıştırılabilir dosyası, çalışma dizini ve başvurulan dosyalar incelenmelidir. Sahiplik ve oturum açma bağlamını yorumlamak için [users and sessions](../user-information/user-and-session-triage.md) sayfasını kullanın.

### Yerel sanal makine konsolları

Bir QEMU sürecinin `-spice` seçeneklerini dinleme adresiyle birlikte inceleyin. [QEMU belgelerinde](https://www.qemu.org/docs/master/system/qemu-manpage.html), `disable-ticketing` seçeneğinin SPICE istemcilerinin kimlik doğrulaması olmadan bağlanmasına izin verdiği belirtilir. Loopback'e bağlı bir dinleyiciye diğer yerel ana makine kullanıcıları da potansiyel olarak erişebilir. Komut satırını açık bir konsol olarak değerlendirmeden önce etkin dinleyiciyi, kimlik doğrulama seçeneklerini ve yerel erişimi doğrulayın. Konsol denetimi **guest**'i etkiler; bir guest hesabı edinmek veya önyükleme durumunu değiştirmek ayrı guest tarafı koşulları gerektirir ve sanallaştırma ana makinesinde root yetkisi vermez. Pasif numaralandırma sırasında guest'e bağlanmadan veya guest'i yeniden başlatmadan süreç argümanlarını ve socket meta verilerini okuyun.

Yerel olarak erişilebilen bir web arayüzü, ilk shell o hesabın dosyalarına erişemese bile hizmet hesabı yetkileriyle kod çalıştırabilir. Örneğin CVE-2023-0297, güvenilmeyen JavaScript'in Python içe aktarmaları etkin Js2Py'ye ulaşması durumunda pyLoad'un `/flash/addcrypted2` işleme mekanizmasını etkiliyordu; [upstream düzeltmesi](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) `pyimport` özelliğini devre dışı bıraktı. Bir pyLoad sürecini ayrıcalık yükseltme yolu olarak değerlendirmeden önce çalışan sürecin sahibini, dinleme adresini, uç noktanın dışarıya açık olup olmadığını ve kurulu düzeltme ya da vendor backport durumunu ilişkilendirin. Yalnızca süreç adı, açık port veya paket sürümü açıklığı kanıtlamaz; pasif numaralandırma sırasında kod çalıştırma payload'ı göndermeyin.

### Terminal paylaşan ayrıcalıklı login shell'leri

Bağımsız bir pseudo-terminal olmadan `su --login <user>` çalıştıran ayrıcalıklı bir etkileşimli shell, terminalin daha düşük ayrıcalıklı login shell'iyle paylaşılmasına neden olabilir. Bu kullanıcının başlangıç dosyası denetlenebiliyorsa ve içindeki kod terminal girdisi enjekte etmek için `TIOCSTI` kullanabiliyorsa, ayrıcalıklı shell yeniden etkin olduğunda bu girdi ona ulaşabilir. [util-linux `su` kılavuzu](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES), paylaşılan terminal riskini açıklar ve etkileşimli kullanım için `su --pty`/`-P` seçeneğini önerir; `su -c` ise denetleyici terminali olmayan ayrı bir oturum başlatır. Risk; gerçek ebeveyn shell'e, terminal ilişkisine, hedef başlangıç dosyasına ve kernel politikasına bağlıdır. Yalnızca süreç adı veya `su -l` argümanı, inceleme için bir ipucudur.

Gözlemlenen süreç ağacını ve TTY sütunlarını, ardından okunabilir başlatıcıyı ve başlangıç dosyasının sahiplik/izinlerini inceleyin. Linux'ta `/proc/sys/dev/tty/legacy_tiocsti` mevcutsa politika hakkında yorum yapmaya yardımcı olabilir; dosyanın bulunmaması güvenli olunduğunu kanıtlamaz. [Linux `TIOCSTI` kılavuzu](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html), Linux 6.2'den itibaren bu sysctl false olduğunda işlemin `CAP_SYS_ADMIN` gerektirebileceğini belirtir. Ana makineyi numaralandırmak amacıyla ioctl çağrısı yapmayın.

Bir veritabanı hesabı bazen hedef kullanıcının başlangıç dosyasını doğrudan dosya sistemi yazma erişimi olmadan değiştirebilir. PostgreSQL sunucu tarafındaki `COPY ... TO 'filename'` komutu dosyayı veritabanı sunucusunun OS hesabı olarak yazar; ancak [PostgreSQL kısıtlamaları](https://www.postgresql.org/docs/current/sql-copy.html), bu dosya biçimini veritabanı süper kullanıcıları veya `pg_write_server_files` gibi rolleri olan kullanıcılarla sınırlar. Hem veritabanı rolünü hem de sunucunun OS dosya izinlerini doğrulayın; uygulama bağlantı dizgesi tek başına dosya yazma yetkisi vermez. Zinciri değerlendirirken ayrıcalıklı başlatıcı ile veritabanı hesabının yeteneklerini birbirinden ayrı tutun.

## Çalışma zamanı yapıtlarını inceleyin

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Silinmiş çalıştırılabilir dosyalar ve silinmiş ancak açık dosyalar, son dosya tanımlayıcıları kapanana kadar referans edilmeye devam eder. Kanıtları veya erişilebilir gizli bilgileri koruyabilirler. İşlem ortamları ve belleği kimlik bilgileri içerebilir; ancak başka bir işlemi okumak, sahiplik, `/proc` bağlama seçenekleri, Yama ptrace politikası ve diğer güvenlik denetimleriyle kısıtlanır. İlgili teknikler için [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) ve [post-exploitation credential hunting](../post-exploitation/README.md) bölümlerine bakın.

Kaydedilmiş syscall izleri de başka bir dosya izni sınırıdır. [`strace` syscall argümanlarını bir çıktı dosyasına kaydeder](https://man7.org/linux/man-pages/man1/strace.1.html); bu nedenle [`execve` argümanlarını](https://man7.org/linux/man-pages/man2/execve.2.html) içeren, okunabilir bir iz, ayrıcalıklı bir işin komut satırında ilettiği parolayı açığa çıkarabilir. Önce mevcut kullanıcının söz konusu izi okuyabildiğini ve argümanın gerçekten bir kimlik bilgisi içerdiğini doğrulayın; daha sonra Unix hesabı değiştirmek için bu kimlik bilgisinin o hesapta kabul edildiğine dair ayrıca kanıt gerekir. Dosya meta verileri, olağan envanter çıkarma sırasında her izi taramadan veya içeriğini yazdırmadan kullanılabilecek faydalı, pasif bir ipucudur.

## Privileged office automation sockets

LibreOffice ve OpenOffice, UNO API'lerini `--accept=socket,host=<host>,port=<port>;urp;` argümanı üzerinden kullanıma açabilir. Erişilebilir bir uç noktası olan, root sahipliğindeki bir ofis işlemi; daha düşük ayrıcalıklı yerel bir kullanıcının, o işlemin güvenlik bağlamında API servislerini çağırmasına olanak tanıyabilir. `SystemShellExecute` servisi, sistem komutu başlatmaya yönelik bir işlem içerir. Loopback adresine bağlamak uzaktan erişimi sınırlar; ancak başka bir denetim erişimi engellemediği sürece soket yerel kullanıcılar için erişilebilir kalır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Süreç sahibini, tam `--accept` argümanını ve mevcut dinleme adresi ile portu ilişkilendirin. Bind işlemi başarısız olan yapılandırılmış bir acceptor yalnızca bir ipucudur; pasif enumeration sırasında API'ye bağlanmayın veya API'yi çağırmayın. Bu koşulu test etmek için ayrıcalıklı bir office örneğini başlatmaktan kaçının.

## Ayrıcalıklı süreçlerin kullandığı System V shared memory

Root-owned bir helper, başka bir kullanıcının yazabildiği bir System V shared-memory segmenti oluşturabilir. Helper daha sonra bu segmentteki verilere bir shell command içinde veya başka bir hassas işlemde güvenirse, executable ve dosyaları korumalı olsa bile segment bir ayrıcalık sınırını aşar. `shmget()` erişim izinlerini flag'lerinin alt dokuz bitinden alır; `0666` modu diğer kullanıcıların yazmasına izin verirken `IPC_CREAT` flag'i bu izinleri daraltmaz. Etkin segmentleri pasif olarak `ipcs -m` ile inceleyin ve sahiplerini, modlarını ve yaşam sürelerini ayrıcalıklı süreç ve bu sürecin girdi işleme biçimiyle ilişkilendirin. Tek başına world-writable bir segment, command execution olduğunu kanıtlamaz.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmentleri, `/dev/shm` altındaki POSIX shared-memory dosyalarından farklıdır. Yalnızca kısa süreliğine oluşturulan bir segment, tek bir `ipcs` anlık görüntüsünde görünmeyebilir; bu nedenle çıktının boş olması, shared memory kullanan bir yardımcı programı devre dışı bırakmaz. Kaynak kodunu veya binary davranışını ve onu çalıştıran `sudo` kuralını inceleyin; numaralandırma sırasında bir segment oluşturmak için ayrıcalıklı yardımcı programı çalıştırmayın. [IPC namespace rehberi](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md), namespace'lerin görünürlüğü nasıl etkilediğini açıklar.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul, agent'ının işletim sistemi kimliğiyle script health check'leri çalıştırabilir. Bir agent root olarak çalışıyorsa, `enable_script_checks` etkinse ve daha düşük ayrıcalıklı bir kullanıcının yerel HTTP API üzerinden script check içeren bir service kaydetmesine izin veriyorsa, bu kullanıcı root olarak çalışan komutlar çalıştırabilir. API'yi yalnızca `127.0.0.1` adresine bağlamak, yerel kullanıcıların API'ye erişmesini engellemez. `enable_local_script_checks` ayarı daha kısıtlayıcıdır: HTTP API kayıtları üzerinden gönderilen script check'leri kapsam dışında bırakır. Consul ACL'leri etkin olduğunda service kaydı için `service:write` gerekir; tek başına `acl.default_policy=allow` satırı, anonim bir çağıranın kayıt yapabileceğini kanıtlamaz. Agent'ın gerçek kimliğini, yüklenen ayarları, API bağlamasını ve yetkilendirmeyi birlikte inceleyin.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Çalışan agent'ın `-config-dir` ve `-config-file` argümanlarını izleyerek ilgili yapılandırmayı bulun ve yalnızca script-check ile ACL alan adlarını ve ayarlarını inceleyin. Yapılandırma dosyaları gossip key'leri veya token'lar da içerebilir; bunları paylaşılan log'lara yapıştırmaktan kaçının. Bu durumu yalnızca tespit etmek için servis kaydetmeyin veya health check çalıştırmayın.

Daha düşük ayrıcalıklı bir kullanıcı, root olarak çalışan agent'ın `-config-dir` ile belirttiği dizine **yazabiliyor ve dizinde arama yapabiliyorsa** ayrı bir local-file yolu mevcuttur: bu dizinden yeni bir `.hcl` veya `.json` servis tanımı yüklenebilir. Dizinde arama ve yazma izinleri, dizin listeleme izni olmasa bile dosya eklenmesine olanak tanıyabilir. Root olarak komut çalıştırmak için agent'ın gerçekten bu dizini yüklediğini, **etkin** script-check ayarının yerel tanımlara izin verdiğini, tanımın yüklendiğini ve agent'ın root ayrıcalıklarını koruduğunu doğrulayın. Hangi ayarların ve health check tanımlarının yeniden yüklenebileceği [Consul belgelerinde](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) açıklanmıştır; script check'lerini etkinleştirmek için yeniden başlatma gerekebilir, bu nedenle kurulu sürümün davranışını doğrulayın. ACL'ler agent'ı koruduğunda [`consul reload` için `agent:write` gerekir](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); yalnızca KV yazma izni bunu sağlamaz. Yazılabilir dizin metadata'sını yetkili bir yeniden yükleme, yeniden başlatma veya komut çalıştırmanın kanıtı değil, inceleme işareti olarak değerlendirin. Yapılandırmaya yazmadan veya API'yi çağırmadan yolları, izinleri ve politikayı inceleyin.

## Servis yürütme zincirini izleyin

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Unit’i, drop-in’leri, `EnvironmentFile=`’ı, yardımcı script’leri, göreli komutları, yazılabilir dizinleri ve socket activation’ı kontrol edin. Root sahipliğindeki bir unit, kullanıcı tarafından yazılabilir bir config veya script okursa yine de güvenli olmayabilir. [Arbitrary file write](../interesting-files-permissions/write-to-root.md) sayfasında yaygın service ve unit abuse yolları ele alınır. Tek seferlik bir `ps` listelemesi kısa ömürlü işleri kaçırıyorsa bunları [pspy](https://github.com/DominicBreuker/pspy) veya audit/process telemetry ile izleyin.

Özel bir **xinetd** service için, etkin stanza’daki `server`, `user` ve erişim kontrollerini çalışan listener ve tam executable ile karşılaştırın. [`user` ayarı](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) başlatılan process’in kimliğini belirlerken, executable üzerindeki set-user-ID biti, [`execve` bu geçişe izin veriyorsa](https://man7.org/linux/man-pages/man2/execve.2.html) effective kimliği ayrıca değiştirebilir. Güvenilmeyen input kabul eden ve erişilebilen ayrıcalıklı bir binary, sabit boyutlu bir buffer’a sınırlandırılmamış [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) gibi memory-safety hataları açısından offline source veya disassembly incelemesini gerektirir. Service eşlemesi ve set-user-ID metadata’sı böyle bir bug’ın kanıtı değil, yalnızca inceleme ipuçlarıdır; pasif enumeration sırasında crash input göndermeyin veya çalışan ayrıcalıklı service’te debug yapmayın.

Okunabilir source’u olan özel bir ayrıcalıklı listener’da, [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) gibi bir copy işleminin kullandığı, caller tarafından kontrol edilen her uzunluğu inceleyin. Yalnızca mevcut write index’inin sabit boyutlu buffer içinde olduğunu kontrol etmek, **copy length** değerinin kalan alana sığdığını göstermez; index’in aralık içinde olduğunu doğruladıktan sonra `copy_length <= capacity - index` koşulunu kontrol edin, ayrıca signedness ve arithmetic overflow durumlarını inceleyin. Bu yalnızca input söz konusu işleme ulaşıyorsa, listener düşük ayrıcalıklı kullanıcı tarafından erişilebiliyorsa ve process daha yüksek bir effective kimliği koruyorsa inceleme ipucudur. Enumeration sırasında source’u ve process metadata’sını offline inceleyin; çalışan service’e crash input göndermeyin.

**Upstart** kullanan sistemlerde system job tanımları `/etc/init/*.conf` altında bulunabilir. Mevcut kullanıcının yazabildiği bir job dosyası; etkin init daemon tam olarak o job’ı yüklüyorsa, `script` veya `exec` stanza’sı daha yüksek ayrıcalıklı bir kimlikle çalışıyorsa ve kullanıcı bu job’ı izin verilen bir `initctl` komutuyla veya başka bir gerçek tetikleyiciyle başlatabiliyorsa önemlidir. Tek başına sudo `initctl` izni, herhangi bir job dosyasının yazılabilir olduğunu veya değiştirilmiş bir job’ın çalışacağını kanıtlamaz. Enumeration sırasında job’ı düzenlemeden veya başlatmadan tam job dosyasının izinlerini, etkin run-as ayarını, çalışan daemon’u ve tetikleyiciyi kontrol edin. [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) ve [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) kılavuzlarına bakın.

Sistemlerdeki [boot job tam olarak bu yolu okuyorsa](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), `/etc/autologin/passwd` gibi okunabilir bir autologin password dosyası, kimlik bilgilerinin açığa çıkmış olabileceğine işaret eder. Boot job’ın yüklü olduğunu ve dosyayı kullandığını doğrulayın; ardından password’ün başka bir yerel hesap veya service için geçerli olup olmadığını ayrıca kontrol edin. Yalnızca dosya adı, password reuse olduğunu kanıtlamaz; password’ü paylaşılan enumeration çıktısına koymadan path ve erişim metadata’sını kaydedin.

Bir unit’in `ExecStart=` satırı veya zamanlanmış bir komut, listelenemeyen bir dizindeki script’in tam pathname’ini açığa çıkarabilir. [Directory search izni](https://man7.org/linux/man-pages/man7/path_resolution.7.html), mevcut kimliğin bilinen bu path’ten geçmesine yine de izin verebilir; başarısız bir dizin listelemesinin dosyayı koruduğunu varsaymak yerine her parent dizinde search erişimini ve dosyada read iznini doğrulayın. Okunabilir bir script transfer credential’ı içerebilir; ancak başka bir hesaba geçiş, bu credential’ın hâlâ geçerli olmasına ve o hesapta bağımsız olarak kabul edilmesine bağlıdır. Gizli değerleri paylaşılan log’lara yazdırmadan path’i ve izin kanıtlarını kaydedin.

Zamanlanmış bir CommonJS Node.js script’i için, script’in kendisi salt okunur olsa bile `require('package')` gibi bare import’ları inceleyin. [Node, yapılandırılmış global path’lere geçmeden önce import eden dosyanın yanındaki ve üst dizinlerindeki `node_modules` dizinlerinde arama yapar](https://nodejs.org/api/modules.html#loading-from-node_modules-folders). Bu üst dizinlerden birine **yazabilen ve erişebilen** düşük ayrıcalıklı bir kullanıcı, aramada önce eşleşecek bir package oluşturabilir. Tam import’un çalıştırıldığını, seçilen package’ın built-in module olmadığını, ilgili path’in oluşturulabildiğini veya değiştirilebildiğini, kurulu runtime’da module’ün oradan çözümlendiğini ve daha yüksek ayrıcalıklı bir job’ın sonraki çalıştırmada onu yükleyeceğini doğrulayın. Yazılabilir parent metadata’sı yalnızca bir inceleme ipucudur; module eklemeden veya job’ı tetiklemeden script’i ve scheduler’ı pasif biçimde inceleyin.

Farklı bir OS kimliği altında package kuran otomatik bir job söz konusu olduğunda, private Python package index de bir trust boundary’dir. Tam job’ı ve run-as hesabını; yapılandırılmış index, seçilen package adları ve düşük ayrıcalıklı bir kullanıcının job’ın gerçekten kuracağı bir package’ı yayımlayıp değiştirebilmesiyle karşılaştırın. Bir source distribution oluşturmak, build backend’ini veya eski `setup.py`’yi kurulum yapanın kimliğiyle çalıştırabilir; kurulu package’ı import etmek ise ayrı bir execution path’tir. Bir index listener’ı, okunabilir upload password hash’i veya package filename’ı tek başına bu zinciri kanıtlamaz. Enumeration sırasında bir şey upload etmeden veya kurmadan job’ı, index yetkilendirmesini ve package provenance’ını inceleyin. [pip’in build-system arayüzüne](https://pip.pypa.io/en/stable/reference/build-system/) ve [güvenli kurulum kılavuzuna](https://pip.pypa.io/en/stable/topics/secure-installs/) bakın.

Ayrı bir web service veya container tarafından yönetilen task queue’yu ayrıcalıklı bir agent düzenli olarak kontrol ediyor olabilir. Daha düşük trust seviyesindeki bir kimlik service’in task database’ine yazabiliyorsa, bu satırların gerçekten agent’a sunulup sunulmadığını ve command task’ın agent’ın OS kimliğiyle çalışıp çalışmadığını belirleyin. Enumeration sırasında queue’yu değiştirmeden veya task göndermeden database write erişimini, hedef session veya routing key’i, aktif polling’i, task yetkilendirmesini ve agent’ın effective user’ını ayrı ayrı doğrulayın. Container içindeki root, tek başına host-root erişimi anlamına gelmez; sınır ancak host ayrıcalıklarına sahip bir consumer, saldırganın kontrol ettiği task verisini çalıştırırsa aşılır. Process, database-file ve service metadata’sını inceleyin.

Yinelenen bir job bunun yerine bir application database yapılandırma satırındaki komutu okuyabilir. Daha düşük ayrıcalıklı database role’ünün tam olarak bu satırı değiştirebildiğini, etkin job’ın değişiklikten sonra satırı okuduğunu ve değerin daha yüksek bir OS kimliğiyle çalışan bir shell’e veya eşdeğer command runner’a ulaştığını doğrulayın. Database write erişimi veya komut gibi görünen bir değer tek başına execution’ı kanıtlamaz; pasif enumeration sırasında satırı değiştirmeden job’ı ve izinleri inceleyin.

Queued message, code yerine URL de içerebilir. Ayrıcalıklı bir consumer bu URL’yi fetch edip yanıtı Lua veya başka bir executable plugin olarak yüklüyorsa, publisher’ın tam exchange ve routing key üzerindeki iznini, tüketilen queue’ya olan binding’i, fetch ve plugin-load path’ini ve worker’ın effective kimliğini doğrulayın. [RabbitMQ, yayımlanan mesajları exchange’ler üzerinden yönlendirir](https://www.rabbitmq.com/docs/exchanges); broker listener’ı veya geçerli bir login, bu worker’a teslimatı tek başına kanıtlamaz. Yakalanmış açık metin broker credential’ları, gerçek packet-capture erişimi ve okunabilir trafik gerektiren ayrı bir ipucudur; publish yetkisini kanıtlamaz. Lua plugin’i yalnızca runtime’ında bu API mevcutsa [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) üzerinden shell komutları çalıştırabilir. Pasif enumeration sırasında trafik yakalamadan, mesaj yayımlamadan veya plugin fetch etmeden yapılandırmayı ve code’u inceleyin.

Ayrıcalıklı bir Python service yerel bir HTTP veya socket endpoint’i sunuyorsa, okunabilir bir script dosya izinleri değişikliği engellese bile input’tan code’a giden bir yolu açığa çıkarabilir. Çalışan process’in ve unit’in kimliğini tam script, listener, route yetkilendirmesi ve caller tarafından kontrol edilen alanlarla karşılaştırın. Ardından bu alanları parsing ve validation adımlarından geçirerek dinamik bir `eval()` veya `exec()` sink’ine kadar izleyin. Özellikle request metninden yeni bir f-string oluşturup bunu evaluate etmek, saldırganın sağladığı replacement field’ları Python expression’ları olarak yorumlayabilir ([Python `eval` uyarısı](https://docs.python.org/3/library/functions.html#eval); [f-string semantiği](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Yalnızca bir `eval` eşleşmesi veya loopback binding, güvenilmeyen bir caller’ın sink’e ulaşabildiğini kanıtlamaz; enumeration sırasında test payload’ı göndermeden gerçek dataflow’u ve erişim kontrollerini inceleyin.

Bu route üzerindeki signed-request gate ayrıca incelenmelidir. Okunabilir source, imzalama anahtarının belirgin biçimde küçük veya tahmin edilebilir bir output space üzerinden türetildiğini gösteriyorsa ve service geçerli bir imzalı örnek sunuyorsa, imza ayrıcalıklı bir `eval()` sink’ini artık korumuyor olabilir. Tam key derivation ve verifier’ı, çalışan service’in kimliğini ve yerel caller erişimini, ayrıca imzalanan alanın sink’e ulaşıp ulaşmadığını doğrulayın; Python [`random` module’ünün](https://docs.python.org/3/library/random.html) import edilmesi veya örnek bir imza bu koşulların hiçbirini kanıtlamaz. Python ayrıca `__builtins__`’i kısıtlamanın güvenilmeyen `eval()` input’u için [bir security boundary olmadığını](https://docs.python.org/3/library/functions.html#eval) belirtir. Key analizini offline yapın ve pasif enumeration sırasında sahte request göndermeyin.

Boş ama yazılabilir bir `/etc/systemd/system/<unit>.service.d` dizini, unit dosyası ve mevcut tüm drop-in’ler korumalı olsa bile önemlidir: kullanıcı yeni bir `.conf` override oluşturabilir. Mevcut kimliğin dizine yazabildiğini ve erişebildiğini, unit’in yüklü olup root olarak çalıştığını ve daemon reload’un ardından bir restart gerçekleşip gerçekleşmeyeceğini kontrol edin. Reload veya restart izni, timer ya da sonraki boot değişikliği etkinleştirebilir; dizine yazma erişimi tek başına değişikliği hemen çalıştırmaz.

Çalışan service’lerde unit’in `[Service]` bölümündeki literal `EnvironmentFile=` path’lerini, adları `.env` ile başlamayan dosyalar dahil, izleyin. Düşük ayrıcalıklı bir kullanıcı bunlardan birini okuyabiliyorsa `API_TOKEN` veya `APP_SECRET_KEY` gibi credential benzeri key adlarını, değerleri paylaşılan log’lara yazdırmadan listeleyin. Etkin unit’i değerlendirirken drop-in override’ları ve isteğe bağlı `-` öneklerini kontrol edin. Okunabilirlik, credential’ların açığa çıkmış olabileceğine işaret eder; privilege escalation için değerin ayrıcalıklı bir işlemde hâlâ geçerli olması gerekir.

### Güvenilmeyen upload’ların ayrıcalıklı biçimde işlenmesi

Root olarak çalışan bir file watcher, kullanıcının yazabildiği bir upload dizinindeki dosyaları kısa ömürlü bir parser veya extractor’a iletebilir. Çalışan watcher’ın parent script’ini veya service’ini izleyerek tam dizini, dosyaları kimin koyabildiğini, child command’i ve argümanlarını, ayrıca child’ın hangi kimlikle çalıştığını doğrulayın. Process snapshot’ı watcher’ı gösterirken upload’lar arasında çalışan extractor’ı kaçırabilir. Pasif enumeration sırasında test payload’ı koymayın veya watcher’ı tetiklemeyin.

Somut bir örnek, Binwalk’ın extraction mode’unun (`-e`) saldırganın kontrol ettiği PFS verisini işlemesidir. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617), PFS extractor’ının hedeflenen dizinin dışına yazmasına izin veriyordu; buna Binwalk’ın daha sonra yükleyebileceği bir plugin path’i de dahildi. Upstream düzeltmeyi [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) sürümüne ekledi, ancak distribution backport’ları görüntülenen sürümün eski kalmasına neden olabilir; uygulanabilirliği değerlendirmeden önce kurulu package’ın güvenlik durumunu [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510) gibi kaynaklardan kontrol edin. Yalnızca Binwalk’ın kurulu sürümü, privilege-escalation path’ini kanıtlamaz: extraction, düşük ayrıcalıklı kullanıcının kontrol edebildiği input üzerinde daha ayrıcalıklı bir process tarafından gerçekten çalıştırılmalıdır.

### Yerel dependency’lerle zamanlanmış build’ler

Zamanlanmış bir `cargo run`, source’u job’ın run-as kullanıcısı olarak yeniden derler. Yalnızca ana crate’i değil, manifest’teki yerel `{ path = "..." }` dependency’leri ile her dependency’nin source ve parent-directory izinlerini inceleyin. Düşük ayrıcalıklı bir kullanıcı Cargo’nun derlediği bir dependency’yi değiştirebiliyorsa ve zamanlanmış job derlenen sonucu çalıştırıyorsa, derlenen code o run-as kullanıcısı olarak çalışabilir. Etkin scheduler komutunu, çalışma dizinini, dependency resolution’ı ve yeniden build gerçekleşip gerçekleşmeyeceğini doğrulayın; başka bir yerdeki yazılabilir Rust source file’ı yalnızca bir ipucudur. Pasif triage için manifest’i ve path metadata’sını okumak yeterlidir. [Cargo path-dependency belgelerine](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) bakın.

## Xvfb framebuffer dosyaları

`Xvfb -fbdir <directory>`, sanal ekranları için `Xvfb_screen<n>` adlı memory-mapped dosyalar kullanır. Başka bir kullanıcının çalışan Xvfb process’i, ekran dosyaları mevcut kullanıcı tarafından okunabilen bir dizin belirtiyorsa framebuffer o kullanıcının masaüstü içeriğini açığa çıkarabilir. Process’i, dosya sahipliğini ve izinlerini birlikte doğrulayın; tek başına okunabilir bir dosya, ekranda yararlı bir içerik bulunduğunu kanıtlamaz. Görüntü verisini paylaşılan enumeration çıktısına kopyalamadan önce path’leri ve metadata’yı inceleyin. [`-fbdir` davranışı Xvfb kılavuzunda](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) açıklanmıştır.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` kılavuzu](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` kılavuzu](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` kılavuzu](https://man.openbsd.org/ipcs.1)
4. [Consul agent yapılandırması: script kontrolleri](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent service kayıt API'si](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL yapılandırması](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice yardımı: harici API istemcileri için socket açma](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
