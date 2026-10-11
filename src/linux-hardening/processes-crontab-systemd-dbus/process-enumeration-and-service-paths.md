# Process Enumeration and Service Paths

{{#include ../../banners/hacktricks-training.md}}

Sorulması gereken temel soru, düşük ayrıcalıklı bir kullanıcının etkileyebildiği verileri veya kodu hangi ayrıcalıklı sürecin kullandığıdır. Süreç ağacını, çalışan ortamı, açık dosyaları ve olası her adayı başlatan unit veya betiği inceleyin.

## Süreçleri ve sahipliklerini eşleyin

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Kullanıcılar arası bir ebeveyn-çocuk ilişkisi normal olabilir; ancak beklenmedik bir geçiş varsa ebeveyn komutunu, argümanları, yürütülebilir dosyayı, çalışma dizinini ve başvurulan dosyaları inceleyin. Sahiplik ve oturum açma bağlamını yorumlamak için [users and sessions](../user-information/user-and-session-triage.md) sayfasını kullanın.

### Yerel sanal makine konsolları

Bir QEMU sürecinin `-spice` seçeneklerini dinleme adresiyle birlikte inceleyin. [QEMU belgelerine](https://www.qemu.org/docs/master/system/qemu-manpage.html) göre `disable-ticketing`, SPICE istemcilerinin kimlik doğrulaması olmadan bağlanmasına izin verir. Loopback adresine bağlı bir dinleyiciye diğer yerel host kullanıcıları yine de erişebilir. Komut satırını açıkta bir konsol olarak değerlendirmeden önce etkin dinleyiciyi, kimlik doğrulama seçeneklerini ve yerel erişimi doğrulayın. Konsol denetimi **guest** üzerinde etkilidir; bir guest hesabı edinmek veya açılış durumunu değiştirmek ayrı guest tarafı koşulları gerektirir ve sanallaştırma host'unda root yetkisi sağlamaz. Pasif numaralandırma sırasında sürecin argümanlarını ve soket meta verilerini okuyun; guest'e bağlanmayın veya guest'i yeniden başlatmayın.

Yerel olarak erişilebilen bir web arayüzü, ilk shell o hesabın dosyalarına erişemese bile hizmet hesabı yetkileriyle kod çalıştırabilir. Örneğin CVE-2023-0297, güvenilmeyen JavaScript'in Python import'ları etkin durumdayken Js2Py'ye ulaşması sonucu pyLoad'un `/flash/addcrypted2` işleme biçimini etkiliyordu; [upstream düzeltmesi](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) `pyimport` özelliğini devre dışı bıraktı. Bir pyLoad sürecini olası bir yetki yükseltme yolu olarak değerlendirmeden önce çalışan sürecin sahibini, dinleme adresini, uç noktanın erişime açıklığını ve kurulu yamayı ya da vendor backport'unu ilişkilendirerek inceleyin. Tek başına süreç adı, açık port veya paket sürümü erişime açıklığı kanıtlamaz; pasif numaralandırma sırasında kod yürütme payload'ı göndermeyin.

### Terminali paylaşan ayrıcalıklı login shell'leri

Bağımsız bir pseudo-terminal olmadan `su --login <user>` çalıştıran ayrıcalıklı bir etkileşimli shell, terminalini daha düşük ayrıcalıklı login shell'iyle paylaşabilir. Kullanıcının başlangıç dosyası kontrol edilebiliyorsa ve içindeki kod terminal girdisi enjekte etmek için `TIOCSTI` kullanabiliyorsa, ayrıcalıklı shell yeniden etkin olduğunda bu girdi ona ulaşabilir. [util-linux `su` kılavuzu](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES), paylaşılan terminal riskini açıklar ve etkileşimli kullanımda `su --pty`/`-P` kullanılmasını önerir; `su -c` ise denetleyici terminali olmayan ayrı bir oturum başlatır. Bu risk için gerçek ebeveyn shell'i, terminal ilişkisi, hedef başlangıç dosyası ve kernel politikası doğrulanmalıdır. Tek başına süreç adı veya `su -l` argümanı yalnızca inceleme gerektiren bir ipucudur.

Gözlemlenen süreç ağacını ve TTY sütunlarını, ardından okunabilir başlatıcı dosyasını ve başlangıç dosyasının sahiplik/izinlerini inceleyin. Linux'ta `/proc/sys/dev/tty/legacy_tiocsti` mevcutsa politika hakkında fikir verebilir; dosyanın bulunmaması güvenliğin kanıtı değildir. [Linux `TIOCSTI` kılavuzunda](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html), Linux 6.2'den itibaren bu sysctl false olduğunda işlemin `CAP_SYS_ADMIN` gerektirebileceği belirtilir. Host'u numaralandırmak amacıyla ioctl çağrısını çalıştırmayın.

Bir veritabanı hesabı bazen hedef kullanıcının başlangıç dosyasını doğrudan dosya sistemine yazma erişimi olmadan değiştirebilir. PostgreSQL sunucu tarafındaki `COPY ... TO 'filename'`, veritabanı sunucusunun işletim sistemi hesabı olarak yazar; ancak [PostgreSQL kısıtlamaları](https://www.postgresql.org/docs/current/sql-copy.html) bu dosya biçimini veritabanı süper kullanıcılarıyla veya `pg_write_server_files` gibi rollere sahip kullanıcılarla sınırlar. Hem veritabanı rolünü hem de sunucu işletim sistemi hesabının dosya izinlerini doğrulayın; uygulama bağlantı dizesi tek başına dosya yazma yetkisi vermez. Zinciri değerlendirirken ayrıcalıklı başlatıcıyı ve veritabanı hesabının yeteneklerini birbirinden ayrı ele alın.

## Çalışma zamanı artefaktlarını inceleyin

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Silinen executable'lar ve silinmiş ancak açık dosyalar, son descriptor kapanana kadar referanslı kalır. Bunlar kanıtları veya erişilebilir sırları koruyabilir. Process ortamları ve belleği kimlik bilgileri içerebilir, ancak başka bir process'i okumak sahiplik, `/proc` mount seçenekleri, Yama ptrace politikası ve diğer güvenlik denetimleriyle kısıtlanır. İlgili teknikler için [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) ve [post-exploitation credential hunting](../post-exploitation/README.md) bölümlerine bakın.

Kaydedilmiş syscall izleri de başka bir dosya izni sınırıdır. [`strace`, syscall argümanlarını bir çıktı dosyasına kaydeder](https://man7.org/linux/man-pages/man1/strace.1.html); bu nedenle [`execve` argümanlarını](https://man7.org/linux/man-pages/man2/execve.2.html) içeren okunabilir bir iz, ayrıcalıklı bir job'ın komut satırında ilettiği parolayı açığa çıkarabilir. Önce mevcut kullanıcının söz konusu izi okuyabildiğini ve argümanın gerçekten bir kimlik bilgisi içerdiğini doğrulayın; daha sonra Unix hesabı geçişinde bu kimlik bilgisinin kabul edildiğini ayrıca kanıtlamak gerekir. Dosya metadata'sı, rutin enumeration sırasında her izi taramadan veya içeriğini yazdırmadan yararlanılabilecek pasif bir ipucudur.

## Ayrıcalıklı ofis otomasyonu soketleri

LibreOffice ve OpenOffice, UNO API'lerini `--accept=socket,host=<host>,port=<port>;urp;` argümanı üzerinden sunabilir. Erişilebilir bir endpoint'i olan root-owned bir ofis process'i, düşük ayrıcalıklı yerel bir kullanıcının bu process'in güvenlik bağlamında API servislerini çağırmasına olanak tanıyabilir. `SystemShellExecute` servisi, bir sistem komutu başlatma işlemi içerir. Loopback'e bind etmek uzaktan erişimi sınırlar, ancak başka bir denetim erişimi engellemediği sürece soket yerel kullanıcılar tarafından erişilebilir durumda kalır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

İşlem sahibini, tam `--accept` argümanını ve o anda dinlenen adres ile portu ilişkilendirin. Bağlama işlemi başarısız olan yapılandırılmış bir acceptor yalnızca bir ipucudur; pasif numaralandırma sırasında API'ye bağlanmayın veya API'yi çağırmayın. Sırf bu durumu test etmek için ayrıcalıklı bir office örneği başlatmaktan kaçının.

## Ayrıcalıklı işlemlerin kullandığı System V paylaşımlı bellek

Root tarafından sahip olunan bir yardımcı program, başka bir kullanıcının yazabildiği bir System V paylaşımlı bellek segmenti oluşturabilir. Yardımcı program daha sonra bu segmentteki verilere bir shell komutunda veya başka bir hassas işlemde güvenirse, çalıştırılabilir dosya ve dosyaları korumalı olsa bile bu segment bir ayrıcalık sınırını aşar. `shmget()` erişim izinlerini bayraklarının alt dokuz bitinden alır; `0666` modu diğer kullanıcıların yazmasına izin verirken `IPC_CREAT` bayrağı bu izinleri daraltmaz. Etkin segmentleri pasif olarak `ipcs -m` ile inceleyin ve sahiplerini, modlarını ve ömürlerini ayrıcalıklı işlem ve girdi işleme biçimiyle ilişkilendirin. Tek başına, herkesin yazabildiği bir segment komut çalıştırıldığını kanıtlamaz.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmentleri, `/dev/shm` altındaki POSIX paylaşımlı bellek dosyalarından farklıdır. Yalnızca bir anlığına oluşturulan bir segment, tek bir `ipcs` anlık görüntüsünde görünmeyebilir; dolayısıyla boş çıktı, paylaşımlı bellek kullanan bir yardımcı programı aklamaz. Kaynağını veya ikili dosyanın davranışını ve onu başlatan `sudo` kuralını inceleyin; numaralandırma sırasında segment oluşturmak için ayrıcalıklı yardımcı programı çalıştırmayın. [IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md), namespace’lerin görünürlüğü nasıl etkilediğini açıklar.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul, agent’ının işletim sistemi kimliğiyle script sağlık kontrolleri çalıştırabilir. Bir agent root olarak çalışıyorsa, `enable_script_checks` etkinse ve daha düşük ayrıcalıklı bir kullanıcının yerel HTTP API üzerinden script kontrolü içeren bir hizmet kaydetmesine izin veriyorsa, bu kullanıcı root olarak çalışan komutlar çalıştırılmasına neden olabilir. API’yi yalnızca `127.0.0.1` adresine bağlamak, yerel kullanıcıların API’ye erişmesini yine de engellemez. `enable_local_script_checks` ayarı daha sınırlıdır: HTTP API kayıtları üzerinden gönderilen script kontrollerini hariç tutar. Consul ACL’leri etkin olduğunda, hizmet kaydı için `service:write` gerekir; tek başına `acl.default_policy=allow` satırı, anonim bir çağıranın kayıt yapabildiğini kanıtlamaz. Agent’ın gerçek kimliğini, yüklenen ayarları, API bağlamasını ve yetkilendirmeyi birlikte inceleyin.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Çalışan agent'ın `-config-dir` ve `-config-file` argümanlarını izleyerek ilgili yapılandırmayı bulun ve yalnızca script-check ile ACL alan adlarını ve ayarlarını inceleyin. Yapılandırma dosyaları gossip key veya token da içerebilir; bunları paylaşılan loglara yapıştırmaktan kaçının. Sırf bu durumu listelemek için bir servis kaydetmeyin veya health check çalıştırmayın.

Daha düşük ayrıcalıklı bir kullanıcı, root olarak çalışan bir agent'ın `-config-dir` ile belirttiği dizine **yazma ve dizinde arama** yetkisine sahipse ayrı bir yerel dosya yolu bulunur: bu dizinden yeni bir `.hcl` veya `.json` servis tanımı yüklenebilir. Dizin listeleme engellense bile dizinde arama ve yazma yetkisi dosya eklemeye olanak tanıyabilir. Root olarak komut çalıştırılabileceğini doğrulamak için agent'ın gerçekten bu dizini yüklediğini, **etkin** script-check ayarının yerel tanımlara izin verdiğini, tanımın yüklendiğini ve agent'ın root ayrıcalıklarını koruduğunu teyit edin. [Consul belgeleri](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations), hangi ayarların ve health-check tanımlarının yeniden yüklenebileceğini açıklar; script check'leri etkinleştirmek yeniden başlatma gerektirebilir, bu nedenle kurulu sürümün davranışını doğrulayın. ACL'ler agent'ı koruyorsa [`consul reload`, `agent:write` gerektirir](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); yalnızca KV yazma izni bunu sağlamaz. Yazılabilir dizin meta verilerini, yetkili bir reload, restart veya komut çalıştırma işleminin kanıtı olarak değil, inceleme işareti olarak değerlendirin. Yapılandırmaya yazmadan veya API'yi çağırmadan yolları, izinleri ve policy'yi inceleyin.

## Servis yürütme zincirini izleyin

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Sistem birimini, drop-in dosyalarını, `EnvironmentFile=`, yardımcı script'leri, göreli komutları, yazılabilir dizinleri ve socket activation'ı kontrol edin. Root sahibi olduğu birim, kullanıcı tarafından yazılabilir bir config veya script okuyorsa yine de güvenli olmayabilir. [Arbitrary file write](../interesting-files-permissions/write-to-root.md) sayfasında yaygın service ve unit abuse yolları ele alınır. Tek seferlik `ps` listelemesinde görünmeyen kısa ömürlü işleri izlemek için [pspy](https://github.com/DominicBreuker/pspy) veya audit/process telemetry kullanın.

Özel bir **xinetd** service için etkin stanza'daki `server`, `user` ve erişim denetimlerini çalışan listener ve tam executable ile ilişkilendirin. [`user` ayarı](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) başlatılan process'in kimliğini belirlerken, executable üzerindeki set-user-ID biti [`execve` bu geçişe izin veriyorsa](https://man7.org/linux/man-pages/man2/execve.2.html) effective identity'yi ayrıca değiştirebilir. Güvenilmeyen input alan ve erişilebilir olan ayrıcalıklı bir binary, sabit boyutlu bir buffer'a sınırlandırılmamış [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) gibi memory-safety hataları için offline source veya disassembly incelemesini gerektirir. Service eşlemesi ve set-user-ID metadata'sı bu tür bir hatanın kanıtı değil, inceleme ipucudur; pasif enumeration sırasında crash input'ları göndermeyin veya çalışan ayrıcalıklı service'te debug yapmayın.

Source kodu okunabilen özel bir ayrıcalıklı listener için, [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) gibi bir copy işleminde kullanılan ve çağıranın denetleyebildiği her uzunluğu inceleyin. Yalnızca geçerli write index'inin sabit bir buffer içinde olduğunu kontrol etmek, **copy length** değerinin kalan alana sığdığını göstermez; index'in aralıkta olduğunu doğruladıktan sonra `copy_length <= capacity - index` koşulunu kontrol edin ve signedness ile arithmetic overflow durumlarını inceleyin. Bu yalnızca input'un o işleme ulaştığı, listener'ın daha düşük ayrıcalıklı kullanıcı tarafından erişilebilir olduğu ve process'in daha yüksek effective identity'yi koruduğu durumlarda inceleme ipucudur. Enumeration sırasında source ve process metadata'sını offline inceleyin; çalışan service'e crash input'ları göndermeyin.

**Upstart** kullanan sistemlerde system job tanımları `/etc/init/*.conf` altında bulunabilir. Geçerli init daemon'ı tam olarak o job'ı yüklüyorsa, `script` veya `exec` stanza'sı daha yüksek ayrıcalıklı bir kimlikle çalışıyorsa ve kullanıcı job'ı izin verilen bir `initctl` komutu ya da başka bir gerçek tetikleyiciyle başlatabiliyorsa, geçerli kullanıcı tarafından yazılabilir bir job dosyası önem taşır. Tek başına bir sudo `initctl` izni, herhangi bir job dosyasının yazılabilir olduğunu veya değiştirilmiş bir job'ın çalışacağını kanıtlamaz. Enumeration sırasında job dosyasının tam izinlerini, effective run-as ayarını, etkin daemon'ı ve tetikleyiciyi kontrol edin; job'ı düzenlemeyin veya başlatmayın. [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) ve [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) kılavuzlarına bakın.

`/etc/autologin/passwd` gibi okunabilir bir autologin password dosyası, [boot job'ın tam olarak bu yolu okuduğu](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf) sistemlerde credential exposure ipucudur. Boot job'ın kurulu olduğunu ve dosyayı kullandığını doğrulayın; ardından password'ün başka bir local account veya service için geçerli olup olmadığını ayrıca kontrol edin. Yalnızca dosya adı password reuse olduğunu kanıtlamaz; password'ü paylaşılan enumeration çıktısına koymadan path ve erişim metadata'sını kaydedin.

Bir unit'in `ExecStart=` satırı veya zamanlanmış bir komut, listelenemeyen bir dizindeki script'in tam pathname'ini gösterebilir. [Directory search permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html) geçerli kimliğin bu bilinen path üzerinden ilerlemesine yine de izin verebilir; başarısız bir dizin listelemesinin dosyayı koruduğunu varsaymak yerine her parent dizinde search erişimini ve dosyada read iznini doğrulayın. Okunabilir bir script transfer credential'ı içerebilir; ancak başka bir account'a geçiş için bu credential'ın hâlâ geçerli olması ve o account tarafından ayrıca kabul edilmesi gerekir. Secret değerlerini paylaşılan log'lara yazmadan path'i ve izin kanıtlarını kaydedin.

Zamanlanmış bir CommonJS Node.js script'i için, script'in kendisi salt okunur olsa bile `require('package')` gibi bare import'ları inceleyin. [Node, importing file'ın yanındaki `node_modules` dizininde ve ardından ancestor dizinlerinde arama yapar](https://nodejs.org/api/modules.html#loading-from-node_modules-folders); daha sonra yapılandırılmış global path'lere başvurur. Bu ancestor dizinlerinden birine **yazma ve arama** izni olan daha düşük ayrıcalıklı bir kullanıcı, aramada önce eşleşecek bir package oluşturabilir. Tam import'un kullanıldığını, seçilen package'ın built-in module olmadığını, ilgili path'in oluşturulabildiğini veya değiştirilebildiğini, kurulu runtime'da module'ün bu konumdan çözümlendiğini ve daha yüksek ayrıcalıklı bir job'ın gelecekteki bir çalıştırmada onu yükleyeceğini doğrulayın. Yazılabilir parent metadata'sı yalnızca inceleme ipucudur; module bırakmadan veya job'ı tetiklemeden script'i ve scheduler'ı pasif biçimde inceleyin.

Farklı bir OS kimliği altında package kuran otomatik bir job, private Python package index'i de bir trust boundary hâline getirir. Tam job'ı ve run-as account'unu, yapılandırılmış index'i, seçilen package adlarını ve daha düşük ayrıcalıklı bir kullanıcının job'ın gerçekten kuracağı bir package'ı yayımlayıp yayımlayamayacağını veya değiştirebilip değiştiremeyeceğini ilişkilendirin. Bir source distribution oluşturmak, build backend'ini veya eski `setup.py` dosyasını installer'ın kimliği altında çalıştırabilir; kurulu package'ı import etmek ise ayrı bir execution path'tir. Bir index listener'ı, okunabilir upload password hash'i veya package filename'ı tek başına bu zinciri kanıtlamaz. Enumeration sırasında bir şey yüklemeden veya kurmadan job'ı, index yetkilendirmesini ve package provenance'ını inceleyin. [pip'in build-system arayüzüne](https://pip.pypa.io/en/stable/reference/build-system/) ve [güvenli kurulum rehberine](https://pip.pypa.io/en/stable/topics/secure-installs/) bakın.

Ayrı bir web service veya container tarafından yönetilen task queue'yu ayrıcalıklı bir agent sorguluyor olabilir. Daha düşük güven düzeyindeki bir kimlik service'in task database'ine yazabiliyorsa, bu satırların gerçekten o agent'a sunulup sunulmadığını ve command task'ın agent'ın OS kimliğiyle çalışıp çalışmadığını belirleyin. Database write erişimini, hedef session veya routing key'i, etkin polling'i, task yetkilendirmesini ve agent'ın effective user'ını ayrı ayrı doğrulayın. Bir container içindeki root, tek başına host-root erişimi anlamına gelmez; sınır ancak host-privileged bir consumer saldırganın denetlediği task verisini çalıştırırsa aşılır. Enumeration sırasında queue'yu değiştirmeden veya task göndermeden process, database file ve service metadata'sını inceleyin.

Zamanlanmış bir job bunun yerine application database config satırından komut okuyabilir. Daha düşük ayrıcalıklı database role'ünün tam o satırı değiştirebildiğini, etkin job'ın değişiklikten sonra satırı okuduğunu ve değerin daha yüksek OS kimliği altında bir shell'e veya eşdeğer bir command runner'a ulaştığını doğrulayın. Database write erişimi veya komut gibi görünen bir değer tek başına execution'ı kanıtlamaz; pasif enumeration sırasında satırı değiştirmeden job'ı ve izinleri inceleyin.

Kuyruğa alınmış bir mesaj kod yerine URL de içerebilir. Ayrıcalıklı bir consumer bu URL'yi alıp yanıtı Lua veya başka bir executable plugin olarak yüklüyorsa, publisher'ın tam exchange ve routing key üzerindeki iznini, tüketilen queue'ya olan binding'i, fetch ve plugin-load yolunu ve worker'ın effective identity'sini doğrulayın. [RabbitMQ, yayımlanan mesajları exchange'ler üzerinden yönlendirir](https://www.rabbitmq.com/docs/exchanges); bir broker listener'ı veya geçerli login bilgileri tek başına bu worker'a teslimatı kanıtlamaz. Yakalanmış cleartext broker credential'ları, gerçek packet-capture erişimi ve okunabilir traffic gerektiren ayrı bir ipucudur; publish yetkisini kanıtlamaz. Lua plugin'i, yalnızca bu API runtime'ında mevcutsa [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) üzerinden shell komutlarını çağırabilir. Pasif enumeration sırasında traffic yakalamadan, mesaj yayımlamadan veya plugin getirmeden config'i ve kodu inceleyin.

Ayrıcalıklı bir Python service local HTTP veya socket endpoint'i sunuyorsa, dosya izinleri değişikliği engellese bile okunabilir bir script input'tan code'a giden yolu açığa çıkarabilir. Etkin process ve unit identity'sini tam script, listener, route yetkilendirmesi ve çağıranın denetlediği alanlarla ilişkilendirin. Ardından bu alanların parsing ve validation aşamalarından geçerek dinamik bir `eval()` veya `exec()` sink'ine ulaşıp ulaşmadığını izleyin. Özellikle request text'inden yeni bir f-string oluşturup bunu evaluate etmek, saldırganın sağladığı replacement field'ları Python expression'ları olarak yorumlayabilir ([Python `eval` uyarısı](https://docs.python.org/3/library/functions.html#eval); [f-string semantiği](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Tek başına `eval` eşleşmesi veya loopback binding, güvenilmeyen bir çağıranın sink'e ulaştığını kanıtlamaz; enumeration sırasında test payload'ı göndermeden gerçek dataflow'u ve erişim denetimlerini inceleyin.

Bu route üzerindeki signed-request gate de ayrıca incelenmelidir. Okunabilir source, signing key'in belirgin biçimde küçük veya tahmin edilebilir bir çıktı uzayından türetildiğini gösteriyorsa ve service geçerli bir signed sample sunuyorsa, signature artık ayrıcalıklı bir `eval()` sink'ini korumayabilir. Tam key derivation ve verifier'ı, çalışan service'in kimliğini ve local caller erişimini, signed field'ın sink'e ulaşıp ulaşmadığını doğrulayın; Python'un [`random` module'ünün](https://docs.python.org/3/library/random.html) import edilmesi veya bir sample signature bu koşulların hiçbirini kanıtlamaz. Python ayrıca `__builtins__` değerini kısıtlamanın, güvenilmeyen `eval()` input'u için [bir security boundary olmadığını](https://docs.python.org/3/library/functions.html#eval) belirtir. Key analizini offline yapın ve pasif enumeration sırasında sahte request göndermeyin.

Boş ama yazılabilir bir `/etc/systemd/system/<unit>.service.d` dizini, unit dosyası ve mevcut tüm drop-in'ler korunsa bile önem taşır: kullanıcı yeni bir `.conf` override oluşturabilir. Dizinin geçerli kimlik tarafından yazılabilir ve aranabilir olduğunu, unit'in yüklü olup root olarak çalıştığını ve daemon reload sonrasında restart gerçekleşip gerçekleşmeyeceğini kontrol edin. Reload veya restart izni, timer ya da daha sonraki bir boot değişikliği etkinleştirebilir; yalnızca dizine yazma erişimi olması değişikliği hemen çalıştırmaz.

Çalışan service'ler için unit'in `[Service]` bölümündeki literal `EnvironmentFile=` path'lerini, adları `.env` ile başlamayan dosyalar dâhil, takip edin. Düşük ayrıcalıklı bir kullanıcı bunlardan birini okuyabiliyorsa, değerleri paylaşılan log'lara yazdırmadan `API_TOKEN` veya `APP_SECRET_KEY` gibi credential içerebilecek key adlarını listeleyin. Etkin unit'i değerlendirirken drop-in override'larını ve isteğe bağlı `-` öneklerini kontrol edin. Okunabilirlik credential exposure ipucudur; ayrıcalık yükseltme sağlaması için değerin hâlâ geçerli bir ayrıcalıklı işlemde kullanılabilmesi gerekir.

### Güvenilmeyen upload'ların ayrıcalıklı işlenmesi

Root olarak çalışan bir file watcher, kullanıcı tarafından yazılabilir upload dizinindeki dosyaları kısa ömürlü bir parser veya extractor'a aktarabilir. Çalışan watcher'ın parent script'ini veya service'ini takip edin; tam dizini, oraya kimlerin dosya koyabildiğini, child command'i ve argümanlarını, ayrıca child'ın çalıştığı kimliği doğrulayın. Bir process snapshot'ı watcher'ı gösterebilir ama upload'lar arasındaki extractor'ı kaçırabilir. Pasif enumeration sırasında test payload'ı koymayın veya watcher'ı tetiklemeyin.

Somut bir örnek, Binwalk'ın extraction mode (`-e`) ile saldırganın denetlediği PFS verisini işlemesidir. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617), PFS extractor'ının plugin path'i dâhil, amaçlanan dizinin dışına yazmasına ve Binwalk'ın bu dosyayı daha sonra yükleyebilmesine olanak tanıyordu. Upstream düzeltmeyi [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) sürümünde yayımladı; ancak distribution backport'ları ekranda görünen eski bir sürümü koruyabilir. Uygulanabilirliğe karar vermeden önce kurulu package'ın güvenlik durumunu [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510) gibi kaynaklardan kontrol edin. Tek başına kurulu Binwalk sürümü bir privilege-escalation yolu olduğunu kanıtlamaz: extraction'ın, daha düşük ayrıcalıklı kullanıcının denetleyebildiği input üzerinde daha ayrıcalıklı bir process tarafından gerçekten çağrılması gerekir.

### Yerel dependency'lerle zamanlanmış build'ler

Zamanlanmış bir `cargo run`, source kodunu job'ın run-as kullanıcısı olarak yeniden derler. Yalnızca ana crate'i değil, manifest'teki yerel `{ path = "..." }` dependency'leri ile her dependency'nin source ve parent-directory izinlerini de inceleyin. Daha düşük ayrıcalıklı bir kullanıcı Cargo'nun derlediği bir dependency'yi değiştirebiliyorsa ve zamanlanmış job sonucu çalıştırıyorsa, derlenen kod o run-as kullanıcısı olarak çalışabilir. Etkin scheduler komutunu, working directory'yi, dependency çözümlemesini ve yeniden build yapılıp yapılmayacağını doğrulayın; başka bir yerdeki yazılabilir Rust source dosyası yalnızca bir ipucudur. Pasif triage için manifest'i ve path metadata'sını okumak yeterlidir. [Cargo path-dependency belgelerine](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) bakın.

## Xvfb framebuffer dosyaları

`Xvfb -fbdir <directory>`, sanal ekranları için `Xvfb_screen<n>` adında memory-mapped dosyalar kullanır. Başka bir kullanıcının çalışan Xvfb process'i, ekran dosyaları geçerli kullanıcı tarafından okunabilen bir dizini belirtiyorsa framebuffer o kullanıcının masaüstü içeriğini açığa çıkarabilir. Process'i, dosya sahipliğini ve izinlerini birlikte doğrulayın; tek başına okunabilir bir dosya, ekranda yararlı içerik olduğunu kanıtlamaz. Görüntü verisini paylaşılan enumeration çıktısına kopyalamadan önce path'leri ve metadata'yı inceleyin. [`-fbdir` davranışı](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) Xvfb manual'ında açıklanmıştır.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` kılavuzu](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` kılavuzu](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` kılavuzu](https://man.openbsd.org/ipcs.1)
4. [Consul agent yapılandırması: script kontrolleri](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent service registration API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL yapılandırması](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice yardımı: harici API istemcileri için socket açma](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
