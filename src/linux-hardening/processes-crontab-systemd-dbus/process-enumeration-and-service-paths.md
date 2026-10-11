# Process Enumeration and Service Paths

{{#include ../../banners/hacktricks-training.md}}

Sorulması gereken faydalı soru, daha düşük ayrıcalıklara sahip bir kullanıcının etkileyebileceği verileri veya kodu hangi ayrıcalıklı sürecin kullandığıdır. Süreç ağacını, canlı ortamı, açık dosyaları ve her aday süreci başlatan unit'i veya betiği inceleyin.

## Süreçleri ve sahipliklerini eşleyin

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Farklı kullanıcılar arasındaki bir üst süreç-alt süreç ilişkisi normal olabilir; ancak beklenmedik bir geçiş, üst sürecin komutunun, argümanlarının, yürütülebilir dosyasının, çalışma dizininin ve başvurulan dosyaların incelenmesini gerektirir. Sahip ve oturum açma bağlamını yorumlamak için [users and sessions](../user-information/user-and-session-triage.md) sayfasını kullanın.

### Yerel sanal makine konsolları

Bir QEMU sürecinin `-spice` seçeneklerini dinleme adresiyle birlikte inceleyin. [QEMU belgelerine](https://www.qemu.org/docs/master/system/qemu-manpage.html) göre `disable-ticketing`, SPICE istemcilerinin kimlik doğrulaması olmadan bağlanmasına izin verir. Loopback'e bağlı bir dinleyiciye diğer yerel ana makine kullanıcıları yine de erişebilir. Komut satırını açıkta bir konsol olarak değerlendirmeden önce çalışan dinleyiciyi, kimlik doğrulama seçeneklerini ve yerel erişimi doğrulayın. Konsol denetimi **guest**'i etkiler; bir guest hesabı edinmek veya önyükleme durumunu değiştirmek guest tarafında ayrı koşullar gerektirir ve sanallaştırma ana makinesinde root yetkisi sağlamaz. Pasif enumeration sırasında guest'e bağlanmadan veya guest'i yeniden başlatmadan süreç argümanlarını ve soket meta verilerini okuyun.

Yerel olarak erişilebilen bir web arayüzü, ilk shell o hesabın dosyalarına erişemese bile hizmet hesabıyla kod çalıştırabilir. Örneğin, CVE-2023-0297, güvenilmeyen JavaScript'in Python importları etkin durumdayken Js2Py'ye ulaşması halinde pyLoad'un `/flash/addcrypted2` işleme biçimini etkiliyordu; [upstream düzeltmesi](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) `pyimport` özelliğini devre dışı bıraktı. Bir pyLoad sürecini yükseltme yolu olarak değerlendirmeden önce çalışan süreç sahibini, dinleme adresini, endpoint'in dışarıya açıklığını ve kurulu yamayı ya da vendor backport'unu karşılaştırın. Süreç adı, açık port veya paket sürümü tek başına açıklığı kanıtlamaz; pasif enumeration sırasında kod çalıştırma payload'ı göndermeyin.

### Terminal paylaşan ayrıcalıklı login shell'leri

Bağımsız bir pseudo-terminal olmadan `su --login <user>` çalıştıran ayrıcalıklı bir etkileşimli shell, terminalini daha düşük ayrıcalıklı login shell'iyle paylaşabilir. Kullanıcının başlangıç dosyası denetlenebiliyorsa ve içindeki kod terminal girdisi enjekte etmek için `TIOCSTI` kullanabiliyorsa, ayrıcalıklı shell yeniden çalışmaya başladığında girdi ona ulaşabilir. [util-linux `su` kılavuzu](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES), paylaşılan terminal riskini açıklar ve etkileşimli kullanımda `su --pty`/`-P` kullanılmasını önerir; `su -c` ise denetleyici terminal olmadan ayrı bir oturum başlatır. Bu risk; gerçek üst shell'e, terminal ilişkisine, hedef başlangıç dosyasına ve kernel ilkesine bağlıdır. Tek başına süreç adı veya `su -l` argümanı yalnızca incelenmesi gereken bir ipucudur.

Gözlemlenen süreç ağacını ve TTY sütunlarını, ardından okunabilir launcher dosyasını ve başlangıç dosyasının sahipliğini/izinlerini inceleyin. Linux'ta `/proc/sys/dev/tty/legacy_tiocsti` mevcutsa ilkeyi anlamaya yardımcı olabilir; dosyanın bulunmaması güvenliğin kanıtı değildir. [Linux `TIOCSTI` kılavuzu](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html), Linux 6.2'den itibaren bu sysctl false olduğunda işlemin `CAP_SYS_ADMIN` gerektirebileceğini belirtir. Ana makineyi enumerate etmek amacıyla ioctl çağrısı yapmayın.

Bir veritabanı hesabı bazen hedef kullanıcının başlangıç dosyasını doğrudan dosya sistemi yazma erişimi olmadan değiştirebilir. PostgreSQL sunucu tarafındaki `COPY ... TO 'filename'` komutu, dosyayı veritabanı sunucusunun işletim sistemi hesabıyla yazar; ancak [PostgreSQL kısıtlamalarına](https://www.postgresql.org/docs/current/sql-copy.html) göre bu dosya biçimini yalnızca veritabanı superuser'ları veya `pg_write_server_files` gibi rollere sahip kullanıcılar kullanabilir. Hem veritabanı rolünü hem de sunucu işletim sistemi hesabının dosya izinlerini doğrulayın; uygulama bağlantı dizesi tek başına dosya yazma yetkisi vermez. Zinciri değerlendirirken ayrıcalıklı launcher ile veritabanı hesabının yeteneklerini birbirinden ayrı ele alın.

## Çalışma zamanı artefaktlarını inceleyin

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Silinen executable dosyalar ve silinmiş ancak açık dosyalar, son descriptor kapanana kadar referanslı kalır. Kanıtları veya erişilebilir sırları koruyabilirler. Process ortamları ve belleği kimlik bilgileri içerebilir; ancak başka bir process'i okumak sahiplik, `/proc` mount seçenekleri, Yama ptrace policy ve diğer güvenlik kontrolleriyle kısıtlanır. İlgili teknikler için [dosya descriptor'ları](../main-system-information/filesystem-links-and-file-descriptors.md) ve [post-exploitation kimlik bilgisi avı](../post-exploitation/README.md) bölümlerine bakın.

Kaydedilmiş syscall izleri de başka bir dosya izni sınırıdır. [`strace`, syscall argümanlarını bir çıktı dosyasına kaydeder](https://man7.org/linux/man-pages/man1/strace.1.html); bu nedenle okunabilir bir [`execve` argümanları](https://man7.org/linux/man-pages/man2/execve.2.html) izi, ayrıcalıklı bir işin komut satırında geçirdiği parolayı açığa çıkarabilir. Önce mevcut kullanıcının söz konusu izi okuyabildiğini ve argümanın gerçekten bir kimlik bilgisi içerdiğini doğrulayın; daha sonra Unix hesabına geçiş için bu kimlik bilgisinin orada kabul edildiğine dair ayrıca kanıt gerekir. Dosya meta verileri, rutin enumeration sırasında her izi taramadan veya içeriğini yazdırmadan elde edilebilecek yararlı bir pasif ipucudur.

## Ayrıcalıklı ofis otomasyonu soketleri

LibreOffice ve OpenOffice, UNO API'lerini `--accept=socket,host=<host>,port=<port>;urp;` argümanı aracılığıyla açığa çıkarabilir. Erişilebilir bir endpoint'i olan root'a ait bir ofis process'i, düşük ayrıcalıklı yerel bir kullanıcının o process'in güvenlik bağlamında API servislerini çağırmasına olanak tanıyabilir. `SystemShellExecute` servisi, sistem komutu başlatmaya yönelik bir işlem içerir. Loopback'e bağlamak uzaktan erişilebilirliği sınırlar; ancak başka bir kontrol erişimi engellemediği sürece soket yerel kullanıcılar tarafından erişilebilir kalır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Süreç sahibini, tam `--accept` argümanını ve mevcut dinleme adresi ile portu ilişkilendirin. Bind işlemi başarısız olan yapılandırılmış bir acceptor yalnızca bir ipucudur; pasif enumeration sırasında API'ye bağlanmayın veya API'yi çağırmayın. Bu durumu test etmek için ayrıcalıklı bir office instance başlatmaktan kaçının.

## Ayrıcalıklı süreçlerin kullandığı System V shared memory

Root sahibi bir yardımcı program, başka bir kullanıcının yazabileceği bir System V shared-memory segmenti oluşturabilir. Yardımcı program daha sonra bu segmentteki verilere bir shell komutunda veya başka bir hassas işlemde güvenirse, yürütülebilir dosya ve dosyaları korunsa bile segment bir ayrıcalık sınırını aşar. `shmget()`, erişim izinlerini bayraklarının en düşük dokuz bitinden alır; `0666` modu diğer kullanıcıların yazmasına izin verirken `IPC_CREAT` bayrağı bu izinleri daraltmaz. Etkin segmentleri pasif olarak `ipcs -m` ile inceleyin ve sahiplerini, modlarını ve yaşam sürelerini ayrıcalıklı süreç ve onun girdi işleme biçimiyle ilişkilendirin. Tek başına, herkesin yazabildiği bir segment komut yürütüldüğünü kanıtlamaz.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmentleri, `/dev/shm` altındaki POSIX shared-memory dosyalarından farklıdır. Yalnızca kısa süreliğine oluşturulan bir segment, tek bir `ipcs` snapshot'ında görünmeyebilir; bu nedenle boş çıktı, shared memory kullanan bir helper'ı aklamaz. Kaynağını veya binary davranışını ve onu başlatan `sudo` kuralını inceleyin; enumeration sırasında segment oluşturmak için privileged helper'ı çalıştırmayın. [IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md), namespace'lerin görünürlüğü nasıl etkilediğini açıklar.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul, işletim sistemi düzeyinde agent'ının kimliğiyle script health check'leri çalıştırabilir. Bir agent root olarak çalışıyorsa, `enable_script_checks` etkinse ve daha düşük ayrıcalıklı bir kullanıcının yerel HTTP API üzerinden script check içeren bir service kaydetmesine izin veriyorsa, bu kullanıcı root olarak çalışan komutları tetikleyebilir. API'yi yalnızca `127.0.0.1` adresine bind etmek, yerel kullanıcıların API'ye erişmesini engellemez. `enable_local_script_checks` ayarı daha kısıtlayıcıdır: HTTP API kayıtları üzerinden gönderilen script check'leri hariç tutar. Consul ACL'leri etkinleştirildiğinde, service kaydı için `service:write` gerekir; tek başına `acl.default_policy=allow` satırı, anonim bir çağıranın kayıt yapabildiğini kanıtlamaz. Agent'ın gerçek kimliğini, yüklenen ayarları, API binding'ini ve yetkilendirmeyi birlikte inceleyin.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Çalışan agent'ın `-config-dir` ve `-config-file` argümanlarını izleyerek ilgili yapılandırmayı bulun; yalnızca script-check ve ACL alan adlarını ve ayarlarını inceleyin. Yapılandırma dosyaları gossip key'leri veya token'lar da içerebilir; bunları paylaşılan loglara yapıştırmayın. Bu durumu yalnızca listelemek için servis kaydetmeyin veya health check çalıştırmayın.

Daha düşük ayrıcalıklı bir kullanıcı, root olarak çalışan agent'ın `-config-dir` ile belirttiği dizine **yazma ve arama** iznine sahipse ayrı bir yerel dosya yolu da vardır: bu dizinden yeni bir `.hcl` veya `.json` servis tanımı yüklenebilir. Dizini listeleme izni olmasa bile dizinde arama ve yazma izni dosya eklemeye olanak sağlayabilir. Root olarak komut çalıştırılabilmesi için agent'ın bu dizini gerçekten yüklediğini, **etkin** script-check ayarının yerel tanımlara izin verdiğini, tanımın yüklendiğini ve agent'ın root ayrıcalıklarını koruduğunu doğrulayın. [Consul belgelerinde](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) hangi ayarların ve health-check tanımlarının yeniden yüklenebildiği açıklanır; script checks özelliğini etkinleştirmek için yeniden başlatma gerekebilir, bu nedenle yüklü sürümün davranışını doğrulayın. ACL'ler agent'ı koruyorsa [`consul reload`, `agent:write` gerektirir](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); yalnızca KV yazma iznine sahip olmak bu izni sağlamaz. Yazılabilir dizin metadata'sını yetkili bir reload, restart veya komut çalıştırma işleminin kanıtı değil, inceleme işareti olarak değerlendirin. Yapılandırma yazmadan veya API'yi çağırmadan yolları, izinleri ve politikayı inceleyin.

## Servis çalıştırma zincirini izleyin

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Unit'i, drop-in'leri, `EnvironmentFile=` değerlerini, yardımcı script'leri, göreli komutları, yazılabilir dizinleri ve socket activation'ı kontrol edin. Root sahipliğindeki bir unit bile kullanıcı tarafından yazılabilir bir config veya script okuduğunda güvensiz olabilir. [Arbitrary file write](../interesting-files-permissions/write-to-root.md) sayfası yaygın service ve unit kötüye kullanım yollarını ele alır. Tek seferlik bir `ps` listelemesinde gözden kaçan kısa ömürlü işleri [pspy](https://github.com/DominicBreuker/pspy) veya audit/process telemetrisiyle izleyin.

Özel bir **xinetd** service'i için etkin stanza'daki `server`, `user` ve erişim kontrollerini çalışan listener ve tam executable ile ilişkilendirin. [`user` ayarı](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) başlatılan process'in kimliğini belirlerken, executable üzerindeki set-user-ID biti, [`execve` bu geçişe izin veriyorsa](https://man7.org/linux/man-pages/man2/execve.2.html) effective kimliği ayrıca değiştirebilir. Güvenilmeyen girdiyi kabul eden ve erişilebilen ayrıcalıklı bir binary, sabit boyutlu bir buffer'a sınırlandırılmamış [`scanf` string dönüşümü](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) gibi memory-safety hataları için çevrimdışı kaynak kodu veya disassembly incelemesini gerektirir. Service eşlemesi ve set-user-ID metadata'sı bu tür bir hatanın kanıtı değil, inceleme ipuçlarıdır; pasif enumeration sırasında crash girdileri göndermeyin veya çalışan ayrıcalıklı service'te debug yapmayın.

Kaynak kodu okunabilir özel bir ayrıcalıklı listener için [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) gibi bir kopyalama işleminde kullanılan, çağıranın kontrol ettiği her uzunluğu inceleyin. Yalnızca geçerli yazma indeksinin sabit bir buffer içinde olduğunu doğrulamak, **kopyalama uzunluğunun** kalan alana sığdığını göstermez; indeksin aralık içinde olduğunu doğruladıktan sonra `copy_length <= capacity - index` koşulunu kontrol edin; ayrıca işaretliliği ve aritmetik taşmayı da kontrol edin. Bu yalnızca girdi ilgili işleme ulaşıyorsa, düşük ayrıcalıklı kullanıcı listener'a erişebiliyorsa ve process daha yüksek bir effective kimliği koruyorsa bir inceleme ipucudur. Kaynak kodunu ve process metadata'sını çevrimdışı inceleyin; enumeration sırasında çalışan service'e crash girdileri göndermeyin.

**Upstart** kullanan sistemlerde system job tanımları `/etc/init/*.conf` altında bulunabilir. Mevcut kullanıcının yazabildiği bir job dosyası; etkin init daemon'ı tam olarak o job'ı yüklüyorsa, `script` veya `exec` stanza'sı daha yüksek ayrıcalıklı bir kimlikle çalışıyorsa ve kullanıcı job'ı izin verilen bir `initctl` komutuyla veya başka gerçek bir tetikleyiciyle başlatabiliyorsa önem taşır. Tek başına bir sudo `initctl` yetkisi, herhangi bir job dosyasının yazılabilir olduğunu veya değiştirilmiş bir job'ın çalışacağını kanıtlamaz. Tam job dosyasının izinlerini, etkin run-as ayarını, çalışan daemon'ı ve tetikleyiciyi kontrol edin; enumeration sırasında job'ı düzenlemeyin veya başlatmayın. [Upstart job yapılandırması](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) ve [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) kılavuzlarına bakın.

Sistemlerdeki [boot job tam olarak bu yolu okuyorsa](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), `/etc/autologin/passwd` gibi okunabilir bir autologin parola dosyası kimlik bilgisi ifşasına işaret eder. Boot job'ın kurulu olduğunu ve dosyayı kullandığını doğrulayın; ardından parolanın başka bir yerel hesap veya service için geçerli olup olmadığını ayrıca doğrulayın. Yalnızca dosya adı parola tekrar kullanımını kanıtlamaz; parolayı ortak enumeration çıktısına koymadan yol ve erişim metadata'sını kaydedin.

Bir unit'in `ExecStart=` değeri veya zamanlanmış bir komut, listelenemeyen bir dizinin içindeki script'in tam yolunu gösterebilir. [Dizin arama izni](https://man7.org/linux/man-pages/man7/path_resolution.7.html), mevcut kimliğin bilinen bu yolda ilerlemesine yine de izin verebilir; başarısız bir dizin listelemesinin dosyaya erişimi engellediğini varsaymak yerine her üst dizinde arama iznini ve dosyada okuma iznini doğrulayın. Okunabilir bir script aktarım kimlik bilgisi içerebilir; ancak başka bir hesaba geçiş, bu kimlik bilgisinin hâlâ geçerli olmasına ve orada bağımsız olarak kabul edilmesine bağlıdır. Gizli değerleri ortak loglara yazdırmadan yolu ve izin kanıtlarını kaydedin.

Zamanlanmış bir CommonJS Node.js script'i için, script'in kendisi salt okunur olsa bile `require('package')` gibi bare import'ları inceleyin. [Node, yapılandırılmış global yollara geçmeden önce import eden dosyanın yanındaki ve üst dizinlerindeki `node_modules` dizinlerinde arama yapar](https://nodejs.org/api/modules.html#loading-from-node_modules-folders). Bu üst dizinlerden birine **yazma ve arama** izni olan düşük ayrıcalıklı bir kullanıcı, daha önce eşleşen bir package oluşturabilir. Tam import'un çalıştırıldığını, seçilen package'ın yerleşik bir module olmadığını, ilgili yolda dosya oluşturulabildiğini veya değişiklik yapılabildiğini, kurulu runtime'da module'ün oradan çözümlendiğini ve daha yüksek ayrıcalıklı bir job'ın sonraki çalıştırmada onu yükleyeceğini doğrulayın. Üst dizinlerin yazılabilir metadata'sı yalnızca inceleme ipucudur; module yerleştirmeden veya job'ı tetiklemeden script'i ve scheduler'ı pasif biçimde inceleyin.

Otomatik bir job farklı bir OS kimliği altında package kuruyorsa özel bir Python package index'i de başka bir güven sınırıdır. Tam job'ı ve run-as hesabını; yapılandırılmış index, seçilen package adları ve düşük ayrıcalıklı bir kullanıcının job'ın gerçekten kuracağı bir package'ı yayımlayıp yayımlayamayacağıyla ilişkilendirin. Bir source distribution oluşturmak, kurulum yapanın kimliği altında build backend'ini veya eski `setup.py` dosyasını çalıştırabilir; kurulu package'ı import etmek ise ayrı bir çalıştırma yoludur. Bir index listener'ı, okunabilir yükleme parola hash'i veya yalnızca package dosya adı bu zinciri kanıtlamaz. Enumeration sırasında hiçbir şey yüklemeden veya kurmadan job'ı, index yetkilendirmesini ve package kaynağını inceleyin. [pip'in build-system arayüzüne](https://pip.pypa.io/en/stable/reference/build-system/) ve [güvenli kurulum yönergelerine](https://pip.pypa.io/en/stable/topics/secure-installs/) bakın.

Ayrı bir web service'i veya container tarafından yönetilen task queue'yu ayrıcalıklı bir agent yokluyor olabilir. Düşük güven düzeyindeki bir kimlik service'in task veritabanına yazabiliyorsa, bu satırların gerçekten o agent'a sunulup sunulmadığını ve bir command task'ın agent'ın OS kimliğiyle çalışıp çalışmadığını belirleyin. Veritabanı yazma erişimini, hedef session veya routing key'i, etkin polling'i, task yetkilendirmesini ve agent'ın effective kullanıcısını ayrı ayrı doğrulayın. Bir container içindeki root, tek başına host-root erişimi anlamına gelmez; sınır ancak host ayrıcalıklı bir consumer saldırganın kontrol ettiği task verisini çalıştırırsa aşılır. Enumeration sırasında queue'yu değiştirmeden veya task göndermeden process, veritabanı dosyası ve service metadata'sını inceleyin.

Zamanlanmış bir job bunun yerine bir uygulama veritabanı yapılandırma satırından komut okuyabilir. Düşük ayrıcalıklı veritabanı rolünün tam olarak o satırı değiştirebildiğini, etkin job'ın değişiklikten sonra bu satırı okuduğunu ve değerin daha yüksek bir OS kimliği altında shell'e veya eşdeğer bir command runner'a ulaştığını doğrulayın. Veritabanına yazma erişimi veya komut gibi görünen bir değer tek başına çalıştırmayı kanıtlamaz; pasif enumeration sırasında satırı değiştirmeden job'ı ve izinleri inceleyin.

Kuyruğa alınmış bir mesaj kod yerine URL de içerebilir. Ayrıcalıklı bir consumer bu URL'yi alıp yanıtı Lua veya başka bir executable plugin olarak yüklüyorsa, publisher'ın tam exchange ve routing key üzerindeki iznini, tüketilen queue'ya olan binding'i, alma ve plugin yükleme yolunu ve worker'ın effective kimliğini doğrulayın. [RabbitMQ, yayımlanan mesajları exchange'ler üzerinden yönlendirir](https://www.rabbitmq.com/docs/exchanges); bir broker listener'ı veya geçerli giriş bilgileri tek başına mesajın bu worker'a ulaşacağını kanıtlamaz. Ele geçirilen açık metin broker kimlik bilgileri, gerçek packet-capture erişimi ve okunabilir trafik gerektiren ayrı bir ipucudur; publish yetkisini kanıtlamaz. Lua plugin'i ancak runtime'ında bu API mevcutsa [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) aracılığıyla shell komutları çalıştırabilir. Pasif enumeration sırasında trafik yakalamadan, mesaj yayımlamadan veya plugin almadan yapılandırmayı ve kodu inceleyin.

Ayrıcalıklı bir Python service yerel bir HTTP veya socket endpoint'i sunuyorsa, okunabilir bir script dosya izinleri nedeniyle değiştirilemiyor olsa bile girdiden koda giden bir yolu açığa çıkarabilir. Çalışan process'in ve unit'in kimliğini tam script, listener, route yetkilendirmesi ve çağıranın kontrol ettiği alanlarla ilişkilendirin. Ardından bu alanları parsing ve validation aşamalarından geçirerek dinamik bir `eval()` veya `exec()` noktasına kadar izleyin. Özellikle request metninden yeni bir f-string oluşturup bunu değerlendirmek, saldırgan tarafından sağlanan replacement field'ların Python expression'ları olarak yorumlanmasına yol açabilir ([Python `eval` uyarısı](https://docs.python.org/3/library/functions.html#eval); [f-string semantiği](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Tek başına `eval` eşleşmesi veya loopback'e bind edilmiş olması, güvenilmeyen bir çağıranın ilgili noktaya ulaştığını kanıtlamaz; enumeration sırasında test payload'ı göndermeden gerçek veri akışını ve erişim kontrollerini inceleyin.

Bu route üzerindeki imzalı request kontrolünün ayrıca incelenmesi gerekir. Okunabilir kaynak kod, imzalama anahtarının açıkça küçük veya tahmin edilebilir bir çıktı alanından türetildiğini gösteriyorsa ve service geçerli imzalı bir örnek sunuyorsa, imza ayrıcalıklı bir `eval()` noktasını artık korumayabilir. Tam anahtar türetme ve doğrulama yöntemini, çalışan service'in kimliğini ve yerel çağıranın erişimini, imzalı alanın ilgili noktaya ulaşıp ulaşmadığını doğrulayın; Python'ın [`random` module'ünün](https://docs.python.org/3/library/random.html) import edilmesi veya örnek bir imza bu koşulların hiçbirini kanıtlamaz. Python ayrıca `__builtins__` öğesini kısıtlamanın, güvenilmeyen `eval()` girdisi için [bir güvenlik sınırı oluşturmadığı](https://docs.python.org/3/library/functions.html#eval) konusunda uyarır. Anahtar analizini çevrimdışı yapın ve pasif enumeration sırasında sahte request göndermeyin.

Boş ancak yazılabilir bir `/etc/systemd/system/<unit>.service.d` dizini, unit dosyası ve mevcut tüm drop-in'ler korumalı olsa bile önemlidir: kullanıcı yeni bir `.conf` override oluşturabilir. Dizin geçerli kimlik tarafından yazılabilir ve aranabilir mi, unit yüklenmiş mi ve root olarak mı çalışıyor, daemon reload ve ardından restart gerçekleşecek mi kontrol edin. Bir reload veya restart izni, timer ya da sonraki boot değişikliği etkili hâle getirebilir; yalnızca dizine yazma erişimi değişikliği hemen çalıştırmaz.

Çalışan service'ler için unit'in `[Service]` bölümündeki `EnvironmentFile=` literal yollarını izleyin; adları `.env` ile başlamayan dosyalar da buna dahildir. Düşük ayrıcalıklı bir kullanıcı bunlardan birini okuyabiliyorsa, değerleri ortak loglara yazdırmadan `API_TOKEN` veya `APP_SECRET_KEY` gibi kimlik bilgilerine benzeyen anahtar adlarını listeleyin. Etkin unit'i değerlendirirken drop-in override'larını ve isteğe bağlı `-` öneklerini kontrol edin. Okunabilirlik, kimlik bilgisi ifşasına işaret eder; ayrıcalık yükseltmek için değerin yine de ayrıcalıklı bir işlemde geçerli olması gerekir.

### Güvenilmeyen upload'ların ayrıcalıklı olarak işlenmesi

Root olarak çalışan bir file watcher, kullanıcı tarafından yazılabilir bir upload dizinindeki dosyaları kısa ömürlü bir parser veya extractor'a iletebilir. Çalışan watcher'ın üst script'ini veya service'ini izleyin; tam dizini, oraya kimlerin dosya koyabildiğini, child komutunu ve argümanlarını ve child'ın hangi kimlikle çalıştığını doğrulayın. Bir process snapshot'ı watcher'ı gösterebilirken upload'lar arasında çalışan extractor'ı kaçırabilir. Pasif enumeration sırasında test payload'ı koymayın veya watcher'ı tetiklemeyin.

Somut bir örnek, Binwalk'ın extraction mode'unun (`-e`) saldırganın kontrol ettiği PFS verisini işlemesidir. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617), PFS extractor'ın plugin yolu da dahil olmak üzere dosyaları hedeflenen dizinin dışına yazmasına olanak sağladı; Binwalk daha sonra bu plugin'i yükleyebilirdi. Upstream düzeltmeyi [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) sürümüne ekledi; ancak dağıtımlar eski görünen bir sürümde backport düzeltmeleri bulundurabilir. Uygulanabilirliğe karar vermeden önce kurulu package'ın güvenlik durumunu [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510) gibi kaynaklardan kontrol edin. Yalnızca Binwalk sürümünün kurulu olması bir privilege-escalation yolunu kanıtlamaz: extraction, düşük ayrıcalıklı kullanıcının kontrol edebildiği bir girdi üzerinde daha ayrıcalıklı bir process tarafından gerçekten çağrılmalıdır.

### Yerel bağımlılıklarla zamanlanmış build'ler

Zamanlanmış bir `cargo run`, kaynak kodunu job'ın run-as kullanıcısı olarak yeniden derler. Yalnızca ana crate'i değil, manifest'teki yerel `{ path = "..." }` bağımlılıklarını ve her bağımlılığın kaynak koduyla üst dizinlerinin izinlerini de inceleyin. Düşük ayrıcalıklı bir kullanıcı Cargo'nun derlediği bir bağımlılığı değiştirebiliyorsa ve zamanlanmış job derlenen sonucu çalıştırıyorsa, derlenen kod o run-as kullanıcısı olarak çalışabilir. Etkin scheduler komutunu, çalışma dizinini, bağımlılık çözümlemesini ve yeniden build gerçekleşip gerçekleşmeyeceğini doğrulayın; başka bir yerde yazılabilir Rust kaynak dosyası yalnızca bir ipucudur. Pasif triage için manifest'i ve yol metadata'sını okumak yeterlidir. [Cargo path dependency belgelerine](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) bakın.

## Xvfb framebuffer dosyaları

`Xvfb -fbdir <directory>`, sanal ekranları için `Xvfb_screen<n>` adlı memory-mapped dosyalar kullanır. Başka bir kullanıcının çalışan Xvfb process'i, ekran dosyaları geçerli kullanıcı tarafından okunabilen bir dizini belirtiyorsa framebuffer o kullanıcının masaüstü içeriğini açığa çıkarabilir. Process'i, dosya sahipliğini ve izinleri birlikte doğrulayın; okunabilir bir dosya tek başına ekranda yararlı içerik olduğunu kanıtlamaz. Görüntü verilerini ortak enumeration çıktısına kopyalamadan önce yolları ve metadata'yı inceleyin. [Xvfb kılavuzu](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) `-fbdir` davranışını açıklar.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` kılavuzu](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` kılavuzu](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` kılavuzu](https://man.openbsd.org/ipcs.1)
4. [Consul agent yapılandırması: script kontrolleri](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent hizmet kaydı API'si](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL yapılandırması](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice yardımı: harici API istemcileri için socket açma](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
