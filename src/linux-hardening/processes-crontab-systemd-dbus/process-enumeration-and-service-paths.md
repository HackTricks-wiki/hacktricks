# Process Enumeration and Service Paths

{{#include ../../banners/hacktricks-training.md}}

Sorulması gereken faydalı soru, ayrıcalığı daha düşük bir kullanıcının etkileyebileceği verileri veya kodu hangi ayrıcalıklı sürecin kullandığıdır. Süreç ağacını, canlı ortamı, açık dosyaları ve her aday süreci başlatan unit veya script'i inceleyin.

## Süreçleri ve sahipliği haritalandırın

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Farklı kullanıcılar arasındaki üst süreç-alt süreç ilişkisi normal olabilir; ancak beklenmeyen bir geçiş, üst sürecin komutunun, argümanlarının, yürütülebilir dosyasının, çalışma dizininin ve başvurulan dosyaların incelenmesini gerektirir. Sürecin sahibini ve oturum açma bağlamını yorumlamak için [kullanıcılar ve oturumlar](../user-information/user-and-session-triage.md) bölümünü kullanın.

### Yerel sanal makine konsolları

Bir QEMU sürecinin `-spice` seçeneklerini dinleme adresiyle birlikte inceleyin. [QEMU belgelerine](https://www.qemu.org/docs/master/system/qemu-manpage.html) göre `disable-ticketing`, SPICE istemcilerinin kimlik doğrulaması olmadan bağlanmasına olanak tanır. Loopback adresine bağlı bir dinleyiciye bile diğer yerel ana bilgisayar kullanıcıları erişebilir. Komut satırını açık bir konsol olarak değerlendirmeden önce etkin dinleyiciyi, kimlik doğrulama seçeneklerini ve yerel erişimi doğrulayın. Konsolun kontrolü **konuğu** etkiler; konuk hesabı edinmek veya önyükleme durumunu değiştirmek ayrı konuk tarafı koşullarını gerektirir ve sanallaştırma ana bilgisayarında root yetkisi sağlamaz. Pasif numaralandırma sırasında konuğa bağlanmadan veya konuğu yeniden başlatmadan süreç argümanlarını ve soket meta verilerini okuyun.

Yerel olarak erişilebilen bir web arayüzü, ilk kabuğun hizmet hesabı dosyalarına erişemediği durumlarda bile bu hesapla kod çalıştırabilir. Örneğin, CVE-2023-0297, güvenilmeyen JavaScript'in Python içe aktarımları etkin durumdayken Js2Py'ye ulaştığı pyLoad'un `/flash/addcrypted2` işleme biçimini etkiliyordu; [upstream düzeltmesi](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) `pyimport` özelliğini devre dışı bıraktı. Bir pyLoad sürecini ayrıcalık yükseltme yolu olarak değerlendirmeden önce çalışan sürecin sahibini, dinleme adresini, endpoint'in erişilebilirliğini ve kurulu düzeltme ya da tedarikçi backport'unu karşılaştırın. Süreç adı, açık port veya paket sürümü tek başına erişilebilirliği kanıtlamaz; pasif numaralandırma sırasında kod çalıştırma payload'ı göndermeyin.

### Terminal paylaşan ayrıcalıklı oturum açma kabukları

Bağımsız bir pseudo-terminal olmadan `su --login <user>` çalıştıran ayrıcalıklı etkileşimli bir kabuk, terminalini daha düşük ayrıcalıklı oturum açma kabuğuyla paylaşabilir. Bu kullanıcının başlangıç dosyası denetlenebiliyorsa ve dosyadaki kod terminal girdisi enjekte etmek için `TIOCSTI` kullanabiliyorsa, ayrıcalıklı kabuk yeniden etkin olduğunda bu girdi ona ulaşabilir. [util-linux `su` kılavuzu](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES), paylaşılan terminal riskini açıklar ve etkileşimli kullanımda `su --pty`/`-P` seçeneklerini önerir; `su -c`, kontrol terminali olmayan ayrı bir oturum başlatır. Riskin geçerli olması için gerçek üst kabuğun, terminal ilişkisinin, hedef başlangıç dosyasının ve çekirdek politikasının bu koşulları karşılaması gerekir. Yalnızca süreç adı veya `su -l` argümanı, inceleme için bir ipucudur.

Gözlemlenen süreç ağacını ve TTY sütunlarını, ardından okunabilir başlatıcıyı ve başlangıç dosyasının sahiplik/izinlerini inceleyin. Linux'ta `/proc/sys/dev/tty/legacy_tiocsti` mevcutsa politika hakkında bilgi sağlayabilir; dosyanın bulunmaması güvenli olunduğunu kanıtlamaz. [Linux `TIOCSTI` kılavuzu](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html), Linux 6.2'den itibaren bu sysctl false olduğunda işlemin `CAP_SYS_ADMIN` gerektirebileceğini belirtir. Ana bilgisayarı numaralandırmak için ioctl'ı çağırmayın.

Bir veritabanı hesabı bazen hedef kullanıcının başlangıç dosyasını doğrudan dosya sistemi yazma erişimi olmadan değiştirebilir. PostgreSQL sunucu tarafındaki `COPY ... TO 'filename'`, dosyayı veritabanı sunucusunun işletim sistemi hesabıyla yazar; ancak [PostgreSQL kısıtlamalarına](https://www.postgresql.org/docs/current/sql-copy.html) göre bu dosya biçimini yalnızca veritabanı süper kullanıcıları veya `pg_write_server_files` gibi rollere sahip kullanıcılar kullanabilir. Hem veritabanı rolünü hem de sunucu işletim sistemi dosya izinlerini doğrulayın; uygulama bağlantı dizesi tek başına dosya yazma yetkisi vermez. Zinciri değerlendirirken ayrıcalıklı başlatıcıyla veritabanı hesabının yeteneklerini birbirinden ayrı ele alın.

## Çalışma zamanı yapıtlarını inceleyin

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Silinmiş executable'lar ve silinmiş ancak açık dosyalar, son descriptor'ları kapanana kadar referans edilmeye devam eder. Bunlar kanıtları veya erişilebilir sırları koruyabilir. Process ortamları ve belleği kimlik bilgileri içerebilir; ancak başka bir process'i okumak, sahiplik, `/proc` mount seçenekleri, Yama ptrace ilkesi ve diğer güvenlik denetimleriyle kısıtlanır. İlgili teknikler için [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) ve [post-exploitation credential hunting](../post-exploitation/README.md) sayfalarına bakın.

Kaydedilmiş syscall trace'leri de başka bir dosya izni sınırıdır. [`strace`, syscall argümanlarını bir çıktı dosyasına kaydeder](https://man7.org/linux/man-pages/man1/strace.1.html); bu nedenle [`execve` argümanlarını](https://man7.org/linux/man-pages/man2/execve.2.html) içeren okunabilir bir trace, ayrıcalıklı bir işin komut satırında aktardığı parolayı açığa çıkarabilir. Öncelikle mevcut kullanıcının söz konusu trace'i okuyabildiğini ve argümanın gerçekten bir kimlik bilgisi içerdiğini doğrulayın; daha sonra Unix hesabı geçişi için bu kimlik bilgisinin orada kabul edildiğini ayrıca kanıtlamak gerekir. Dosya meta verileri, rutin enumerasyon sırasında her trace'i taramadan veya içeriğini yazdırmadan yararlanılabilecek pasif bir ipucudur.

## Ayrıcalıklı ofis otomasyonu soketleri

LibreOffice ve OpenOffice, UNO API'lerini `--accept=socket,host=<host>,port=<port>;urp;` argümanı üzerinden sunabilir. Erişilebilir bir endpoint'i olan root sahipli bir ofis process'i, daha düşük ayrıcalıklı yerel bir kullanıcının o process'in güvenlik bağlamında API servislerini çağırmasına olanak tanıyabilir. `SystemShellExecute` servisi, bir sistem komutu başlatma işlemi içerir. Loopback'e bağlanmak uzaktan erişimi sınırlar; ancak başka bir denetim erişimi engellemediği sürece soket yerel kullanıcılar tarafından erişilebilir durumda kalır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Süreç sahibini, tam `--accept` argümanını ve o anki dinleme adresi ile portu ilişkilendirin. Bağlama işlemi başarısız olan yapılandırılmış bir acceptor yalnızca bir ipucudur; pasif numaralandırma sırasında API'ye bağlanmayın veya API'yi çağırmayın. Sırf bu durumu test etmek için ayrıcalıklı bir office örneği başlatmaktan kaçının.

## Ayrıcalıklı süreçlerin kullandığı System V paylaşımlı bellek

Root sahipli bir yardımcı program, başka bir kullanıcının yazabileceği bir System V paylaşımlı bellek segmenti oluşturabilir. Yardımcı program daha sonra bu segmentteki verilere bir shell komutunda veya başka bir hassas işlemde güvenirse, yürütülebilir dosya ve dosyaları korumalı olsa bile segment bir ayrıcalık sınırını aşar. `shmget()` erişim izinlerini bayraklarının düşük dokuz bitinden alır; `0666` modu diğer kullanıcıların yazmasına izin verirken, `IPC_CREAT` bayrağı bu izinleri daraltmaz. Etkin segmentleri `ipcs -m` ile pasif olarak inceleyin ve sahiplerini, modlarını ve kullanım ömürlerini ayrıcalıklı süreç ve girdi işleme biçimiyle ilişkilendirin. Herkese açık yazma izni olan bir segment tek başına komut yürütme kanıtı değildir.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmentleri, `/dev/shm` altındaki POSIX paylaşımlı bellek dosyalarından farklıdır. Yalnızca kısa süreliğine oluşturulan bir segment, tek bir `ipcs` anlık görüntüsünde görünmeyebilir; bu nedenle boş çıktı, paylaşımlı bellek kullanan bir yardımcı programı aklamaz. Kaynağını veya ikili dosyanın davranışını ve onu başlatan `sudo` kuralını inceleyin; numaralandırma sırasında segment oluşturmak için ayrıcalıklı yardımcı programı çalıştırmayın. [IPC namespace kılavuzu](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md), namespace’lerin görünürlüğü nasıl etkilediğini açıklar.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script kontrolleri

Consul, işletim sisteminde agent’ın kimliğiyle script sağlık kontrolleri çalıştırabilir. Bir agent root olarak çalışıyorsa, `enable_script_checks` etkinse ve daha düşük ayrıcalıklı bir kullanıcının yerel HTTP API üzerinden script kontrolü içeren bir servis kaydetmesine izin veriyorsa, bu kullanıcı root olarak çalışan komutlar çalıştırabilir. API’yi yalnızca `127.0.0.1` adresine bağlamak, yerel kullanıcıların API’ye erişmesini engellemez. `enable_local_script_checks` ayarı daha kısıtlayıcıdır: HTTP API kayıtları üzerinden gönderilen script kontrollerini hariç tutar. Consul ACL’leri etkin olduğunda servis kaydı için `service:write` gerekir; tek başına `acl.default_policy=allow` satırı, anonim bir çağıranın kayıt yapabildiğini kanıtlamaz. Agent’ın kimliğini, yüklenen ayarları, API bağlamasını ve yetkilendirmeyi birlikte inceleyin.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Çalışan agent'ın `-config-dir` ve `-config-file` argümanlarını izleyerek ilgili yapılandırmayı bulun ve yalnızca script-check ile ACL alan adlarını ve ayarlarını inceleyin. Yapılandırma dosyalarında gossip anahtarları veya token'lar da bulunabilir; bunları paylaşılan loglara yapıştırmaktan kaçının. Bu durumu yalnızca listelemek için bir service kaydetmeyin veya health check çalıştırmayın.

Daha düşük ayrıcalıklı bir kullanıcı, root olarak çalışan agent'ın `-config-dir` ile belirttiği dizine **yazma ve dizinde arama** iznine sahipse ayrı bir yerel dosya yolu vardır: bu dizine yeni bir `.hcl` veya `.json` service tanımı eklenebilir. Dizin içeriğini listeleme izni olmasa bile, dizinde arama ve yazma izinleri dosya eklemeye olanak sağlayabilir. Root olarak komut çalıştırılabildiğini doğrulamak için agent'ın gerçekten bu dizini yüklediğini, etkin script-check ayarının yerel tanımlara izin verdiğini, tanımın yüklendiğini ve agent'ın root ayrıcalıklarını koruduğunu teyit edin. [Consul belgeleri](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations), hangi ayarların ve health check tanımlarının yeniden yüklenebileceğini açıklar; script check'lerini etkinleştirmek için yeniden başlatma gerekebilir, bu nedenle kurulu sürümün davranışını doğrulayın. ACL'ler agent'ı koruyorsa, [`consul reload` için `agent:write` gerekir](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); yalnızca KV yazma izni bu yetkiyi sağlamaz. Yazılabilir dizin meta verilerini, yetkili bir yeniden yüklemenin, yeniden başlatmanın veya komut çalıştırmanın kanıtı olarak değil, inceleme işareti olarak değerlendirin. Yapılandırma yazmadan veya API'yi çağırmadan yolları, izinleri ve politikayı inceleyin.

## Service yürütme zincirini izleyin

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Servisi, drop-in'leri, `EnvironmentFile=`, helper script'leri, göreli komutları, yazılabilir dizinleri ve socket activation'ı kontrol edin. Root-owned bir unit, kullanıcı tarafından yazılabilir bir config veya script okursa yine de güvenli olmayabilir. [arbitrary file write](../interesting-files-permissions/write-to-root.md) sayfasında yaygın service ve unit abuse yolları ele alınır. Tek seferlik `ps` listelemesi kısa ömürlü işleri kaçırıyorsa bunları [pspy](https://github.com/DominicBreuker/pspy) veya audit/process telemetry ile izleyin.

Özel bir **xinetd** servisi için etkin stanza'daki `server`, `user` ve access control ayarlarını çalışan listener ve tam executable ile ilişkilendirin. [`user` ayarı](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) başlatılan process'in kimliğini belirlerken executable üzerindeki set-user-ID biti, [`execve` bu geçişe izin veriyorsa](https://man7.org/linux/man-pages/man2/execve.2.html) etkin kimliğini ayrıca değiştirebilir. Güvenilmeyen girdi kabul eden ve erişilebilen ayrıcalıklı bir binary, sabit boyutlu bir buffer'a sınırlandırılmamış [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) gibi memory-safety hataları açısından kaynak kodunun çevrimdışı incelenmesini veya disassembly incelemesini gerektirir. Service mapping ve set-user-ID metadata'sı, böyle bir hatanın kanıtı değil, inceleme ipuçlarıdır; pasif enumeration sırasında crash girdileri göndermeyin veya çalışan ayrıcalıklı servisi debug etmeyin.

Kaynak kodu okunabilen özel bir ayrıcalıklı listener için [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) gibi bir kopyalama işleminin kullandığı, çağıran tarafından kontrol edilen her uzunluğu inceleyin. Yalnızca geçerli yazma indeksinin sabit bir buffer içinde olduğunu kontrol etmek, **kopyalama uzunluğunun** kalan alana sığdığını göstermez; indeksin aralık içinde olduğunu doğruladıktan sonra `copy_length <= capacity - index` koşulunu doğrulayın, ayrıca işaretliliği ve aritmetik taşmayı kontrol edin. Bu yalnızca girdi söz konusu işleme ulaşıyorsa, düşük ayrıcalıklı kullanıcı listener'a erişebiliyorsa ve process daha yüksek bir etkin kimliği koruyorsa bir inceleme ipucudur. Kaynak kodunu ve process metadata'sını çevrimdışı inceleyin; enumeration sırasında çalışan servise crash girdileri göndermeyin.

**Upstart** kullanan sistemlerde system job tanımları `/etc/init/*.conf` altında bulunabilir. Mevcut kullanıcının yazabildiği bir job dosyası, yalnızca etkin init daemon tam olarak o job'ı yüklüyorsa, `script` veya `exec` stanza'sı daha yüksek ayrıcalıklı bir kimlikle çalışıyorsa ve kullanıcı bu job'ı izin verilen bir `initctl` komutu veya başka bir gerçek tetikleyiciyle başlatabiliyorsa önem taşır. Tek başına bir sudo `initctl` izni, herhangi bir job dosyasının yazılabilir olduğunu veya değiştirilmiş bir job'ın çalışacağını kanıtlamaz. Enumeration sırasında job'ı düzenlemeden veya başlatmadan tam job dosyasının izinlerini, etkin run-as ayarını, etkin daemon'ı ve tetikleyiciyi kontrol edin. [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) ve [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) kılavuzlarına bakın.

Örneğin, [boot job'ın tam olarak bu yolu okuduğu](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf) sistemlerde `/etc/autologin/passwd` gibi okunabilir bir autologin password file, kimlik bilgilerinin açığa çıkabileceğine dair bir ipucudur. Boot job'ın yüklü olduğunu ve bu dosyayı kullandığını doğrulayın, ardından parolanın başka bir yerel hesap veya servis için geçerli olup olmadığını ayrıca kontrol edin. Yalnızca dosya adı, parolanın tekrar kullanıldığını kanıtlamaz; parolayı paylaşılan enumeration çıktısına koymadan yolu ve erişim metadata'sını kaydedin.

Bir unit'in `ExecStart=` satırı veya zamanlanmış bir komut, listelenemeyen bir dizinin içindeki script'in tam yolunu gösterebilir. [Directory search permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html), mevcut kimliğin bilinen bu yolda ilerlemesine yine de izin verebilir; dizin listesinin alınamamasının dosyayı koruduğunu varsaymak yerine her üst dizinde search iznini ve dosyada read iznini doğrulayın. Okunabilir bir script transfer credential'ı içerebilir, ancak başka bir hesaba geçiş için bu credential'ın hâlâ geçerli olması ve o hesap tarafından ayrıca kabul edilmesi gerekir. Gizli değerleri paylaşılan loglara yazdırmadan yolu ve izin kanıtlarını kaydedin.

Zamanlanmış bir CommonJS Node.js script'inde, script'in kendisi salt okunur olsa bile `require('package')` gibi bare import'ları inceleyin. [Node, önce import eden dosyanın yanındaki ve sonra üst dizinlerindeki `node_modules` dizinlerinde arama yapar](https://nodejs.org/api/modules.html#loading-from-node_modules-folders); ardından yapılandırılmış global yollara başvurur. Bu üst dizinlerden birine **yazma ve arama** izni olan düşük ayrıcalıklı bir kullanıcı, daha önce eşleşecek bir package oluşturabilir. Tam import'un kullanıldığını, seçilen package'ın yerleşik bir module olmadığını, ilgili yolun oluşturulabildiğini veya değiştirilebildiğini, kurulu runtime'da module'ün oradan çözümlendiğini ve daha yüksek ayrıcalıklı job'ın sonraki çalıştırmada onu yükleyeceğini doğrulayın. Yazılabilir üst dizin metadata'sı yalnızca bir inceleme ipucudur; module yerleştirmeden veya job'ı tetiklemeden script'i ve scheduler'ı pasif biçimde inceleyin.

Özel bir Python package index, otomatik bir job farklı bir OS kimliği altında package yüklediğinde başka bir trust boundary oluşturur. Tam job'ı ve run-as hesabını; yapılandırılmış index'i, seçilen package adlarını ve düşük ayrıcalıklı bir kullanıcının job'ın gerçekten yükleyeceği bir package'ı yayımlayıp yayımlayamayacağını veya değiştirebilip değiştiremeyeceğini ilişkilendirin. Bir source distribution oluşturmak, build backend'ini veya eski `setup.py` dosyasını yükleyicinin kimliği altında çalıştırabilir; kurulu package'ı import etmek ise ayrı bir execution path'tir. Bir index listener'ı, okunabilir upload password hash'i veya package dosya adı tek başına bu zinciri kanıtlamaz. Enumeration sırasında herhangi bir şey yüklemeden veya kurmadan job'ı, index yetkilendirmesini ve package provenance'ını inceleyin. [pip'in build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) ve [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/) belgelerine bakın.

Ayrı bir web service veya container tarafından yönetilen task queue'yu ayrıcalıklı bir agent düzenli olarak kontrol ediyor olabilir. Düşük güven düzeyindeki bir kimlik service'in task database'ine yazabiliyorsa, bu kayıtların gerçekten agent'a sunulup sunulmadığını ve bir command task'ın agent'ın OS kimliğiyle çalışıp çalışmadığını belirleyin. Database yazma erişimini, hedef session veya routing key'i, aktif polling'i, task yetkilendirmesini ve agent'ın etkin kullanıcısını ayrı ayrı doğrulayın. Container içindeki root, tek başına host-root erişimi anlamına gelmez; sınır ancak host-privileged bir consumer saldırganın kontrolündeki task verisini çalıştırırsa aşılır. Enumeration sırasında queue'yu değiştirmeden veya task göndermeden process, database file ve service metadata'sını inceleyin.

Zamanlanmış bir job bunun yerine bir application database config satırından komut okuyabilir. Düşük ayrıcalıklı database rolünün tam olarak bu satırı değiştirebildiğini, etkin job'ın değişiklikten sonra satırı okuduğunu ve değerin daha yüksek bir OS kimliği altında shell'e veya eşdeğer bir command runner'a ulaştığını doğrulayın. Database yazma erişimi veya komut gibi görünen bir değer tek başına çalıştırılacağını kanıtlamaz; pasif enumeration sırasında satırı değiştirmeden job'ı ve izinleri inceleyin.

Sıraya alınmış bir mesaj kod yerine URL de içerebilir. Ayrıcalıklı bir consumer bu URL'yi getirip yanıtı Lua veya başka bir executable plugin olarak yüklüyorsa, yayıncının tam exchange ve routing key üzerindeki iznini, tüketilen queue'ya olan binding'i, fetch ve plugin-load yolunu ve worker'ın etkin kimliğini doğrulayın. [RabbitMQ, yayımlanan mesajları exchange'ler üzerinden yönlendirir](https://www.rabbitmq.com/docs/exchanges); bir broker listener'ı veya geçerli login, tek başına mesajın bu worker'a iletildiğini kanıtlamaz. Yakalanmış cleartext broker credential'ları, gerçek packet-capture erişimi ve okunabilir trafik gerektiren ayrı bir ipucudur; publish yetkisini kanıtlamaz. Lua plugin'i [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) üzerinden shell komutları çalıştırabilir, ancak yalnızca bu API runtime'ında mevcutsa. Pasif enumeration sırasında trafik yakalamadan, mesaj yayımlamadan veya plugin getirmeden config'i ve kodu inceleyin.

Ayrıcalıklı bir Python service yerel HTTP veya socket endpoint'i sunuyorsa, okunabilir bir script dosya izinleri nedeniyle değiştirilemiyor olsa bile girdiden koda giden bir yol gösterebilir. Etkin process ve unit kimliğini; tam script, listener, route yetkilendirmesi ve çağıran tarafından kontrol edilen alanlarla ilişkilendirin. Ardından bu alanları parsing ve validation adımlarından geçirerek dinamik bir `eval()` veya `exec()` sink'ine kadar izleyin. Özellikle request metninden yeni bir f-string oluşturup değerlendirmek, saldırganın sağladığı replacement field'ları Python expression'ları olarak yorumlayabilir ([Python `eval` warning](https://docs.python.org/3/library/functions.html#eval); [f-string semantics](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Tek başına bir `eval` eşleşmesi veya loopback binding, güvenilmeyen bir çağıranın sink'e ulaştığını kanıtlamaz; enumeration sırasında test payload'ı göndermeden gerçek dataflow'u ve access control'leri inceleyin.

Bu route üzerindeki signed-request gate ayrıca incelenmelidir. Okunabilir kaynak kod, imzalama anahtarının belirgin biçimde küçük veya tahmin edilebilir bir çıktı uzayından türetildiğini gösteriyorsa ve service geçerli bir imzalı örnek sunuyorsa, imza ayrıcalıklı bir `eval()` sink'ini artık korumayabilir. Tam key derivation ve verifier'ı, çalışan service'in kimliğini ve yerel çağıran erişimini, imzalanmış alanın sink'e ulaşıp ulaşmadığını doğrulayın; Python'ın [`random` module](https://docs.python.org/3/library/random.html) import edilmesi veya tek başına bir örnek imza bu koşullardan hiçbirini kanıtlamaz. Python ayrıca `__builtins__`'i kısıtlamanın güvenilmeyen `eval()` girdisine karşı [bir güvenlik sınırı olmadığını](https://docs.python.org/3/library/functions.html#eval) belirtir. Key analizini çevrimdışı yapın ve pasif enumeration sırasında sahte request'ler göndermeyin.

Boş ama yazılabilir bir `/etc/systemd/system/<unit>.service.d` dizini, unit dosyası ve mevcut tüm drop-in'ler korunsa bile önem taşır: kullanıcı yeni bir `.conf` override oluşturabilir. Dizin için mevcut kimliğin yazma ve arama izinlerini, unit'in yüklü olup root olarak çalıştığını ve daemon reload'un ardından restart olup olmayacağını kontrol edin. Bir reload veya restart izni, timer ya da sonraki boot değişikliği etkinleştirebilir; dizine yazma erişimi tek başına değişikliği hemen çalıştırmaz.

Çalışan servislerde, unit'in `[Service]` bölümündeki literal `EnvironmentFile=` yollarını izleyin; adı `.env` ile başlamayan dosyalar da buna dahildir. Düşük ayrıcalıklı bir kullanıcı bunlardan birini okuyabiliyorsa, değerleri paylaşılan loglara yazdırmadan `API_TOKEN` veya `APP_SECRET_KEY` gibi credential'ı çağrıştıran key adlarını listeleyin. Etkin unit'i değerlendirirken drop-in override'ları ve isteğe bağlı `-` öneklerini kontrol edin. Dosyanın okunabilir olması, kimlik bilgilerinin açığa çıkabileceğine dair bir ipucudur; ayrıcalık yükseltme için değerin ayrıcalıklı bir işlemde hâlâ geçerli olması gerekir.

### Güvenilmeyen upload'ların ayrıcalıklı işlenmesi

Root olarak çalışan bir file watcher, kullanıcı tarafından yazılabilir bir upload dizinindeki dosyaları kısa ömürlü bir parser veya extractor'a aktarabilir. Çalışan watcher'ın üst script'ini veya service'ini izleyin ve tam dizini, dosyaları kimin oraya koyabildiğini, child command'i ve argümanlarını ve child'ın hangi kimlikle çalıştığını doğrulayın. Process snapshot'ı, watcher'ı gösterirken upload'lar arasındaki extractor'ı kaçırabilir. Pasif enumeration sırasında test payload'ı yerleştirmeyin veya watcher'ı tetiklemeyin.

Somut bir örnek, Binwalk'ın extraction mode'unun (`-e`) saldırganın kontrolündeki PFS verisini işlemesidir. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617), PFS extractor'ın amaçlanan dizinin dışına, Binwalk'ın daha sonra yükleyebileceği bir plugin yoluna bile yazmasına olanak tanıyordu. Upstream düzeltmeyi [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) sürümüne ekledi; ancak dağıtım backport'ları ekranda görünen daha eski bir sürümü koruyabilir. Uygulanabilirliğe karar vermeden önce kurulu package'ın güvenlik durumunu, örneğin [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510) üzerinden kontrol edin. Yalnızca Binwalk'ın kurulu olması, bir privilege-escalation yolu olduğunu kanıtlamaz: extraction, düşük ayrıcalıklı kullanıcının kontrol edebildiği girdi üzerinde daha ayrıcalıklı bir process tarafından gerçekten çağrılmalıdır.

### Yerel dependency kullanan zamanlanmış build'ler

Zamanlanmış bir `cargo run`, kaynak kodunu job'ın run-as kullanıcısı olarak yeniden derler. Yalnızca ana crate'i değil, manifest'teki yerel `{ path = "..." }` dependency'lerini ve her dependency'nin kaynak kodu ile üst dizin izinlerini inceleyin. Düşük ayrıcalıklı bir kullanıcı Cargo'nun derlediği bir dependency'yi değiştirebiliyorsa ve zamanlanmış job derleme sonucunu çalıştırıyorsa, derlenen kod o run-as kullanıcısı olarak çalışabilir. Etkin scheduler komutunu, çalışma dizinini, dependency çözümlemesini ve yeniden derleme yapılıp yapılmayacağını doğrulayın; başka bir yerdeki yazılabilir Rust kaynak dosyası yalnızca bir ipucudur. Pasif triage için manifest'i ve yol metadata'sını okumak yeterlidir. [Cargo path-dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) sayfasına bakın.

## Xvfb framebuffer dosyaları

`Xvfb -fbdir <directory>`, sanal ekranları için `Xvfb_screen<n>` adlı memory-mapped dosyalar kullanır. Başka bir kullanıcının çalışan Xvfb process'i, ekran dosyaları mevcut kullanıcı tarafından okunabilen bir dizini belirtiyorsa framebuffer, o kullanıcının masaüstü içeriğini açığa çıkarabilir. Process'i, dosya sahipliğini ve izinlerini birlikte doğrulayın; tek başına okunabilir bir dosya ekranda işe yarar içerik olduğunu kanıtlamaz. Görüntü verisini paylaşılan enumeration çıktısına kopyalamadan önce yolları ve metadata'yı inceleyin. [Xvfb manual](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html), `-fbdir` davranışını açıklar.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` kılavuzu](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` kılavuzu](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` kılavuzu](https://man.openbsd.org/ipcs.1)
4. [Consul agent yapılandırması: script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent hizmet kaydı API'si](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL yapılandırması](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice yardımı: harici API istemcileri için socket açma](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
