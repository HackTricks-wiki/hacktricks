# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

AppArmor, **programlara program başına profiller aracılığıyla mevcut kaynakları kısıtlamak için tasarlanmış bir çekirdek geliştirmesidir**, erişim kontrol özelliklerini doğrudan programlara bağlayarak Zorunlu Erişim Kontrolü (MAC) uygulamaktadır. Bu sistem, **profilleri çekirdeğe yükleyerek** çalışır, genellikle önyükleme sırasında, ve bu profiller bir programın erişebileceği kaynakları, örneğin ağ bağlantıları, ham soket erişimi ve dosya izinleri gibi, belirler.

AppArmor profilleri için iki çalışma modu vardır:

- **Zorunlu Mod**: Bu mod, profil içinde tanımlanan politikaları aktif olarak uygular, bu politikaları ihlal eden eylemleri engeller ve bunları syslog veya auditd gibi sistemler aracılığıyla kaydeder.
- **Şikayet Modu**: Zorunlu modun aksine, şikayet modu profilin politikalarına aykırı olan eylemleri engellemez. Bunun yerine, bu girişimleri politika ihlali olarak kaydeder ve kısıtlamaları uygulamaz.

### AppArmor Bileşenleri

- **Çekirdek Modülü**: Politikaların uygulanmasından sorumludur.
- **Politikalar**: Program davranışı ve kaynak erişimi için kuralları ve kısıtlamaları belirtir.
- **Ayrıştırıcı**: Politikaları uygulama veya raporlama için çekirdeğe yükler.
- **Araçlar**: AppArmor ile etkileşimde bulunmak ve yönetmek için bir arayüz sağlayan kullanıcı modu programlarıdır.

### Profillerin Yolu

AppArmor profilleri genellikle _**/etc/apparmor.d/**_ dizininde saklanır.\
`sudo aa-status` komutunu kullanarak bazı profiller tarafından kısıtlanan ikili dosyaları listeleyebilirsiniz. Listelenen her ikili dosyanın yolundaki "/" karakterini bir nokta ile değiştirebilir ve belirtilen klasördeki apparmor profilinin adını elde edebilirsiniz.

Örneğin, _/usr/bin/man_ için bir **apparmor** profili _/etc/apparmor.d/usr.bin.man_ konumunda bulunacaktır.

### Komutlar
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Profil Oluşturma

- Etkilenen çalıştırılabilir dosyayı belirtmek için, **mutlak yollar ve joker karakterler** (dosya globbing için) dosyaları belirtmekte kullanılabilir.
- İkili dosyanın **dosyalar** üzerindeki erişimini belirtmek için aşağıdaki **erişim kontrolleri** kullanılabilir:
- **r** (okuma)
- **w** (yazma)
- **m** (bellek haritası olarak çalıştırılabilir)
- **k** (dosya kilitleme)
- **l** (sert bağlantılar oluşturma)
- **ix** (yeni programın miras aldığı politika ile başka bir programı çalıştırmak için)
- **Px** (ortamı temizledikten sonra başka bir profil altında çalıştırmak)
- **Cx** (ortamı temizledikten sonra bir çocuk profil altında çalıştırmak)
- **Ux** (ortamı temizledikten sonra kısıtlanmamış olarak çalıştırmak)
- **Değişkenler** profillerde tanımlanabilir ve profil dışından manipüle edilebilir. Örneğin: @{PROC} ve @{HOME} (profil dosyasına #include \<tunables/global> ekleyin)
- **İzin verme kurallarını geçersiz kılmak için yasaklama kuralları desteklenmektedir**.

### aa-genprof

Profil oluşturmaya başlamak için apparmor size yardımcı olabilir. **Apparmor'un bir ikili dosya tarafından gerçekleştirilen eylemleri incelemesi ve ardından hangi eylemleri izin vermek veya yasaklamak istediğinize karar vermenize olanak tanıması mümkündür**.\
Sadece şunu çalıştırmanız yeterlidir:
```bash
sudo aa-genprof /path/to/binary
```
Daha sonra, farklı bir konsolda ikili dosyanın genellikle gerçekleştireceği tüm eylemleri gerçekleştirin:
```bash
/path/to/binary -a dosomething
```
Sonra, ilk konsolda "**s**" tuşuna basın ve ardından kaydedilen eylemlerde neyi yok saymak, neyi izin vermek veya ne yapacağınızı belirtin. İşlemi bitirdiğinizde "**f**" tuşuna basın ve yeni profil _/etc/apparmor.d/path.to.binary_ içinde oluşturulacaktır.

> [!NOTE]
> Ok tuşlarını kullanarak neyi izin vermek/yok saymak/veya ne yapmak istediğinizi seçebilirsiniz.

### aa-easyprof

Ayrıca, bir ikili dosyanın apparmor profilinin bir şablonunu oluşturabilirsiniz:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
> [!NOTE]
> Oluşturulan bir profilde varsayılan olarak hiçbir şeye izin verilmediğini unutmayın, bu nedenle her şey reddedilir. Örneğin, `/etc/passwd` dosyasının okunmasına izin vermek için `/etc/passwd r,` gibi satırlar eklemeniz gerekecek.

Daha sonra yeni profili **uygulayabilirsiniz**.
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Loglardan bir profili değiştirme

Aşağıdaki araç, logları okuyacak ve kullanıcıdan tespit edilen bazı yasaklı eylemleri izin verip vermek istemediğini soracaktır:
```bash
sudo aa-logprof
```
> [!NOTE]
> Ok tuşlarını kullanarak neyi izin vermek/engellemek/başka bir şey yapmak istediğinizi seçebilirsiniz.

### Bir Profili Yönetmek
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Loglar

Örnek **AUDIT** ve **DENIED** logları _/var/log/audit/audit.log_ dosyasından **`service_bin`** yürütülebilir dosyası için:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Bu bilgiyi şu şekilde de alabilirsiniz:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Docker'da Apparmor

Docker'ın **docker-profile** profilinin varsayılan olarak nasıl yüklendiğine dikkat edin:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Varsayılan olarak **Apparmor docker-default profili** [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) adresinden oluşturulur.

**docker-default profili Özeti**:

- Tüm **ağ** erişimi
- **Hiçbir yetenek** tanımlanmamıştır (Ancak, bazı yetenekler temel temel kuralları dahil etmekten gelecektir, yani #include \<abstractions/base>)
- Herhangi bir **/proc** dosyasına **yazma** **izin verilmez**
- Diğer **alt dizinler**/**dosyalar** için /**proc** ve /**sys** okuma/yazma/kilit/bağlantı/çalıştırma erişimi **reddedilir**
- **Bağlama** **izin verilmez**
- **Ptrace** yalnızca **aynı apparmor profili** tarafından kısıtlanmış bir süreçte çalıştırılabilir

Bir **docker konteyneri çalıştırdığınızda** aşağıdaki çıktıyı görmelisiniz:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Not edin ki **apparmor varsayılan olarak konteynere verilen yetenek ayrıcalıklarını bile engelleyecektir**. Örneğin, **SYS_ADMIN yeteneği verilse bile /proc içinde yazma iznini engelleyebilecektir** çünkü varsayılan olarak docker apparmor profili bu erişimi reddeder:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
AppArmor kısıtlamalarını aşmak için **apparmor'ı devre dışı bırakmalısınız**:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Not edin ki varsayılan olarak **AppArmor**, **SYS_ADMIN** yetkisi ile bile konteynerin içinden klasörleri **monte etmesini** **yasaklayacaktır**.

Not edin ki docker konteynerine **yetkiler** **ekleyebilir/çıkarabilirsiniz** (bu hala **AppArmor** ve **Seccomp** gibi koruma yöntemleri tarafından kısıtlanacaktır):

- `--cap-add=SYS_ADMIN` `SYS_ADMIN` yetkisini ver
- `--cap-add=ALL` tüm yetkileri ver
- `--cap-drop=ALL --cap-add=SYS_PTRACE` tüm yetkileri kaldır ve sadece `SYS_PTRACE` ver

> [!NOTE]
> Genellikle, bir **docker** konteynerinin içinde **yetkili bir yetki** bulduğunuzda **ama** **sömürü** kısmının **çalışmadığını** **bulursanız**, bu, docker'ın **apparmor'unun bunu engelliyor olmasından** kaynaklanacaktır.

### Örnek

(Örnek [**buradan**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/) alınmıştır)

AppArmor işlevselliğini göstermek için, aşağıdaki satırı ekleyerek “mydocker” adında yeni bir Docker profili oluşturdum:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Profili etkinleştirmek için aşağıdakileri yapmamız gerekiyor:
```
sudo apparmor_parser -r -W mydocker
```
Profilleri listelemek için aşağıdaki komutu kullanabiliriz. Aşağıdaki komut, benim yeni AppArmor profilimi listelemektedir.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Aşağıda gösterildiği gibi, “/etc/” dizinini değiştirmeye çalıştığımızda hata alıyoruz çünkü AppArmor profili “/etc” dizinine yazma erişimini engelliyor.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Bir konteynerin hangi **apparmor profilinin çalıştığını** bulmak için:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Sonra, **kullanılan tam profili bulmak için** aşağıdaki satırı çalıştırabilirsiniz:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Garip bir durumda **apparmor docker profilini değiştirebilir ve yeniden yükleyebilirsiniz.** Kısıtlamaları kaldırabilir ve "bypass" edebilirsiniz.

### AppArmor Docker Bypass2

**AppArmor yol tabanlıdır**, bu, bir dizin içindeki dosyaları **koruyor** olsa bile, eğer **konteynerin nasıl çalıştırılacağını yapılandırabiliyorsanız**, ana bilgisayarın proc dizinini **`/host/proc`** içine **mount** edebilir ve artık **AppArmor tarafından korunmayacaktır**.

### AppArmor Shebang Bypass

[**bu hata**](https://bugs.launchpad.net/apparmor/+bug/1911431) ile **belirli kaynaklarla perl'in çalıştırılmasını engelliyorsanız**, eğer sadece ilk satırda **`#!/usr/bin/perl`** belirten bir shell script oluşturursanız ve dosyayı doğrudan **çalıştırırsanız**, istediğiniz her şeyi çalıştırabileceksiniz. Örnek:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
