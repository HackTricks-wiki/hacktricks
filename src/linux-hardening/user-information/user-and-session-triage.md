# Kullanıcılar, Oturumlar ve Kimlik Bilgisi Artefaktları

{{#include ../../banners/hacktricks-training.md}}

Önce mevcut shell'in sahibi olan kimlikle başlayın, ardından diğer kullanıcıları, grupları, etkin oturumları ve kimlik bilgisi depolarını listeleyin. [Gerçek, etkin ve kaydedilmiş kullanıcı kimliği](euid-ruid-suid.md) sayfasında, bir işlemin etkin ayrıcalıklarının neden oturum açma hesabından farklı olabileceği açıklanır.

## Kimlikleri ve grup tabanlı erişimi listeleyin

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent`, yalnızca `/etc/passwd` dosyasını okuyarak gözden kaçabilecek dizin tabanlı hesapları da içerir. UID 0 hesaplarını, login shell'lerini, home dizinlerini, ek grupları ve yapılandırması beklenmedik şekilde etkileşimli login'e izin veren hesapları inceleyin. [İlgi çekici gruplar](interesting-groups-linux-pe/README.md) sayfasında `sudo`, `docker`, `disk` ve `shadow` gibi devredilmiş erişimler ele alınır. Bir grup adını ayrıcalık olarak değerlendirmeden önce gerçek dosya sistemi ACL'lerini ve yerel politikayı kontrol edin.

NSS, [`passwd`, `group` veya `shadow` sorgularını](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) bir veritabanına yönlendiriyorsa, veritabanı tabanlı kimlikleri değerlendirmeden önce etkin sağlayıcıyı ve yapılandırma yolunu inceleyin. PostgreSQL NSS kurulumlarında `/etc/nss-pgsql.conf` ve `/etc/nss-pgsql-root.conf` yalnızca yol ipuçlarıdır; bağlantı ayarları kimlik bilgileri içerebilir. Bir veritabanı rolü, ancak etkin NSS sağlayıcısının gerçekten döndürdüğü kayıtları değiştirebiliyorsa ve bir hesap bu kayıtlarla kimlik doğrulayabiliyorsa önem taşır. Birincil GID'nin 0 olması, UID 0 değil, root grubuna üyelik sağlar; sudo grubu eşlemesi, etkin bir [sudoers grup kuralı](https://man7.org/linux/man-pages/man5/sudoers.5.html) ve gereken kimlik doğrulamayı gerektirir. UID 0 eşlemesi ise farklı bir kimlik sınırıdır. Pasif envanter çıkarma sırasında bağlantı dizelerini yazdırmayın veya hesap kayıtlarını değiştirmeyin.

Yerel hesap adları arasındaki sayısal UID'leri de karşılaştırın. [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) içindeki iki ad aynı Unix dosya kimliğine karşılık gelebilirken, bu adların login kimlik doğrulama kayıtları farklı olabilir. Bu nedenle, paylaşılan sıfır olmayan bir UID'ye sahip yeni eklenmiş bir alias, başarılı kimlik doğrulamanın ardından başka bir kullanıcının dosyalarına veya süreçlerine erişim sağlayabilir; bu, UID 0 veya ayrı bir ayrıcalık yolu olmadıkça root yetkisi vermez. Paylaşılan UID'ler kasıtlı olabilir. Hesap kaynağını (`/etc/passwd` veya NSS), oluşturulma geçmişini, shell ve home dizinini, gerçek kimlik doğrulama politikasını ve hesapların bu kimliği paylaşma yetkisi olup olmadığını doğrulayın. Yalnızca yerel hesapları kontrol etmek, dizin tabanlı bir alias olmadığını kanıtlamaz.

## Etkin ve yakın tarihli oturumları bulun

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Bir `screen` veya `tmux` soketi, izinleri mevcut kullanıcının bağlanmasına olanak tanıyorsa mevcut bir kabuğu açığa çıkarabilir. Erişmeyi denemeden önce sahibini ve soket modunu kontrol edin; başka bir kullanıcının oturumuna otomatik olarak bağlanılamaz. Etkin bir sudo zaman damgası veya SSH agent soketi de önemli olabilir, ancak bunların yeniden kullanımı kullanıcı kimliğine, izinlere ve ilkelere bağlıdır. Agent forwarding'in kötüye kullanımı için bkz. [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Bir [OpenSSH multiplex kontrol soketi](https://man.openbsd.org/ssh_config#ControlMaster), `SSH_AUTH_SOCK`'tan ayrıdır: `ControlMaster` ve `ControlPath`, sonraki SSH istemcilerinin kimliği doğrulanmış mevcut bir bağlantıyı paylaşmasını sağlarken `ControlPersist`, ilk oturum sona erdikten sonra master'ın kullanılabilir kalmasını sağlayabilir. Mevcut kullanıcının `.ssh/config` dosyasını ve `.ssh` altındaki sığ düzeydeki soket yollarını; sahiplerini ve izinlerini de kontrol edin. Tek başına bir soket dosyası adı, master'ın etkin olduğunu, mevcut kullanıcının bağlanabileceğini veya hangi uzak hesabı kullandığını kanıtlamaz.

## Kullanıcı artefaktlarını inceleyin

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell geçmişi, başlangıç dosyaları, SSH anahtarları, uygulama yapılandırması, GPG anahtarlıkları ve Kerberos önbellekleri kimlik bilgilerini veya yazılabilir kalıcılık noktalarını açığa çıkarabilir. Daha ayrıcalıklı bir hesaba ait yazılabilir bir `authorized_keys` dosyası veya kabuk başlangıç dosyası incelenmelidir. [Post-exploitation sayfası](../post-exploitation/README.md) GPG ana dizininin taşınmasını ve kimlik bilgisi aramayı ele alır; [Linux Active Directory](linux-active-directory.md), Kerberos önbelleğinin ve keytab'lerin yeniden kullanımını ele alır. [PAM sayfası](../software-information/pam-pluggable-authentication-modules.md) kimlik doğrulama politikası risklerini açıklar.
{{#include ../../banners/hacktricks-training.md}}
