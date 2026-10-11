# Kullanıcılar, Oturumlar ve Kimlik Bilgisi Yapıtları

{{#include ../../banners/hacktricks-training.md}}

Önce mevcut shell’i kullanan kimliği belirleyin; ardından diğer kullanıcıları, grupları, etkin oturumları ve kimlik bilgisi depolarını listeleyin. [Gerçek, etkin ve kaydedilmiş kullanıcı kimliği](euid-ruid-suid.md) sayfası, bir sürecin etkin ayrıcalıklarının neden oturum açma hesabından farklı olabileceğini açıklar.

## Kimlikleri ve grup tabanlı erişimi listeleme

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent`, `/etc/passwd` dosyasını doğrudan okumayla gözden kaçabilecek dizin destekli hesapları da içerir. UID 0 hesaplarını, oturum açma kabuklarını, home dizinlerini, ek grupları ve yapılandırması beklenmedik şekilde etkileşimli oturum açmaya izin veren hesapları inceleyin. [İlginç gruplar](interesting-groups-linux-pe/README.md) sayfasında `sudo`, `docker`, `disk` ve `shadow` gibi yetki devreden gruplar ele alınır. Bir grup adını ayrıcalık olarak değerlendirmeden önce gerçek dosya sistemi ACL'lerini ve yerel politikayı kontrol edin.

[NSS, `passwd`, `group` veya `shadow` sorgularını](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) bir veritabanına yönlendiriyorsa, veritabanı destekli kimlikleri değerlendirmeden önce etkin sağlayıcıyı ve yapılandırma yolunu inceleyin. PostgreSQL NSS kurulumlarında `/etc/nss-pgsql.conf` ve `/etc/nss-pgsql-root.conf` yalnızca yol bilgisi veren ipuçlarıdır; bağlantı ayarları kimlik bilgileri içerebilir. Bir veritabanı rolü, yalnızca etkin NSS sağlayıcısının gerçekten döndürdüğü kayıtları değiştirebiliyorsa ve bir hesap bu kayıtları kullanarak kimlik doğrulayabiliyorsa önem taşır. Birincil GID'nin 0 olması root grubu üyeliği sağlar, UID 0 sağlamaz; bir sudo grubu eşlemesi, etkin bir [sudoers grup kuralı](https://man7.org/linux/man-pages/man5/sudoers.5.html) ve gerekli kimlik doğrulamasını gerektirir. UID 0 eşlemesi ise farklı bir kimlik sınırıdır. Pasif envanter çıkarma sırasında bağlantı dizelerini yazdırmayın veya hesap kayıtlarını değiştirmeyin.

Yerel hesap adları arasındaki sayısal UID'leri de karşılaştırın. [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) içindeki iki ad aynı Unix dosya kimliğine karşılık gelebilirken, oturum açma kimlik doğrulama kayıtları farklı olabilir. Bu nedenle, paylaşılan sıfır olmayan UID'ye sahip yeni eklenmiş bir diğer ad, başarılı kimlik doğrulamasının ardından başka bir kullanıcının dosyalarına veya süreçlerine erişim sağlayabilir; ancak bu UID ya da ayrı bir ayrıcalık yolu sağlamadıkça root yetkisi vermez. Paylaşılan UID'ler kasıtlı olabilir. Hesap kaynağını (`/etc/passwd` veya NSS), oluşturulma geçmişini, kabuğu ve home dizinini, gerçek kimlik doğrulama politikasını ve hesapların bu kimliği paylaşmaya yetkili olup olmadığını doğrulayın. Yalnızca yerel hesaplarda yapılan yinelenen UID kontrolü, dizin destekli bir diğer adı tespit edemez.

## Etkin ve yakın tarihli oturumları bulma

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Bir `screen` veya `tmux` socket'i, izinleri mevcut kullanıcının attach olmasına olanak tanıyorsa mevcut bir shell'i açığa çıkarabilir. Erişmeyi denemeden önce sahibini ve socket modunu kontrol edin; başka bir kullanıcının session'ına otomatik olarak attach olunamaz. Aktif bir sudo timestamp'i veya SSH agent socket'i de önemli olabilir, ancak bunların yeniden kullanımı kullanıcı kimliğine, izinlere ve policy'ye bağlıdır. Agent forwarding abuse için bkz. [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Bir [OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster), `SSH_AUTH_SOCK`'tan farklıdır: `ControlMaster` ve `ControlPath`, sonraki SSH client'larının mevcut, kimliği doğrulanmış bir bağlantıyı paylaşmasını sağlarken `ControlPersist`, ilk session sona erdikten sonra master'ın kullanılabilir kalmasını sağlayabilir. Mevcut kullanıcının `.ssh/config` dosyasını ve `.ssh` altındaki sığ seviyedeki socket path'lerini; sahip ve izin bilgileriyle birlikte inceleyin. Tek başına bir socket dosya adı, master'ın etkin olduğunu, mevcut kullanıcının bağlanabildiğini veya hangi uzak hesabı kullandığını kanıtlamaz.

## Kullanıcı artefaktlarını inceleyin

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell geçmişi, başlangıç dosyaları, SSH anahtarları, uygulama yapılandırmaları, GPG anahtarlıkları ve Kerberos önbellekleri kimlik bilgilerini veya yazılabilir kalıcılık noktalarını ortaya çıkarabilir. Daha ayrıcalıklı bir hesaba ait yazılabilir bir `authorized_keys` dosyası ya da shell başlangıç dosyası incelenmelidir. [Post-exploitation sayfası](../post-exploitation/README.md), GPG homedir konumunu değiştirme ve kimlik bilgisi arama konularını ele alır; [Linux Active Directory](linux-active-directory.md), Kerberos önbelleğinin ve keytab'in yeniden kullanımını ele alır. [PAM sayfası](../software-information/pam-pluggable-authentication-modules.md), kimlik doğrulama ilkesi risklerini açıklar.
{{#include ../../banners/hacktricks-training.md}}
