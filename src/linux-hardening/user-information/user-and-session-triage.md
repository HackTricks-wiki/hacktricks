# Kullanıcılar, Oturumlar ve Kimlik Bilgisi Artıkları

{{#include ../../banners/hacktricks-training.md}}

Önce mevcut shell’in sahibi olan kimliği belirleyin, ardından diğer kullanıcıları, grupları, etkin oturumları ve kimlik bilgisi depolarını listeleyin. [Gerçek, etkin ve kaydedilmiş kullanıcı kimliği](euid-ruid-suid.md) sayfasında, bir işlemin etkin ayrıcalıklarının neden oturum açma hesabından farklı olabileceği açıklanıyor.

## Kimlikleri ve grup tabanlı erişimi listeleyin

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent`, yalnızca `/etc/passwd` dosyasını okumakla gözden kaçabilecek dizin tabanlı hesapları da içerir. UID 0 hesaplarını, login shell'lerini, home dizinlerini, ek grupları ve yapılandırması beklenmedik şekilde etkileşimli login'e izin veren hesapları inceleyin. [interesting groups](interesting-groups-linux-pe/README.md) sayfasında `sudo`, `docker`, `disk` ve `shadow` gibi devredilmiş erişimler ele alınır. Bir grup adını ayrıcalık olarak değerlendirmeden önce gerçek dosya sistemi ACL'lerini ve yerel politikayı kontrol edin.

[NSS, `passwd`, `group` veya `shadow` sorgularını](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) bir veritabanına yönlendiriyorsa, veritabanı tabanlı kimlikleri değerlendirmeden önce etkin sağlayıcıyı ve yapılandırma yolunu inceleyin. PostgreSQL NSS dağıtımlarında `/etc/nss-pgsql.conf` ve `/etc/nss-pgsql-root.conf`, bağlantı ayarları kimlik bilgileri içerebileceğinden yalnızca yol gösterici ipuçlarıdır. Bir veritabanı rolü, yalnızca etkin NSS sağlayıcısının gerçekten döndürdüğü kayıtları değiştirebiliyorsa ve bir hesap bu kayıtlarla kimlik doğrulayabiliyorsa önem taşır. Birincil GID'nin 0 olması root grubu üyeliği sağlar, UID 0 sağlamaz; sudo grubu eşlemesi, etkin bir [sudoers grup kuralı](https://man7.org/linux/man-pages/man5/sudoers.5.html) ve gerekli kimlik doğrulamayı gerektirir. UID 0 eşlemesi farklı bir kimlik sınırıdır. Pasif enumeration sırasında bağlantı dizelerini yazdırmayın veya hesap kayıtlarını değiştirmeyin.

Ayrıca yerel hesap adlarındaki sayısal UID'leri karşılaştırın. [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) içindeki iki ad aynı Unix dosya kimliğini gösterebilirken, login kimlik doğrulama kayıtları farklı olabilir. Bu nedenle, paylaşılan sıfır olmayan UID'ye sahip yeni eklenmiş bir takma ad, başarılı kimlik doğrulamasından sonra başka bir kullanıcının dosyalarına veya süreçlerine erişim sağlayabilir; bu UID ya da ayrı bir ayrıcalık yolu root yetkisi vermediği sürece root erişimi sağlamaz. Paylaşılan UID'ler kasıtlı olabilir. Hesap kaynağını (`/etc/passwd` veya NSS), oluşturulma geçmişini, shell'i ve home dizinini, gerçek kimlik doğrulama politikasını ve hesapların bu kimliği paylaşma yetkisi olup olmadığını doğrulayın. Yalnızca yerel hesapları denetleyen bir kontrol, dizin tabanlı bir takma ad olmadığını kanıtlayamaz.

## Etkin ve yakın zamandaki oturumları bulun

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Bir `screen` veya `tmux` socket'i, izinleri mevcut kullanıcının bağlanmasına olanak tanıyorsa açık bir shell'i kullanıma sunabilir. Erişimi denemeden önce sahibini ve socket modunu kontrol edin; başka bir kullanıcının oturumuna otomatik olarak bağlanılamaz. Etkin bir sudo zaman damgası veya SSH agent socket'i de önemli olabilir, ancak bunların yeniden kullanılması kullanıcı kimliğine, izinlere ve ilkelere bağlıdır. Agent forwarding kötüye kullanımı için [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) sayfasına bakın.

Bir [OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster), `SSH_AUTH_SOCK`'tan ayrıdır: `ControlMaster` ve `ControlPath`, sonraki SSH istemcilerinin mevcut, kimlik doğrulaması yapılmış bir bağlantıyı paylaşmasını sağlar; `ControlPersist` ise ilk oturum sona erdikten sonra master'ın kullanılabilir kalmasını sağlayabilir. Mevcut kullanıcının `.ssh/config` dosyasını ve `.ssh` içindeki sığ socket yollarını; sahiplik ve izinler dâhil inceleyin. Yalnızca socket dosya adı, master'ın etkin olduğunu, mevcut kullanıcının bağlanabileceğini veya hangi uzak hesabı kullandığını kanıtlamaz.

## Kullanıcı artefaktlarını gözden geçirin

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell geçmişi, başlangıç dosyaları, SSH anahtarları, uygulama yapılandırmaları, GPG anahtarlıkları ve Kerberos önbellekleri kimlik bilgilerini veya yazılabilir kalıcılık noktalarını açığa çıkarabilir. Daha ayrıcalıklı bir hesaba ait yazılabilir bir `authorized_keys` dosyası veya kabuk başlangıç dosyası incelenmelidir. [Post-exploitation sayfası](../post-exploitation/README.md) GPG homedir konumunu değiştirme ve kimlik bilgisi avcılığını ele alır; [Linux Active Directory](linux-active-directory.md), Kerberos önbelleğinin ve keytab'in yeniden kullanımını ele alır. [PAM sayfası](../software-information/pam-pluggable-authentication-modules.md) kimlik doğrulama politikası risklerini açıklar.
{{#include ../../banners/hacktricks-training.md}}
