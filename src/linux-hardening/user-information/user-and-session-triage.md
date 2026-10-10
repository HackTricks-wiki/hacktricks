# Kullanıcılar, Oturumlar ve Kimlik Bilgisi Kalıntıları

{{#include ../../banners/hacktricks-training.md}}

Önce mevcut shell'in sahibi olan kimliği belirleyin, ardından diğer kullanıcıları, grupları, etkin oturumları ve kimlik bilgisi depolarını listeleyin. [Gerçek, etkin ve kaydedilmiş kullanıcı kimliği](euid-ruid-suid.md) sayfasında, bir sürecin etkin yetkilerinin neden oturum açtığı hesaptan farklı olabileceği açıklanıyor.

## Kimlikleri ve grup tabanlı erişimi listeleme

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent`, yalnızca `/etc/passwd` dosyasını okumakla gözden kaçabilecek dizin destekli hesapları da içerir. UID 0 hesaplarını, login shell'lerini, home dizinlerini, ek grupları ve yapılandırması beklenmedik şekilde etkileşimli login'e izin veren hesapları inceleyin. [interesting groups](interesting-groups-linux-pe/README.md) sayfasında `sudo`, `docker`, `disk` ve `shadow` gibi yetki devredilmiş erişimler ele alınır. Bir grup adını yetki olarak değerlendirmeden önce gerçek dosya sistemi ACL'lerini ve yerel politikayı kontrol edin.

[NSS, `passwd`, `group` veya `shadow` aramalarını](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) bir veritabanına yönlendiriyorsa, veritabanı destekli kimlikleri değerlendirmeden önce etkin sağlayıcıyı ve yapılandırma yolunu inceleyin. PostgreSQL NSS dağıtımlarında `/etc/nss-pgsql.conf` ve `/etc/nss-pgsql-root.conf` yalnızca yol ipuçlarıdır; bağlantı ayarları kimlik bilgileri içerebilir. Bir veritabanı rolü ancak etkin NSS sağlayıcısının gerçekten döndürdüğü kayıtları değiştirebiliyorsa ve bir hesap bu kayıtları kullanarak kimlik doğrulayabiliyorsa önem taşır. Birincil GID'nin 0 olması, UID 0 değil, root grubuna üyelik sağlar; sudo grubu eşlemesi, etkin bir [sudoers grup kuralı](https://man7.org/linux/man-pages/man5/sudoers.5.html) ve gerekli kimlik doğrulamayı gerektirir. UID 0 eşlemesi farklı bir kimlik sınırıdır. Pasif numaralandırma sırasında bağlantı dizelerini yazdırmayın veya hesap kayıtlarını değiştirmeyin.

Ayrıca yerel hesap adlarındaki sayısal UID'leri karşılaştırın. [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) içindeki iki ad aynı Unix dosya kimliğine karşılık gelebilirken, login kimlik doğrulama kayıtları farklı olabilir. Bu nedenle, paylaşılan sıfırdan farklı bir UID'ye sahip yeni eklenmiş bir takma ad, başarılı kimlik doğrulamasının ardından başka bir kullanıcının dosyalarına veya süreçlerine erişim sağlayabilir; bu UID ya da ayrı bir yetki yolu sağlamadığı sürece root yetkisi vermez. Paylaşılan UID'ler kasıtlı olabilir. Hesap kaynağını (`/etc/passwd` ya da NSS), oluşturulma geçmişini, shell'i ve home dizinini, geçerli kimlik doğrulama politikasını ve hesapların bu kimliği paylaşma yetkisi olup olmadığını doğrulayın. Yalnızca yerel hesaplarda yapılan bir yinelenen kayıt kontrolü, dizin destekli bir takma adı dışlayamaz.

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

Bir `screen` veya `tmux` soketi, izinleri mevcut kullanıcının bağlanmasına olanak tanıyorsa mevcut bir shell'i açığa çıkarabilir. Erişmeyi denemeden önce sahibini ve soket modunu kontrol edin; başka bir kullanıcının oturumuna otomatik olarak bağlanılamaz. Etkin bir sudo zaman damgası veya SSH agent soketi de önemli olabilir, ancak bunların yeniden kullanımı kullanıcı kimliğine, izinlere ve politikaya bağlıdır. Agent forwarding istismarı için bkz. [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Bir [OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster), `SSH_AUTH_SOCK`'tan ayrıdır: `ControlMaster` ve `ControlPath`, sonraki SSH istemcilerinin mevcut bir kimliği doğrulanmış bağlantıyı paylaşmasını sağlarken `ControlPersist`, ilk oturum sona erdikten sonra da master bağlantısını kullanılabilir durumda tutabilir. Mevcut kullanıcının `.ssh/config` dosyasını ve sığ `.ssh` soket yollarını; sahip ve izin bilgileri dahil olmak üzere inceleyin. Tek başına bir soket dosya adı, master bağlantısının etkin olduğunu, mevcut kullanıcının bağlanabileceğini veya hangi uzak hesabı kullandığını kanıtlamaz.

## Kullanıcı artefaktlarını inceleme

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history, startup dosyaları, SSH anahtarları, uygulama yapılandırmaları, GPG keyring'leri ve Kerberos önbellekleri kimlik bilgilerini veya yazılabilir kalıcılık noktalarını açığa çıkarabilir. Daha ayrıcalıklı bir hesaba ait yazılabilir `authorized_keys` dosyası veya shell startup dosyası incelenmelidir. [post-exploitation sayfası](../post-exploitation/README.md), GPG homedir taşıma ve kimlik bilgisi arama konularını ele alır; [Linux Active Directory](linux-active-directory.md), Kerberos önbelleği ve keytab yeniden kullanımını ele alır. [PAM sayfası](../software-information/pam-pluggable-authentication-modules.md), kimlik doğrulama ilkesi risklerini açıklar.
{{#include ../../banners/hacktricks-training.md}}
