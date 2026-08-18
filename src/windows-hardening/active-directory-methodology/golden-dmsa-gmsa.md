# Golden gMSA/dMSA Attack (Managed Service Account Parolalarının Çevrimdışı Türetilmesi)

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows Managed Service Accounts, yöneticinin uzun süre geçerli olan bir parolayı yönetmesine gerek kalmadan service çalıştırmak için tasarlanmış domain principals'tır:

1. **gMSA** (group Managed Service Account), `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword` üzerinden yetkilendirilen bilgisayarlar tarafından kullanılabilir.
2. **dMSA** (delegated Managed Service Account), **Windows Server 2025**'te kullanıma sunulmuştur. Normal authentication işlemini yetkili machine identities'ye bağlar ve bir migration workflow aracılığıyla legacy service account'un yerini alabilir.

**Golden dMSA** ile **BadSuccessor**'ı karıştırmayın. Golden dMSA, KDS root-key material'ının ele geçirilmesini ve managed-account key'lerinin türetilmesini gerektirir; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) ise bir dMSA object'i ve migration attributes'ları üzerindeki control'ü kötüye kullanır.

Bir DC, her gMSA için bağımsız olarak oluşturulmuş bir clear-text password saklamaz. Password'ü bir **KDS root key**, zamana göre indekslenmiş bir Group Key Distribution Protocol (GKDI) key'i ve account SID'den türetir. Root-key object'leri `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...` altında bulunan `msKds-ProvRootKey` object'leridir; hassas değer `msKds-RootKeyData`'dır. `msDS-ManagedPasswordId` bir **GUID değildir**: KDS root-key GUID'ini, GKDI `L0`/`L1`/`L2` index'lerini ve domain/forest metadata'sını içeren binary bir key identifier'dır. DC, KDF'yi `GMSA PASSWORD` label'ı ve context olarak binary SID ile uygular, ardından bir `MSDS-MANAGEDPASSWORD_BLOB`'u yalnızca gMSA password'ünü almaya yetkili principals'lara sunar.<sup>[[2]](#references)</sup>

Bir dMSA normalde operational olarak farklıdır: secret'ın DC üzerinde kalması amaçlanır ve KDC, yetkili bir machine'a credentials verir. Ancak dMSA'ler, temel KDS/GKDI password derivation mekanizmasını yeniden kullanır. Golden dMSA bu secret'ı doğrudan yeniden oluşturur ve böylece amaçlanan machine-bound flow'u ve service host üzerindeki Credential Guard'ı bypass eder.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Bir KDS root key'i extract ettikten sonra saldırgan, `msDS-ManagedPassword`'ı okumadan bu key'e bağlı account'lar için password türetebilir. Bu işlem, account başına uygulanan password-retrieval ACL'sini bypass eder ve ele geçirilmiş root key kullanılmaya devam ettiği sürece olağan managed-password rotation işlemlerinden etkilenmez. gMSA'ler için okunabilir `msDS-ManagedPasswordId` normalde tam key identifier'ını sağlar. ACL ile kısıtlanmış dMSA'ler için Golden dMSA, eksik identifier'ı yalnızca **1.024 aday** seviyesine indirir.<sup>[[1]](#references)[[2]](#references)</sup>

### Ön Koşullar

* Genellikle Enterprise Admin / forest-root Domain Admin haklarıyla, bir DC üzerindeki `SYSTEM` ile ya da exposed bir DC database veya backup'tan elde edilen ilgili KDS root-key object'i.<sup>[[1]](#references)[[2]](#references)</sup>
* Hedef account'un SID'i, DNS domain'i, forest name'i ve `sAMAccountName`'i.<sup>[[1]](#references)[[2]](#references)</sup>
* Doğrudan gMSA computation için base64-encoded `msDS-ManagedPasswordId`; Golden dMSA için bunun yerine tahmin yapılabilir.<sup>[[1]](#references)[[2]](#references)</sup>
* [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) için .NET Framework 4.7.2 yüklü bir x64 Windows host.<sup>[[3]](#references)</sup>

### Faz 1 - KDS root key'i Extract Etme

`GoldenDMSA` ve [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA), root-key object field'larını base64 blob olarak export eder. Domain argument'ı olmadan tools, forest root'u sorgular ve uygun privileged directory access gerektirir. Domain/forest argument'ı ile bir DC üzerindeki `SYSTEM`, o DC'nin local Configuration naming-context replica'sını sorgulayabilir.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Hem root-key GUID'sini hem de base64 root-key blob'unu kaydedin. Bir registry `SECURITY`/`SYSTEM` hive export'u tek başına KDS root key değildir: yetkili materyal AD Configuration partition'ındadır.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - gMSA / dMSA nesnelerini listeleme

gMSA'ler için `sAMAccountName`, `objectSid` ve binary `msDS-ManagedPasswordId` değerlerini alın. İkincisi, çağıranın `msDS-ManagedPassword` değerini alma izni olmasa bile genellikle okunabilir.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
Bir dMSA'nın varsayılan ACL'si, düşük ayrıcalıklı LDAP enumeration işlemini engelleyebilir. `GoldenDMSA info`, LDAP'ı sorgulayabilir veya aday RID'leri enumerate edip `\PIPE\lsarpc` üzerinden `LsaLookupSids` aracılığıyla SID'leri çözümleyebilir; ardından dMSA'ları computer accounts ve gMSA'lardan ayırt edebilir.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Aşama 3 - `msDS-ManagedPasswordId` değerini yeniden oluşturma veya tahmin etme

Anahtar tanımlayıcı, rastgele bitlerin izlediği bir hesap oluşturma zaman damgasını değil, `L0Index`, `L1Index` ve `L2Index` değerlerini içerir. Semperis, parola oluşturma yolunun aday `L0Index` değerini kullanmadığını, `L1Index` ve `L2Index` değerlerinin ise her birinin `0..31` aralığındaki değerlerle sınırlı olduğunu tespit etti. Sonuç olarak root-key GUID, domain, forest ve SID değerlerini bilen bir saldırgan, `32 * 32 = 1,024` aday tanımlayıcının tamamını oluşturabilir.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Türetimler çevrimdışı yapılır, ancak geçerli adayı belirlemek genellikle authentication denemeleri gerektirir. Bu durum, geçerli anahtar bulunmadan önce bir dizi başarısız Kerberos pre-authentication veya NTLM validation işlemi oluşturabilir. AES Kerberos anahtarları için tool tarafından kullanılan managed-account salt değeri, `UPPERCASE.DNS.DOMAIN` + `host` + sondaki `$` karakteri çıkarılmış, küçük harfli hesap UPN'sinden oluşur (örneğin, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Aşama 4 - Parolayı hesaplama ve kullanma

Tam identifier biliniyorsa 256 baytlık password buffer'ı hesaplayın ve bunu NTLM/AES materyaline dönüştürün. Bu tool'ların yazdırdığı base64 değeri, LDAP `MSDS-MANAGEDPASSWORD_BLOB`'un kendisi değil, encode edilmiş password buffer'ıdır.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
NTLM sonucu, NTLM'nin kabul edildiği yerlerde kullanılabilir; AES anahtarı ise yönetilen hesap yalnızca AES kullandığında pass-the-hash üzerinden geçiş / TGT istekleri için kullanılabilir. Bu, saldırganın makinesini `PrincipalsAllowedToRetrieveManagedPassword` öğesine eklemeden, ele geçirilen managed service account'ın ayrıcalıklarını, SPN'lerini, delegation yapılandırmasını ve kaynak erişimini sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Cross-domain Configuration-partition abuse

KDS root-key nesneleri, child domain'lerdeki DC'lere çoğaltılan forest Configuration naming context içinde bulunur. Sonuç olarak, bir child-domain DC'si üzerindeki `SYSTEM`, forest-root DC'sinden nesneyi doğrudan okuyamasa da child DC'nin yerel replikasından forest-root KDS materyalini okuyabilir. Saldırgan bir parent-domain gMSA'sinin `msDS-ManagedPasswordId` değerini de okuyabiliyorsa, GoldenGMSA bu parent hesabın parolasını hesaplayabilir; SID filtering bu cryptographic saldırıyı engellemez.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Tespit, Sınırlama ve Kurtarma

* Başarılı `msKds-RootKeyData` okumaları için, `msKds-ProvRootKey` nesneleri tarafından devralınan **Master Root Keys** kapsayıcısında bir SACL yapılandırın. Directory Service Access auditing etkinleştirildiğinde, online extraction Security event **4662** oluşturur; beklenen DC'ler veya Tier-0 operatörleri olmayan özneleri araştırın. Ayrıca bu SACL'lerdeki ve root-key nesnesi ACL'lerindeki değişiklikleri de audit edin.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Child-to-parent attack, KDS nesnesini ele geçirilmiş child DC'nin yerel replica'sından okur; bu nedenle forest-root domain bu okumayı gözlemlemeyebilir. Parent domain'de, `msDS-GroupManagedServiceAccount` nesneleri üzerindeki `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) okumalarını başarılı şekilde audit edin ve başka bir domain'deki principal'lar tarafından yapılan okumaları araştırın.<sup>[[5]](#references)</sup>
* KDS nesnesi erişimini, managed account'lar tarafından gerçekleştirilen olağandışı logon'lar ve `$` soneki taşıyan service account'lar için Kerberos/NTLM failure artışlarıyla ilişkilendirin. Önceki database/backup theft sonrasında gerçekleştirilen offline computation, canlı bir DC'de görünür değildir.<sup>[[1]](#references)[[3]](#references)</sup>
* Root-key exposure sonrasında sıradan password rotation yeterli değildir. Microsoft'un mevcut recovery procedure'ü yeni bir KDS root key oluşturur, ilgili tüm DC'lerde KDS'yi yeniden başlatır ve etkilenen account'ları bu key'e taşır. Exposure kapsamı/zamanı bilinmiyorsa ve güvenli bir roll beklemek kabul edilemezse, compromised key'i kullanan her gMSA'yı değiştirin; kapsam biliniyorsa Microsoft, güvenli rolling'i zorlamak için authoritative-restore workflow'ünü belgeler. Eski key'i silmeden önce yeni key GUID'sini `msDS-ManagedPasswordId` içinde doğrulayın.<sup>[[4]](#references)</sup>
* DC database ve backup erişimini, Configuration-partition replication'ı ve KDS root-key administration'ı Tier-0 olarak ele alın. `ManagedPasswordIntervalInDays` değerini azaltmak bazı recovery window'larını sınırlar, ancak zaten compromised olan bir root key'i revoke etmez.<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration, identifier generation, 1,024-candidate validation, password computation ve NTLM/AES conversion.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration ve online, offline ve cross-domain password computation.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) ve [`Impacket`](https://github.com/fortra/impacket) - derived NTLM/AES key'lerini authorised testing kapsamında kullanın veya doğrulayın.



## References

- [1] [Golden dMSA - delegated Managed Service Accounts için authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Golden gMSA attack sonrasında nasıl recovery yapılır](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter as security boundary between domains? Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
