# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protokolünün kısıtlandığı ve Kerberos authentication'ın öncelikli olduğu ortamlara yöneliktir. Bu saldırı, bir kullanıcının NTLM hash'ini veya AES key'lerini kullanarak Kerberos ticket'ları talep eder ve ağ içindeki kaynaklara yetkisiz erişim sağlar.

Teknik olarak:

- **Over-Pass-the-Hash** genellikle **NT hash** değerini **RC4-HMAC** Kerberos key'i üzerinden bir Kerberos TGT'sine dönüştürmek anlamına gelir.
- **Pass-the-Key**, zaten **AES128/AES256** gibi bir Kerberos key'ine sahip olduğunuz ve doğrudan bu key ile bir TGT talep ettiğiniz daha genel versiyondur.

Bu fark hardened ortamlarda önemlidir: **RC4 devre dışı bırakılmışsa** veya KDC tarafından artık varsayılan olarak kabul edilmiyorsa, yalnızca **NT hash** yeterli değildir ve bir **AES key**'ine (veya bundan türetmek için cleartext password'e) ihtiyacınız olur.

Bu saldırıyı gerçekleştirmek için ilk adım, hedef kullanıcının hesabına ait NTLM hash'ini veya password'ünü elde etmektir. Bu bilgiler güvence altına alındıktan sonra, hesap için bir Ticket Granting Ticket (TGT) elde edilebilir; bu da saldırganın kullanıcının izinlerine sahip olduğu service'lere veya makinelere erişmesini sağlar.

Süreç aşağıdaki command'ler ile başlatılabilir:<sup>[[1]](#references)</sup>
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
`getTGT.py`, `-service <SPN>` ile **AS-REQ üzerinden doğrudan service ticket istemeyi** de destekler. Bu, ek bir TGS-REQ göndermeden belirli bir SPN için ticket istediğinizde kullanışlı olabilir:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Ayrıca, elde edilen ticket `smbexec.py` veya `wmiexec.py` gibi çeşitli araçlarla kullanılabilir ve saldırının kapsamı genişletilebilir.

_PyAsn1Error_ veya _KDC cannot find the name_ gibi karşılaşılan sorunlar genellikle Impacket kütüphanesinin güncellenmesiyle ya da IP adresi yerine hostname kullanılmasıyla çözülür; böylece Kerberos KDC ile uyumluluk sağlanır.

Rubeus.exe kullanılarak uygulanan alternatif bir komut dizisi, bu tekniğin başka bir yönünü gösterir:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem, **Pass the Key** yaklaşımını temel alır ve ticket'ın kimlik doğrulama amacıyla doğrudan ele geçirilip kullanılmasına odaklanır. Uygulamada:

- `Rubeus asktgt`, **raw Kerberos AS-REQ/AS-REP** isteğini kendisi gönderir ve `/luid` ile başka bir logon session'ı hedeflemek veya `/createnetonly` ile ayrı bir logon session oluşturmak istemediğiniz sürece admin haklarına ihtiyaç duymaz.<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth`, credential materyalini bir logon session'a patch'ler ve bu nedenle **LSASS'a dokunur**; bu işlem genellikle local admin veya `SYSTEM` gerektirir ve EDR açısından daha fazla gürültü oluşturur.

Mimikatz ile örnekler:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Operasyonel güvenliğe uymak ve AES256 kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec`, Rubeus tarafından oluşturulan trafiğin native Windows Kerberos trafiğinden biraz farklı olması nedeniyle önemlidir. Ayrıca `/opsec` seçeneğinin **AES256** trafiği için tasarlandığını unutmayın; RC4 ile kullanmak genellikle `/force` gerektirir ve bu da amacın büyük bölümünü ortadan kaldırır; çünkü modern domain'lerde **RC4 kullanımı başlı başına güçlü bir sinyaldir**.

## Detection notları

Her TGT request, DC üzerinde **event `4768`** oluşturur. Güncel Windows build'lerinde bu event, eski writeup'larda belirtilenden daha kullanışlı alanlar içerir:

- `TicketEncryptionType`, verilen TGT için hangi enctype'ın kullanıldığını gösterir. Yaygın değerler **RC4-HMAC** için `0x17`, **AES128** için `0x11` ve **AES256** için `0x12` şeklindedir.<sup>[[3]](#references)</sup>
- Güncellenmiş event'ler ayrıca `SessionKeyEncryptionType`, `PreAuthEncryptionType` ve client tarafından bildirilen enctype'ları gösterir. Bu da **gerçek RC4 bağımlılığını**, kafa karıştırıcı legacy varsayılanlarından ayırt etmeye yardımcı olur.
- Modern bir ortamda `0x17` görülmesi, account'un, host'un veya KDC fallback path'inin hâlâ RC4'e izin verdiğine dair iyi bir ipucudur; dolayısıyla ortam NT-hash-based Over-Pass-the-Hash için daha elverişlidir.

Microsoft, Kasım 2022 Kerberos hardening güncellemelerinden bu yana RC4-by-default davranışını kademeli olarak azaltmaktadır ve güncel yayımlanmış guidance, **Q2 2026'nın sonuna kadar AD DC'ler için RC4'ü varsayılan enctype olarak kaldırmayı** önermektedir. Offensive perspective açısından bu, **AES ile Pass-the-Key** yönteminin giderek daha güvenilir bir path olduğu; klasik **yalnızca NT-hash kullanan OpTH** yönteminin ise hardened estate'lerde daha sık başarısız olmaya devam edeceği anlamına gelir.<sup>[[3]](#references)</sup>

Kerberos encryption type'ları ve ilgili ticketing davranışı hakkında daha fazla bilgi için:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Daha stealthy version

> [!WARNING]
> Her logon session aynı anda yalnızca bir aktif TGT bulundurabilir; bu nedenle dikkatli olun.

1. Cobalt Strike'tan **`make_token`** ile yeni bir logon session oluşturun.
2. Ardından mevcut session'ı etkilemeden yeni logon session için TGT oluşturmak üzere Rubeus kullanın.

Benzer bir isolation işlemini, sacrificial **logon type 9** session kullanarak doğrudan Rubeus ile de gerçekleştirebilirsiniz:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Bu, mevcut session TGT'sinin üzerine yazılmasını önler ve ticket'ı mevcut logon session'ınıza import etmekten genellikle daha güvenlidir.

## References

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
