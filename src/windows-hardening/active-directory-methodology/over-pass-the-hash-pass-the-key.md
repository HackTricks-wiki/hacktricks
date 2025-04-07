# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protokolünün kısıtlandığı ve Kerberos kimlik doğrulamasının öncelikli olduğu ortamlarda tasarlanmıştır. Bu saldırı, bir kullanıcının NTLM hash'ini veya AES anahtarlarını kullanarak Kerberos biletleri talep eder ve bu sayede bir ağ içindeki kaynaklara yetkisiz erişim sağlar.

Bu saldırıyı gerçekleştirmek için ilk adım, hedef kullanıcının hesabının NTLM hash'ini veya şifresini edinmektir. Bu bilgiyi güvence altına aldıktan sonra, hesabın bir Ticket Granting Ticket (TGT) alması sağlanabilir ve bu da saldırganın kullanıcının izinleri olan hizmetlere veya makinelere erişmesine olanak tanır.

İşlem, aşağıdaki komutlarla başlatılabilir:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 gerektiren senaryolar için `-aesKey [AES key]` seçeneği kullanılabilir. Ayrıca, elde edilen bilet, smbexec.py veya wmiexec.py gibi çeşitli araçlarla kullanılabilir ve saldırının kapsamını genişletebilir.

_PyAsn1Error_ veya _KDC cannot find the name_ gibi karşılaşılan sorunlar genellikle Impacket kütüphanesinin güncellenmesi veya IP adresi yerine ana bilgisayar adının kullanılmasıyla çözülür, bu da Kerberos KDC ile uyumluluğu sağlar.

Rubeus.exe kullanarak alternatif bir komut dizisi, bu tekniğin başka bir yönünü göstermektedir:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem, kimlik doğrulama amaçları için bileti doğrudan ele geçirme ve kullanma odaklı **Pass the Key** yaklaşımını yansıtır. Bir TGT isteğinin başlatılmasının, varsayılan olarak RC4-HMAC kullanımını belirten `4768: A Kerberos authentication ticket (TGT) was requested` olayını tetiklediğini belirtmek önemlidir; ancak modern Windows sistemleri AES256'yı tercih etmektedir.

Operasyonel güvenliğe uymak ve AES256 kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Gizli versiyon

> [!WARNING]
> Her oturum açma seansı aynı anda yalnızca bir aktif TGT'ye sahip olabilir, bu yüzden dikkatli olun.

1. Cobalt Strike'dan **`make_token`** ile yeni bir oturum açma seansı oluşturun.
2. Ardından, mevcut olanı etkilemeden yeni oturum açma seansı için Rubeus kullanarak bir TGT oluşturun.


## Referanslar

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)


{{#include ../../banners/hacktricks-training.md}}
