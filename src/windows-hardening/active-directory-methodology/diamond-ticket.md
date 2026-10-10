# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Soos 'n golden ticket** is 'n diamond ticket 'n TGT wat gebruik kan word om **toegang tot enige diens as enige gebruiker te verkry**. 'n Golden ticket word heeltemal vanlyn vervals, met die krbtgt-hash van daardie domein geënkripteer en dan in 'n aanmeldingsessie geplaas om gebruik te word. Omdat domeinbeheerders nie tred hou met watter TGT's hulle (of ander domeinbeheerders) wettiglik uitgereik het nie, sal hulle TGT's wat met hul eie krbtgt-hash geënkripteer is, geredelik aanvaar.<sup>[[1]](#references)</sup>

Daar is twee algemene tegnieke om die gebruik van golden tickets op te spoor:

- Soek na TGS-REQ's sonder 'n ooreenstemmende AS-REQ.
- Soek na TGT's met onrealistiese waardes, soos Mimikatz se verstekleeftyd van 10 jaar.

'n **diamond ticket** word geskep deur **die velde van 'n wettige TGT wat deur 'n DC uitgereik is, te wysig**. Dit word gedoen deur 'n **TGT aan te vra**, dit met die domein se krbtgt-hash te **dekripteer**, die verlangde kaartjieveI d te **wysig** en dit dan **weer te enkripteer**. Dit **oorkom die twee bogenoemde tekortkominge** van 'n golden ticket omdat:<sup>[[1]](#references)</sup>

- TGS-REQ's 'n voorafgaande AS-REQ sal hê.
- Die TGT deur 'n DC uitgereik is, wat beteken dat dit al die korrekte besonderhede van die domein se Kerberos-beleid sal bevat. Hoewel hierdie besonderhede akkuraat in 'n golden ticket vervals kan word, is dit meer ingewikkeld en vatbaar vir foute.

### Vereistes en werkvloei

- **Kriptografiese materiaal**: die krbtgt AES256-sleutel (verkieslik) of NTLM-hash om die TGT te dekripteer en weer te onderteken.
- **Wettige TGT-blob**: verkry met `/tgtdeleg`, `asktgt`, `s4u` of deur kaartjies uit die geheue uit te voer.
- **Konteksdata**: die teikengebruiker se RID, groep-RID's/SID's en (opsioneel) PAC-kenmerke wat van LDAP afgelei is.
- **Dienssleutels** (slegs as jy dienskaartjies weer wil skep): AES-sleutel van die diens-SPN wat nageboots moet word.

1. Verkry 'n TGT vir enige gebruiker wat jy beheer via AS-REQ (Rubeus se `/tgtdeleg` is gerieflik omdat dit die kliënt dwing om die Kerberos GSS-API-handdruk sonder aanmeldbewyse uit te voer).
2. Dekripteer die teruggekryde TGT met die krbtgt-sleutel en pas PAC-kenmerke aan (gebruiker, groepe, aanmeldinligting, SID's, toestel-eise, ens.).
3. Enkripteer/onderteken die kaartjie weer met dieselfde krbtgt-sleutel en spuit dit in die huidige aanmeldingsessie in (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Herhaal die proses opsioneel met 'n dienskaartjie deur 'n geldige TGT-blob en die teikendiens se sleutel te verskaf om ongemerk op die netwerk te bly.

### Bygewerkte Rubeus-tradecraft (2024+)

Onlangse werk deur Huntress het die `diamond`-aksie in Rubeus gemoderniseer deur die `/ldap`- en `/opsec`-verbeterings in te voer wat voorheen net vir golden/silver tickets beskikbaar was. `/ldap` haal nou werklike PAC-konteks op deur LDAP te raadpleeg **en** SYSVOL te koppel om rekening-/groepkenmerke en Kerberos-/wagwoordbeleid (bv. `GptTmpl.inf`) te onttrek. `/opsec` laat die AS-REQ/AS-REP-vloei soos Windows s'n lyk deur die twee-stap-preauth-uitruiling uit te voer en slegs AES plus realistiese KDCOptions af te dwing. Dit verminder ooglopende aanduidings, soos ontbrekende PAC-velde of leeftye wat nie met die beleid ooreenstem nie, aansienlik.<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (met opsionele `/ldapuser` en `/ldappassword`) raadpleeg AD en SYSVOL om die teiken gebruiker se PAC-beleidsdata te weerspieël.
- `/opsec` dwing ’n Windows-agtige AS-REQ-herpoging af, stel lawaaierige vlae op nul en hou by AES256.
- `/tgtdeleg` sorg dat jy nie aan die slagoffer se heldertextwagwoord of NTLM/AES-sleutel hoef te raak nie, terwyl dit steeds ’n dekripteerbare TGT teruggee.

### Hersamestelling van dienskaartjies

Dieselfde Rubeus-opdatering het die vermoë bygevoeg om die diamond-tegniek op TGS-blobs toe te pas. Deur `diamond` ’n **base64-geënkodeerde TGT** (van `asktgt`, `/tgtdeleg` of ’n voorheen vervalste TGT), die **diens-SPN** en die **diens se AES-sleutel** te gee, kan jy realistiese dienskaartjies skep sonder om aan die KDC te raak—wat effektief ’n sluwer silver ticket oplewer.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Hierdie werkvloei is ideaal wanneer jy reeds ’n service account key beheer (bv. met `lsadump::lsa /inject` of `secretsdump.py` gedump) en ’n eenmalige TGS wil skep wat perfek by AD-beleid, tydlyne en PAC-data pas, sonder om enige nuwe AS/TGS-verkeer te genereer.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

’n Nuwer variasie, wat soms ’n **sapphire ticket** genoem word, kombineer Diamond se basis van ’n “real TGT” met **S4U2self+U2U** om ’n bevoorregte PAC te steel en dit in jou eie TGT te plaas. In plaas daarvan om ekstra SIDs te versin, versoek jy ’n U2U S4U2self-ticket vir ’n gebruiker met hoë voorregte, waar die `sname` op die requester met lae voorregte gerig is; die KRB_TGS_REQ bevat die requester se TGT in `additional-tickets` en stel `ENC-TKT-IN-SKEY` in, sodat die dienskaartjie met daardie gebruiker se sleutel gedekripteer kan word. Jy onttrek dan die bevoorregte PAC en voeg dit in jou wettige TGT in voordat jy dit met die krbtgt-sleutel weer onderteken.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket se `ticketer.py` sluit nou ondersteuning vir sapphire in via `-impersonate` + `-request` (KDC-uitruiling regstreeks):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` aanvaar ’n gebruikersnaam of SID; `-request` vereis aktiewe gebruiker-creds plus krbtgt-sleutelmateriaal (AES/NTLM) om tickets te dekripteer/patch.

Belangrike OPSEC-aanwysers wanneer hierdie variant gebruik word:<sup>[[5]](#references)</sup>

- TGS-REQ sal `ENC-TKT-IN-SKEY` en `additional-tickets` (die slagoffer se TGT) bevat — iets wat selde in normale verkeer voorkom.
- `sname` is dikwels gelyk aan die versoekende gebruiker (selfbedienings-toegang), en Event ID 4769 wys die oproeper en teiken as dieselfde SPN/gebruiker.
- Verwag gepaarde 4768/4769-inskrywings met dieselfde kliëntrekenaar, maar verskillende CNAMES (versoeker met lae voorregte teenoor PAC-eienaar met hoë voorregte).

### OPSEC- en opsporingsnotas

- Die tradisionele hunter-heuristieke (TGS sonder AS, lewensduur van dekades) geld steeds vir golden tickets, maar diamond tickets kom hoofsaaklik na vore wanneer die **PAC-inhoud of groepkartering onmoontlik lyk**. Vul elke PAC-veld in (aanmeldure, gebruikerprofielpaaie, toestel-ID’s) sodat outomatiese vergelykings nie die vervalsing onmiddellik merk nie.<sup>[[3]](#references)</sup>
- **Moenie te veel groepe/RID’s byvoeg nie**. As jy net `512` (Domain Admins) en `519` (Enterprise Admins) nodig het, stop daar en maak seker dat die teikenrekening elders in AD geloofwaardig aan daardie groepe behoort. Oormatige `ExtraSids` verklap die vervalsing.
- Sapphire-styl-omruilings laat U2U-vingerafdrukke: `ENC-TKT-IN-SKEY` + `additional-tickets` plus ’n `sname` wat in 4769 na ’n gebruiker (dikwels die versoeker) verwys, en ’n daaropvolgende 4624-aanmelding wat van die vervalste ticket afkomstig is. Korrelleer daardie velde eerder as om net na gapings sonder AS-REQ te soek.<sup>[[5]](#references)</sup>
- Microsoft het begin om **RC4-diens-ticket-uitreiking** uit te faseer weens CVE-2026-20833; die afdwinging van slegs AES-etipes op die KDC versterk die domein en strook met diamond/sapphire-gereedskap (/opsec dwing reeds AES af). Die vermenging van RC4 in vervalste PAC’s sal toenemend uitstaan.<sup>[[6]](#references)</sup>
- Splunk se Security Content-projek versprei aanvalreeks-telemetrie vir diamond tickets, plus opsporings soos *Windows Domain Admin-nabootsingsaanwyser*, wat ongewone Event ID 4768/4769/4624-reekse en PAC-groepveranderings korreleer. Die herhaling van daardie datastel (of die generering van jou eie met die opdragte hierbo) help om SOC-dekking vir T1558.001 te bekragtig en gee jou terselfdertyd konkrete waarskuwingslogika om te ontduik.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Edelgesteentes: Die nuwe generasie Kerberos-aanvalle (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Ons speel graag met tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Die Kerberos Diamond Ticket hersny (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Aanvaldata en opsporings vir Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Die skadukant van edelstene: Diamond- en Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Afdwinging van RC4-dienstickets vir CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
