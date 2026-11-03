# LDAP-ondertekening en kanaalbinding: verharding

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit saak maak

LDAP-relay/MITM-aanvalle stuur authentication na ’n domain controller om ’n geauthentiseerde LDAP-konteks te verkry. Die [oorsig van naamresolusie-vergiftiging en relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) dek die breër werkvloei. Twee verwante kontroles verminder hierdie aanvalspaaie:

- **LDAP-kanaalbinding (CBT)** bind toepaslike authentication aan die TLS-bedienersertifikaat/-kanaal wat deur LDAPS gebruik word, wat relay tussen kanale bemoeilik.
- **LDAP-ondertekening** vereis integriteitsbeskerming vir SASL LDAP-binds. Dit voeg nie vertroulikheid by nie; gebruik TLS wanneer LDAP-inhoud ook enkripsie benodig.<sup>[[2]](#references)</sup>

**Vinnige kontrole van die sekuriteitsposisie**: gereedskap soos `netexec ldap <dc> -u user -p pass` rapporteer die waargenome ondertekenings- en kanaalbindingsbeleid. `(signing:None)` en `(channel binding:Never)` dui op ontbrekende kontroles, maar ’n suksesvolle relay hang steeds af van die vasgelegde authentication-tipe, EPA-gedrag, rekeningvoorregte, teikenprotokol en relay-beskerming. Wanneer die gerelayde identiteit die nodige regte het, kan gereedskap soos KrbRelayUp `msDS-AllowedToActOnBehalfOfOtherIdentity` skryf, hulpbron-gebaseerde beperkte delegasie (RBCD) instel en die gevolglike delegasiepad gebruik om ’n bevoorregte identiteit na te boots.<sup>[[4]](#references)</sup>

**Server 2025 DC's** stel ’n nuwe GPO (**LDAP server signing requirements Enforcement**) bekend wat by verstek **Require Signing** gebruik wanneer dit **Not Configured** is. Om afdwinging te vermy, moet jy daardie beleid uitdruklik op **Disabled** stel.<sup>[[1]](#references)</sup>

## LDAP-kanaalbinding (slegs LDAPS)

- **Vereistes**:
  - Die CVE-2017-8563-pleister (2017) voeg ondersteuning vir Extended Protection for Authentication by.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) voeg LDAPS CBT-“what-if”-telemetrie by.<sup>[[2]](#references)</sup>
- **GPO (DC's)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (verstek, geen CBT)
  - `When Supported` (gedeeltelike afdwinging: CBT-bekwame kliënte moet ’n geldige token verskaf; kliënte sonder CBT-ondersteuning kan steeds bind, en ouditgebeurtenisse word uitgereik)
  - `Always` (afdwinging: verwerp LDAPS-binds sonder geldige CBT)<sup>[[1]](#references)</sup>
- **Oudit**: stel op **When Supported** om die volgende te wys:
  - **3074** – LDAPS-bind sou CBT-validering misluk het indien dit afgedwing is.
  - **3075** – LDAPS-bind het CBT-data weggelaat en sou verwerp gewees het indien dit afgedwing is.
  - (Gebeurtenis **3039** dui steeds CBT-mislukkings op ouer builds aan.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Afdwinging**: stel op **Always** sodra LDAPS-kliënte CBT's stuur; dit is slegs effektief op **LDAPS** (nie rou 389 nie).<sup>[[1]](#references)</sup>

`When Supported` is nie slegs vir ouditering nie: dit valideer CBT vir bekwame kliënte, terwyl kliënte sonder CBT-ondersteuning toegelaat word. Die [Microsoft-beleidsverwysing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) beskryf die verstekwaardes wat van die weergawe afhang. LDAP-ondertekening is van toepassing op relevante binds oor LDAP/389; kanaalbinding is van toepassing op TLS-beskermde LDAP-authentication.


## LDAP-ondertekening

- **Kliënt-GPO**: `Network security: LDAP client signing requirements` = `Require signing` (teenoor die verstek `Negotiate signing` op moderne Windows).<sup>[[1]](#references)</sup>
- **DC-GPO**:
  - Ouer beleid: `Domain controller: LDAP server signing requirements` = `Require signing` (verstek is `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: laat die ouer beleid op `None` en stel `LDAP server signing requirements Enforcement` op `Enabled` (by verstek word dit afgedwing wanneer dit Not Configured is; stel op `Disabled` om dit te vermy).<sup>[[1]](#references)</sup>
- **Verenigbaarheid**: Maak ’n inventaris van nie-Windows-toestelle en toepassings wat eenvoudige binds of ongetekende SASL-binds gebruik. Microsoft dokumenteer ondersteuning op onderhoude Windows-weergawes; stellings oor verenigbaarheid met ouer kliënte moet teen die werklike kliëntstapel nagegaan word, eerder as om dit tot ’n XP-weergawedrempel te vereenvoudig.<sup>[[2]](#references)</sup>

## Relay-aanvalspaaie en herauthentisering met getekende SASL

As **slegs ondertekening** vereis word, kan relay na LDAPS steeds werk wanneer kanaalbinding nie afgedwing word nie: TLS verskaf integriteit op die vervoervlak. As **slegs kanaalbinding** vereis word, het gewone LDAP geen TLS-kanaal waaraan dit kan bind nie; ’n relay kan op TCP 389 authenticate en dan StartTLS gebruik vir bewerkings wat TLS vereis, mits die gerelayde identiteit die nodige regte het. Die afdwinging van albei sluit hierdie konvensionele alternatiewe, maar dit het nie die volgende kwesbaarheid op ongepleisterde domeinbeheerders gestop nie.<sup>[[5]](#references)</sup>

### Voeg ’n LDAP-bewerking ná ’n gerelayde Bind

Op kwesbare Windows Server 2016–2025-domeinbeheerders, vestig eers ’n **getekende NTLM SASL LDAP-verbinding** op TCP 389 as identiteit X, met geloofsbriewe waarvan jy die sessiesleutel ken (of ’n anonieme NTLM SASL-konteks waar dit aanvaar word). Dwing identiteit Y om **oor SMB** te authenticate by die relay. Stuur Y se NTLM NEGOTIATE en die DC se CHALLENGE deur GSS-SPNEGO Bind-versoeke op X se bestaande LDAP-verbinding. Die Windows SMB-kliënt stel `NTLMSSP_NEGOTIATE_SIGN`, dus vereis die gevolglike LDAP-bind ’n getekende SASL-laag; ’n HTTP/WebDAV-oorspronguitruiling het gewoonlik nie daardie vlag nie en is nie hier uitruilbaar nie.<sup>[[5]](#references)</sup>

Wanneer Y NTLM AUTHENTICATE stuur, plaas **twee afsonderlike LDAP-boodskappe in een lengtevoorafgaande SASL-rekord**: ’n BindRequest wat daardie antwoord bevat, gevolg deur ’n ModifyRequest. Teken die hele rekord met X se bekende sleutel. Die kwesbare DC valideer die rekord onder X, voltooi die Bind en verander die verbinding se magtiging na Y, en voer dan die oorblywende ModifyRequest as Y uit sonder om die rekord weer onder Y se sleutel te valideer. Dit openbaar nie Y se wagwoord of sessiesleutel nie; ’n latere rekord wat met X onderteken is, misluk. ’n RBCD-skryfbewerking na `msDS-AllowedToActOnBehalfOfOtherIdentity` of ’n skryfbewerking vir shadow credentials na `msDS-KeyCredentialLink` vereis steeds dat Y toestemming op die teikenobjek het. Sien [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md), en, vir ’n gerelayde DC-rekenaarrekening, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Dit is ’n omseiling van **gewone LDAP**, nie ’n omseiling van LDAPS-kanaalbinding nie. Op LDAPS beskerm TLS die verbinding, en Windows vestig nie die X-sleutel NTLM SASL-ondertekeningslaag wat vir hierdie rekordstapel-aanvalspad nodig is nie. As TCP 389 nie beskikbaar is nie, kan die tegniek nie bloot na TCP 636 oorgedra word nie. Die sekuriteitsopdaterings van Oktober 2026 voorkom die bewerking met dieselfde rekord deur oorblywende data te verwerp nadat die Bind die verbinding se identiteit verander het.<sup>[[5]](#references)</sup> KB5126646 is die opdatering vir Windows Server 2025; die ander betrokke Server-weergawes het verskillende KB-nommers.<sup>[[7]](#references)</sup>

Die navorser se [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) omhul ’n gewysigde `ntlmrelayx.py` vir hierdie werkvloei. Dit vereis ’n **SMB**-bron om authentication af te dwing, ’n vasgepinde Impacket-boom wat LDAP-ondertekenings-/sekuriteitskonteks-API's blootstel (PyPI Impacket 0.13.1 is onvoldoende), en ’n aanvaller-beheerde rekening vir die aanvanklike getekende bind. Vir ’n RBCD-skryfbewerking, verskaf die DN van die slagofferobjek en die SID van ’n beheerde delegerende rekenaar; gebruik `-attribute` saam met `-value` of `-value-hex` vir ’n ander toegelate skryfbewerking. Bevestig die instrument se onafhanklike, getekende terugleesbewerking eerder as om ’n relay-kant-`FAILED`-boodskap as bewys te beskou dat die ModifyRequest misluk het.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Dwing SMB-verifikasie afsonderlik af; sien [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) vir een coercion-oppervlak en die [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) vir ander. Die nutsding se opdrag en implementering word in sy repository gedokumenteer.<sup>[[6]](#references)</sup>

## Ouditeer-eerste-uitrol (aanbeveel: ~30 dae)

1. Aktiveer LDAP-koppelvlakdiagnostiek op elke DC om ongetekende binds aan te teken (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Stel DC GPO `LDAP server channel binding token requirements` = **When Supported** vir gedeeltelike CBT-afdwinging en telemetrie; bevestig eers versoenbaarheid met legacy-kliënte.<sup>[[1]](#references)</sup>
3. Monitor Directory Service-gebeurtenisse:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – ongetekende/ongetekende-toelaat-binds (nie aan die ondertekeningsvereistes voldoen nie).
   - **3074/3075** – LDAPS-binds wat sou misluk of CBT sou weglaat (vereis KB4520412 op 2019/2022 en stap 2 hierbo).
4. Dwing af in afsonderlike veranderinge:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC's).
   - `LDAP client signing requirements` = **Require signing** (kliënte).
   - `LDAP server signing requirements` = **Require signing** (DC's) **of** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP-kanaalbinding en LDAP-ondertekening](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP-kanaalbinding- en ondertekeningsvereistes](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP-relayversagingsopdatering](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP-ondertekening gedeaktiveer → Kerberos-relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Onderteken, verseël en relayeer, NTLM-styl](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo-bewys-van-konsep](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Windows Server-vrystellingsinligting](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
