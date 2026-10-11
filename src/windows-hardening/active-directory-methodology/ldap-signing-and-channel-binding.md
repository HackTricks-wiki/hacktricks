# Versterking van LDAP Signing en Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit belangrik is

LDAP relay/MITM-aanvalle stuur verifikasie aan ’n domeinbeheerder deur om ’n geverifieerde LDAP-konteks te verkry. Twee verwante kontroles beperk hierdie paaie:

- **LDAP channel binding (CBT)** koppel toepaslike verifikasie aan die TLS-bedienersertifikaat/-kanaal wat deur LDAPS gebruik word, wat cross-channel relay bemoeilik.
- **LDAP signing** vereis integriteitsbeskerming vir SASL LDAP-binds. Dit voeg nie vertroulikheid by nie; gebruik TLS wanneer LDAP-inhoud ook enkripsie nodig het.<sup>[[2]](#references)</sup>

**Vinnige houdingskontrole**: nutsgoed soos `netexec ldap <dc> -u user -p pass` rapporteer die waargenome signing- en channel-binding-beleid. `(signing:None)` en `(channel binding:Never)` dui op ontbrekende kontroles, maar ’n suksesvolle relay hang steeds af van die vasgelegde verifikasietipe, EPA-gedrag, rekeningvoorregte, teikenprotokol en relay-beskermings. Wanneer die gerelayde identiteit die nodige regte het, kan nutsgoed soos KrbRelayUp `msDS-AllowedToActOnBehalfOfOtherIdentity` skryf, resource-based constrained delegation (RBCD) instel en die gevolglike delegasieroete gebruik om ’n bevoorregte identiteit na te boots.<sup>[[4]](#references)</sup>

**Server 2025 DCs** stel ’n nuwe GPO (**LDAP server signing requirements Enforcement**) bekend wat standaard op **Require Signing** ingestel is wanneer dit **Not Configured** gelaat word. Om afdwinging te vermy, moet jy daardie beleid uitdruklik op **Disabled** stel.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (slegs LDAPS)

- **Vereistes**:
  - Die CVE-2017-8563-pleister (2017) voeg ondersteuning vir Extended Protection for Authentication by.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) voeg LDAPS CBT-“what-if”-telemetrie by.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (standaard, geen CBT)
  - `When Supported` (gedeeltelike afdwinging: CBT-bekwame kliënte moet ’n geldige token verskaf; kliënte sonder CBT-ondersteuning kan steeds bind, en ouditgebeurtenisse word gegenereer)
  - `Always` (afdwinging: verwerp LDAPS-binds sonder ’n geldige CBT)<sup>[[1]](#references)</sup>
- **Oudit**: stel **When Supported** in om die volgende te wys:
  - **3074** – LDAPS-bind sou CBT-validering misluk het indien dit afgedwing is.
  - **3075** – LDAPS-bind het CBT-data weggelaat en sou verwerp gewees het indien dit afgedwing is.
  - (Gebeurtenis **3039** dui steeds op CBT-mislukkings in ouer builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Afdwinging**: stel **Always** in sodra LDAPS-kliënte CBTs stuur; dit is slegs effektief op **LDAPS** (nie rou 389 nie).<sup>[[1]](#references)</sup>

`When Supported` is nie slegs vir ouditering nie: dit valideer CBT vir bekwame kliënte terwyl kliënte sonder CBT-ondersteuning toegelaat word. Die [Microsoft-beleidsverwysing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) beskryf die verstekwaardes wat van die weergawe afhang. LDAP signing is van toepassing op relevante binds op LDAP/389; channel binding is van toepassing op TLS-beskermde LDAP-verifikasie.


## LDAP Signing

- **Kliënt-GPO**: `Network security: LDAP client signing requirements` = `Require signing` (teenoor die moderne Windows-verstekwaarde `Negotiate signing`).<sup>[[1]](#references)</sup>
- **DC-GPO**:
  - Ouderwets: `Domain controller: LDAP server signing requirements` = `Require signing` (verstekwaarde is `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: laat die ou beleid op `None` en stel `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = by verstek afgedwing; stel `Disabled` in om dit te vermy).<sup>[[1]](#references)</sup>
- **Verenigbaarheid**: Maak ’n inventaris van nie-Windows-toestelle en toepassings wat simple binds of ongetekende SASL-binds gebruik. Microsoft dokumenteer ondersteuning op Windows-weergawes wat steeds onderhou word; stellings oor verenigbaarheid met ou kliënte moet teen die werklike kliëntstapel nagegaan word, eerder as om dit tot ’n XP-weergawedrempel te beperk.<sup>[[2]](#references)</sup>

## Oudit-eerste ontplooiing (aanbevole tydperk: ~30 dae)

1. Aktiveer LDAP-koppelvlakdiagnostiek op elke DC om ongetekende binds aan te teken (Gebeurtenis **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Stel DC GPO `LDAP server channel binding token requirements` = **When Supported** vir gedeeltelike CBT-afdwinging en telemetrie; bevestig eers versoenbaarheid met legacy-kliënte.<sup>[[1]](#references)</sup>
3. Monitor Directory Service-gebeurtenisse:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow binds (nie-voldoenend aan signing-vereistes).
   - **3074/3075** – LDAPS binds wat sou faal of CBT sou weglaat (vereis KB4520412 op 2019/2022 en stap 2 hierbo).
4. Dwing af in afsonderlike veranderings:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (kliënte).
   - `LDAP server signing requirements` = **Require signing** (DCs) **of** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding en LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding- en signing-vereistes](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay-versagingsopdatering](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing gedeaktiveer → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
