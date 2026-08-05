# macOS-stelseluitbreidings

{{#include ../../../banners/hacktricks-training.md}}

## Stelseluitbreidings / Endpoint Security Framework

Anders as Kernel Extensions, **stelseluitbreidings loop in gebruikersruimte** eerder as kernruimte, wat die risiko van ’n stelselongeluk weens uitbreidingwanfunksionering verminder.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Daar is drie tipes stelseluitbreidings: **DriverKit** Extensions, **Network** Extensions en **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit is ’n vervanging vir kernel extensions wat **hardewareondersteuning verskaf**. Dit laat toestelbestuurders (soos USB-, Serial-, NIC- en HID-bestuurders) in gebruikersruimte eerder as kernruimte loop. Die DriverKit-raamwerk sluit **gebruikersruimteweergawes van sekere I/O Kit-klasse** in, en die kern stuur normale I/O Kit-gebeurtenisse na gebruikersruimte aan, wat ’n veiliger omgewing bied waarin hierdie bestuurders kan loop.<sup>[2]</sup>

### **Network Extensions**

Network Extensions bied die vermoë om netwerkgedrag aan te pas. Daar is verskeie tipes Network Extensions:

- **App Proxy**: Dit word gebruik om ’n VPN-kliënt te skep wat ’n vloeioriëntasie-gebaseerde, pasgemaakte VPN-protokol implementeer. Dit beteken dat dit netwerkverkeer op grond van verbindings (of vloei) eerder as individuele pakkette hanteer.
- **Packet Tunnel**: Dit word gebruik om ’n VPN-kliënt te skep wat ’n pakketgeoriënteerde, pasgemaakte VPN-protokol implementeer. Dit beteken dat dit netwerkverkeer op grond van individuele pakkette hanteer.
- **Filter Data**: Dit word gebruik om netwerk-"vloei" te filter. Dit kan netwerkdata op vloeivlak monitor of wysig.
- **Filter Packet**: Dit word gebruik om individuele netwerkpakkette te filter. Dit kan netwerkdata op pakketvlak monitor of wysig.
- **DNS Proxy**: Dit word gebruik om ’n pasgemaakte DNS-verskaffer te skep. Dit kan gebruik word om DNS-versoeke en -antwoorde te monitor of te wysig.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security is ’n raamwerk wat deur Apple in macOS verskaf word en ’n stel API’s vir stelselsekuriteit bied. Dit is bedoel vir gebruik deur **sekuriteitsverskaffers en ontwikkelaars om produkte te bou wat stelselaktiwiteit kan monitor en beheer** om kwaadwillige aktiwiteit te identifiseer en daarteen te beskerm.

Hierdie raamwerk verskaf ’n **versameling API’s om stelselaktiwiteit te monitor en te beheer**, soos prosesuitvoerings, lêerstelselgebeurtenisse, netwerk- en kerng gebeurtenisse.

Die kern van hierdie raamwerk word in die kern geïmplementeer, as ’n Kernel Extension (KEXT) geleë by **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Hierdie KEXT bestaan uit verskeie belangrike komponente:

- **EndpointSecurityDriver**: Dit tree op as die "toegangspunt" vir die kernel extension. Dit is die hoofinteraksiepunt tussen die OS en die Endpoint Security-raamwerk.
- **EndpointSecurityEventManager**: Hierdie komponent is verantwoordelik vir die implementering van kernhooks. Kernhooks laat die raamwerk toe om stelselgebeurtenisse te monitor deur stelseloproepe te onderskep.
- **EndpointSecurityClientManager**: Dit bestuur die kommunikasie met gebruikersruimte-kliënte en hou rekord van watter kliënte verbind is en gebeurteniskennisgewings moet ontvang.
- **EndpointSecurityMessageManager**: Dit stuur boodskappe en gebeurteniskennisgewings na gebruikersruimte-kliënte.

Die gebeurtenisse wat die Endpoint Security-raamwerk kan monitor, word in die volgende kategorieë ingedeel:

- Lêergebeurtenisse
- Prosesgebeurtenisse
- Socket-gebeurtenisse
- Kerng gebeurtenisse (soos die laai/ontlaai van ’n kernel extension of die oopmaak van ’n I/O Kit-toestel)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Gebruikersruimte-kommunikasie** met die Endpoint Security-raamwerk vind deur die IOUserClient-klas plaas. Twee verskillende subklasse word gebruik, afhangend van die tipe oproeper:

- **EndpointSecurityDriverClient**: Dit vereis die `com.apple.private.endpoint-security.manager`-entitlement, wat slegs deur die stelselproses `endpointsecurityd` besit word.
- **EndpointSecurityExternalClient**: Dit vereis die `com.apple.developer.endpoint-security.client`-entitlement. Dit sal tipies deur derdeparty-sekuriteitsagteware gebruik word wat met die Endpoint Security-raamwerk moet kommunikeer.<sup>[1]</sup>

Die Endpoint Security Extensions:**`libEndpointSecurity.dylib`** is die C-biblioteek wat stelseluitbreidings gebruik om met die kern te kommunikeer. Hierdie biblioteek gebruik die I/O Kit (`IOKit`) om met die Endpoint Security KEXT te kommunikeer.<sup>[2]</sup>

**`endpointsecurityd`** is ’n belangrike stelseldaemon wat betrokke is by die bestuur en bekendstelling van endpoint security-stelseluitbreidings, veral tydens die vroeë selflaaiproses. **Slegs stelseluitbreidings** met **`NSEndpointSecurityEarlyBoot`** in hul `Info.plist`-lêer gemerk is, ontvang hierdie vroeë selflaaibehandeling.<sup>[2]</sup>

Nog ’n stelseldaemon, **`sysextd`**, **valideer stelseluitbreidings** en skuif hulle na die korrekte stelselliggings. Dit vra dan die relevante daemon om die uitbreiding te laai. Die **`SystemExtensions.framework`** is verantwoordelik vir die aktivering en deaktivering van stelseluitbreidings.<sup>[2]</sup>

## Om ESF te omseil

ESF word gebruik deur sekuriteitsnutsmiddels wat sal probeer om ’n red teamer op te spoor, dus klink enige inligting oor hoe dit vermy kan word interessant.

### CVE-2021-30965

Die probleem is dat die sekuriteitstoepassing **Full Disk Access-permissies** moet hê. As ’n aanvaller dit dus kon verwyder, kon hy verhoed dat die sagteware loop:<sup>[3]</sup>
```bash
tccutil reset All
```
Vir **meer inligting** oor hierdie bypass en verwante gevalle, kyk na die praatjie [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Uiteindelik is dit reggestel deur die nuwe toestemming **`kTCCServiceEndpointSecurityClient`** toe te ken aan die security-app wat deur **`tccd`** bestuur word, sodat `tccutil` nie sy toestemmings sal uitvee en verhoed dat dit loop nie.<sup>[3]</sup>

## Verwysings

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
