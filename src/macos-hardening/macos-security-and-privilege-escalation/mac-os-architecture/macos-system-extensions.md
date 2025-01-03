# macOS Stelselsuitbreidings

{{#include ../../../banners/hacktricks-training.md}}

## Stelselsuitbreidings / Eindpunt Sekuriteit Raamwerk

Verskil met Kernel Uitbreidings, **Stelselsuitbreidings loop in gebruikersruimte** eerder as in kernruimte, wat die risiko van 'n stelselfout as gevolg van 'n uitbreiding se wanfunksie verminder.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Daar is drie tipes stelselsuitbreidings: **DriverKit** Uitbreidings, **Netwerk** Uitbreidings, en **Eindpunt Sekuriteit** Uitbreidings.

### **DriverKit Uitbreidings**

DriverKit is 'n vervanging vir kernuitbreidings wat **hardewareondersteuning bied**. Dit laat toestel bestuurders (soos USB, Serial, NIC, en HID bestuurders) toe om in gebruikersruimte te loop eerder as in kernruimte. Die DriverKit raamwerk sluit **gebruikersruimte weergawes van sekere I/O Kit klasse** in, en die kern stuur normale I/O Kit gebeurtenisse na gebruikersruimte, wat 'n veiliger omgewing bied vir hierdie bestuurders om te loop.

### **Netwerk Uitbreidings**

Netwerk Uitbreidings bied die vermoë om netwerkgedrag aan te pas. Daar is verskeie tipes Netwerk Uitbreidings:

- **App Proxy**: Dit word gebruik om 'n VPN-klient te skep wat 'n vloei-georiënteerde, pasgemaakte VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer gebaseer op verbindings (of vloei) eerder as individuele pakkette.
- **Pakket Tunnel**: Dit word gebruik om 'n VPN-klient te skep wat 'n pakket-georiënteerde, pasgemaakte VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer gebaseer op individuele pakkette.
- **Filter Data**: Dit word gebruik om netwerk "vloei" te filter. Dit kan netwerkdata op vloei vlak monitor of wysig.
- **Filter Pakket**: Dit word gebruik om individuele netwerkpakkette te filter. Dit kan netwerkdata op pakketvlak monitor of wysig.
- **DNS Proxy**: Dit word gebruik om 'n pasgemaakte DNS-verskaffer te skep. Dit kan gebruik word om DNS versoeke en antwoorde te monitor of te wysig.

## Eindpunt Sekuriteit Raamwerk

Eindpunt Sekuriteit is 'n raamwerk wat deur Apple in macOS verskaf word wat 'n stel API's vir stelselsekuriteit bied. Dit is bedoel vir gebruik deur **sekuriteitsverskaffers en ontwikkelaars om produkte te bou wat stelselsaktiwiteit kan monitor en beheer** om kwaadwillige aktiwiteit te identifiseer en te beskerm.

Hierdie raamwerk bied 'n **versameling API's om stelselsaktiwiteit te monitor en te beheer**, soos prosesuitvoerings, lêerstelselsgebeurtenisse, netwerk- en kerngebeurtenisse.

Die kern van hierdie raamwerk is in die kern geïmplementeer, as 'n Kernel Uitbreiding (KEXT) geleë by **`/System/Library/Extensions/EndpointSecurity.kext`**. Hierdie KEXT bestaan uit verskeie sleutelkomponente:

- **EndpointSecurityDriver**: Dit dien as die "toegangspunt" vir die kernuitbreiding. Dit is die hoofpunt van interaksie tussen die OS en die Eindpunt Sekuriteit raamwerk.
- **EndpointSecurityEventManager**: Hierdie komponent is verantwoordelik vir die implementering van kernhake. Kernhake laat die raamwerk toe om stelselsgebeurtenisse te monitor deur stelselsoproepe te onderskep.
- **EndpointSecurityClientManager**: Dit bestuur die kommunikasie met gebruikersruimte kliënte, en hou dop watter kliënte gekoppel is en gebeurtenis kennisgewings moet ontvang.
- **EndpointSecurityMessageManager**: Dit stuur boodskappe en gebeurtenis kennisgewings na gebruikersruimte kliënte.

Die gebeurtenisse wat die Eindpunt Sekuriteit raamwerk kan monitor, is gekategoriseer in:

- Lêergebeurtenisse
- Prosesgebeurtenisse
- Sokketgebeurtenisse
- Kerngebeurtenisse (soos die laai/ontlaai van 'n kernuitbreiding of die opening van 'n I/O Kit toestel)

### Eindpunt Sekuriteit Raamwerk Argitektuur

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Gebruikersruimte kommunikasie** met die Eindpunt Sekuriteit raamwerk gebeur deur die IOUserClient klas. Twee verskillende subklasse word gebruik, afhangende van die tipe oproeper:

- **EndpointSecurityDriverClient**: Dit vereis die `com.apple.private.endpoint-security.manager` regte, wat slegs deur die stelselsproses `endpointsecurityd` besit word.
- **EndpointSecurityExternalClient**: Dit vereis die `com.apple.developer.endpoint-security.client` regte. Dit sou tipies gebruik word deur derdeparty sekuriteitsagteware wat met die Eindpunt Sekuriteit raamwerk moet interaksie hê.

Die Eindpunt Sekuriteit Uitbreidings:**`libEndpointSecurity.dylib`** is die C biblioteek wat stelselsuitbreidings gebruik om met die kern te kommunikeer. Hierdie biblioteek gebruik die I/O Kit (`IOKit`) om met die Eindpunt Sekuriteit KEXT te kommunikeer.

**`endpointsecurityd`** is 'n sleutel stelseldemon wat betrokke is by die bestuur en bekendstelling van eindpunt sekuriteit stelselsuitbreidings, veral tydens die vroeë opstartproses. **Slegs stelselsuitbreidings** gemerk met **`NSEndpointSecurityEarlyBoot`** in hul `Info.plist` lêer ontvang hierdie vroeë opstartbehandeling.

Nog 'n stelseldemon, **`sysextd`**, **valideer stelselsuitbreidings** en skuif hulle na die regte stelsellokasies. Dit vra dan die relevante demon om die uitbreiding te laai. Die **`SystemExtensions.framework`** is verantwoordelik vir die aktivering en deaktivering van stelselsuitbreidings.

## Omseiling van ESF

ESF word gebruik deur sekuriteitsinstrumente wat sal probeer om 'n rooi spanlid te ontdek, so enige inligting oor hoe dit vermy kan word klink interessant.

### CVE-2021-30965

Die ding is dat die sekuriteitsaansoek **Volledige Skyf Toegang regte** moet hê. So as 'n aanvaller dit kan verwyder, kan hy die sagteware verhinder om te loop:
```bash
tccutil reset All
```
Vir **meer inligting** oor hierdie omseiling en verwante, kyk na die praatjie [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Aan die einde is dit reggestel deur die nuwe toestemming **`kTCCServiceEndpointSecurityClient`** aan die sekuriteitsprogram wat deur **`tccd`** bestuur word te gee, sodat `tccutil` nie sy toestemmings sal skoonmaak nie, wat dit verhinder om te loop.

## Verwysings

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
