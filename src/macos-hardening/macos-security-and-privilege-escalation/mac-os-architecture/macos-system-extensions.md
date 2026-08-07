# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Anders as Kernel Extensions, **System Extensions loop in user space** in plaas van kernel space, wat die risiko van ’n stelselongeluk weens ’n fout in die extension verminder.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Daar is drie tipes system extensions: **DriverKit** Extensions, **Network** Extensions, en **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit is ’n plaasvervanger vir kernel extensions wat **hardeware-ondersteuning verskaf**. Dit laat device drivers (soos USB-, Serial-, NIC- en HID-drivers) in user space eerder as kernel space loop. Die DriverKit framework sluit **user space-weergawes van sekere I/O Kit-klasse** in, en die kernel stuur normale I/O Kit-events na user space aan, wat ’n veiliger omgewing bied waarin hierdie drivers kan loop.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions bied die vermoë om netwerkgedrag aan te pas. Daar is verskeie tipes Network Extensions:

- **App Proxy**: Dit word gebruik om ’n VPN-client te skep wat ’n flow-georiënteerde, pasgemaakte VPN-protokol implementeer. Dit beteken dat dit netwerkverkeer op grond van verbindings (of flows) hanteer eerder as individuele packets.
- **Packet Tunnel**: Dit word gebruik om ’n VPN-client te skep wat ’n packet-georiënteerde, pasgemaakte VPN-protokol implementeer. Dit beteken dat dit netwerkverkeer op grond van individuele packets hanteer.
- **Filter Data**: Dit word gebruik om netwerk-“flows” te filter. Dit kan netwerkdata op flow-vlak monitor of wysig.
- **Filter Packet**: Dit word gebruik om individuele netwerk-packets te filter. Dit kan netwerkdata op packet-vlak monitor of wysig.
- **DNS Proxy**: Dit word gebruik om ’n pasgemaakte DNS-provider te skep. Dit kan gebruik word om DNS-requests en -responses te monitor of wysig.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security is ’n framework wat deur Apple in macOS verskaf word en wat ’n stel APIs vir stelselsekuriteit bied. Dit is bedoel vir gebruik deur **sekuriteitsverskaffers en developers om produkte te bou wat stelselaktiwiteit kan monitor en beheer** om kwaadwillige aktiwiteit te identifiseer en daarteen te beskerm.

Hierdie framework verskaf ’n **versameling APIs om stelselaktiwiteit te monitor en beheer**, soos prosesuitvoerings, lêerstelsel-events, netwerk- en kernel-events.

Die kern van hierdie framework word in die kernel geïmplementeer, as ’n Kernel Extension (KEXT) wat by **`/System/Library/Extensions/EndpointSecurity.kext`** geleë is.<sup>[[2]](#references)</sup> Hierdie KEXT bestaan uit verskeie sleutelkomponente:

- **EndpointSecurityDriver**: Dit tree op as die “entry point” vir die kernel extension. Dit is die hoofinteraksiepunt tussen die OS en die Endpoint Security framework.
- **EndpointSecurityEventManager**: Hierdie komponent is verantwoordelik vir die implementering van kernel hooks. Kernel hooks laat die framework toe om stelsel-events te monitor deur system calls te onderskep.
- **EndpointSecurityClientManager**: Dit bestuur die kommunikasie met user space-clients, hou rekord van watter clients gekoppel is en gebeurteniskennisgewings moet ontvang.
- **EndpointSecurityMessageManager**: Dit stuur boodskappe en gebeurteniskennisgewings na user space-clients.

Die events wat die Endpoint Security framework kan monitor, word in die volgende kategorieë ingedeel:

- File events
- Process events
- Socket events
- Kernel events (soos die laai/ontlaai van ’n kernel extension of die opening van ’n I/O Kit-device)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**User-space-kommunikasie** met die Endpoint Security framework vind deur die IOUserClient-klas plaas. Twee verskillende subklasse word gebruik, afhangend van die tipe caller:

- **EndpointSecurityDriverClient**: Dit vereis die `com.apple.private.endpoint-security.manager` entitlement, wat slegs deur die stelselproses `endpointsecurityd` besit word.
- **EndpointSecurityExternalClient**: Dit vereis die `com.apple.developer.endpoint-security.client` entitlement. Dit sal tipies gebruik word deur third-party security software wat met die Endpoint Security framework moet interaksie hê.<sup>[[1]](#references)</sup>

Die Endpoint Security Extensions:**`libEndpointSecurity.dylib`** is die C-library wat system extensions gebruik om met die kernel te kommunikeer. Hierdie library gebruik die I/O Kit (`IOKit`) om met die Endpoint Security KEXT te kommunikeer.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** is ’n belangrike stelseldaemon wat betrokke is by die bestuur en launch van endpoint security system extensions, veral tydens die vroeë bootproses. **Slegs system extensions** wat met **`NSEndpointSecurityEarlyBoot`** in hul `Info.plist`-lêer gemerk is, ontvang hierdie vroeë-boot-behandeling.<sup>[[2]](#references)</sup>

Nog ’n stelseldaemon, **`sysextd`**, **valideer system extensions** en skuif hulle na die korrekte stelselliggings. Dit vra dan die relevante daemon om die extension te laai. Die **`SystemExtensions.framework`** is verantwoordelik vir die aktivering en deaktivering van system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF word gebruik deur security tools wat sal probeer om ’n red teamer op te spoor, dus klink enige inligting oor hoe dit vermy kan word interessant.

### CVE-2021-30965

Die probleem is dat die security application **Full Disk Access permissions** moet hê. As ’n attacker dit dus kon verwyder, sou hy kon voorkom dat die software loop:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Vir **meer inligting** oor hierdie bypass en verwante bypasses, kyk na die praatjie [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup>

Uiteindelik is dit reggestel deur die nuwe toestemming **`kTCCServiceEndpointSecurityClient`** aan die security-app te gee wat deur **`tccd`** bestuur word, sodat **`tccutil`** nie sy toestemmings sal uitvee en verhoed dat dit loop nie.<sup>[[3]](#references)</sup>

## Verwysings

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
