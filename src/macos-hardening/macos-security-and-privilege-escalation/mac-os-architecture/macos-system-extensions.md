# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Tofauti na Kernel Extensions, **System Extensions zinafanya kazi katika nafasi ya mtumiaji** badala ya nafasi ya kernel, kupunguza hatari ya kuanguka kwa mfumo kutokana na kasoro ya kiendelezi.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Kuna aina tatu za system extensions: **DriverKit** Extensions, **Network** Extensions, na **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit ni mbadala wa kernel extensions ambazo **zinatoa msaada wa vifaa**. Inaruhusu madereva ya vifaa (kama vile USB, Serial, NIC, na HID drivers) kufanya kazi katika nafasi ya mtumiaji badala ya nafasi ya kernel. Mfumo wa DriverKit unajumuisha **toleo la nafasi ya mtumiaji la baadhi ya madarasa ya I/O Kit**, na kernel inapeleka matukio ya kawaida ya I/O Kit kwa nafasi ya mtumiaji, ikitoa mazingira salama kwa madereva haya kufanya kazi.

### **Network Extensions**

Network Extensions zinatoa uwezo wa kubadilisha tabia za mtandao. Kuna aina kadhaa za Network Extensions:

- **App Proxy**: Hii inatumika kwa kuunda mteja wa VPN ambao unatekeleza itifaki ya VPN iliyobinafsishwa inayotegemea mtiririko. Hii inamaanisha inashughulikia trafiki ya mtandao kulingana na muunganisho (au mitiririko) badala ya pakiti za kibinafsi.
- **Packet Tunnel**: Hii inatumika kwa kuunda mteja wa VPN ambao unatekeleza itifaki ya VPN iliyobinafsishwa inayotegemea pakiti. Hii inamaanisha inashughulikia trafiki ya mtandao kulingana na pakiti za kibinafsi.
- **Filter Data**: Hii inatumika kwa kuchuja "mitiririko" ya mtandao. Inaweza kufuatilia au kubadilisha data za mtandao katika kiwango cha mtiririko.
- **Filter Packet**: Hii inatumika kwa kuchuja pakiti za mtandao za kibinafsi. Inaweza kufuatilia au kubadilisha data za mtandao katika kiwango cha pakiti.
- **DNS Proxy**: Hii inatumika kwa kuunda mtoa huduma wa DNS uliobinafsishwa. Inaweza kutumika kufuatilia au kubadilisha maombi na majibu ya DNS.

## Endpoint Security Framework

Endpoint Security ni mfumo unaotolewa na Apple katika macOS ambao unatoa seti ya APIs kwa usalama wa mfumo. Unakusudiwa kutumiwa na **watoa huduma za usalama na waendelezaji kujenga bidhaa ambazo zinaweza kufuatilia na kudhibiti shughuli za mfumo** ili kubaini na kulinda dhidi ya shughuli mbaya.

Mfumo huu unatoa **mkusanyiko wa APIs za kufuatilia na kudhibiti shughuli za mfumo**, kama vile utekelezaji wa michakato, matukio ya mfumo wa faili, matukio ya mtandao na kernel.

Msingi wa mfumo huu umewekwa katika kernel, kama Kernel Extension (KEXT) iliyoko **`/System/Library/Extensions/EndpointSecurity.kext`**. KEXT hii inajumuisha vipengele kadhaa muhimu:

- **EndpointSecurityDriver**: Hii inafanya kazi kama "nukta ya kuingia" kwa kiendelezi cha kernel. Ni nukta kuu ya mwingiliano kati ya OS na mfumo wa Endpoint Security.
- **EndpointSecurityEventManager**: Kipengele hiki kinawajibika kwa kutekeleza nanga za kernel. Nanga za kernel zinaruhusu mfumo kufuatilia matukio ya mfumo kwa kukamata wito wa mfumo.
- **EndpointSecurityClientManager**: Hii inasimamia mawasiliano na wateja wa nafasi ya mtumiaji, ikifuatilia ni wateja gani wameunganishwa na wanahitaji kupokea arifa za matukio.
- **EndpointSecurityMessageManager**: Hii inatuma ujumbe na arifa za matukio kwa wateja wa nafasi ya mtumiaji.

Matukio ambayo mfumo wa Endpoint Security unaweza kufuatilia yanagawanywa katika:

- Matukio ya faili
- Matukio ya mchakato
- Matukio ya socket
- Matukio ya kernel (kama vile kupakia/kutoa kiendelezi cha kernel au kufungua kifaa cha I/O Kit)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Mawasiliano ya nafasi ya mtumiaji** na mfumo wa Endpoint Security hufanyika kupitia darasa la IOUserClient. Aina mbili tofauti za subclasses zinatumika, kulingana na aina ya mpiga simu:

- **EndpointSecurityDriverClient**: Hii inahitaji ruhusa ya `com.apple.private.endpoint-security.manager`, ambayo inashikiliwa tu na mchakato wa mfumo `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Hii inahitaji ruhusa ya `com.apple.developer.endpoint-security.client`. Hii kwa kawaida ingetumiwa na programu za usalama za wahusika wengine ambazo zinahitaji kuingiliana na mfumo wa Endpoint Security.

The Endpoint Security Extensions:**`libEndpointSecurity.dylib`** ni maktaba ya C ambayo system extensions hutumia kuwasiliana na kernel. Maktaba hii inatumia I/O Kit (`IOKit`) kuwasiliana na KEXT ya Endpoint Security.

**`endpointsecurityd`** ni daemon muhimu wa mfumo unaohusika na kusimamia na kuzindua system extensions za usalama wa mwisho, hasa wakati wa mchakato wa kuanzisha mapema. **Ni system extensions tu** zilizo na **`NSEndpointSecurityEarlyBoot`** katika faili yao ya `Info.plist` zinazopokea matibabu haya ya kuanzisha mapema.

Daemon nyingine ya mfumo, **`sysextd`**, **inasimamia system extensions** na kuhamasisha katika maeneo sahihi ya mfumo. Kisha inaomba daemon husika kupakia kiendelezi. **`SystemExtensions.framework`** inawajibika kwa kuanzisha na kuzima system extensions.

## Bypassing ESF

ESF inatumika na zana za usalama ambazo zitajaribu kugundua mchezaji wa red team, hivyo taarifa yoyote kuhusu jinsi hii inaweza kuepukwa inavutia.

### CVE-2021-30965

Jambo ni kwamba programu ya usalama inahitaji kuwa na **Ruhusa za Ufikiaji wa Disk Kamili**. Hivyo ikiwa mshambuliaji anaweza kuondoa hiyo, anaweza kuzuia programu hiyo isifanye kazi:
```bash
tccutil reset All
```
Kwa **maelezo zaidi** kuhusu hii bypass na zinazohusiana, angalia mazungumzo [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Mwishowe, hii ilirekebishwa kwa kutoa ruhusa mpya **`kTCCServiceEndpointSecurityClient`** kwa programu ya usalama inayosimamiwa na **`tccd`** ili `tccutil` isifute ruhusa zake na kuzuia kuendesha kwake.

## Marejeleo

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
