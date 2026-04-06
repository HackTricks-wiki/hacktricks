# macOS Gevaarlike Entitlements & TCC toestemmings

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Let wel dat entitlements wat begin met **`com.apple`** nie beskikbaar is vir derdepartye nie; slegs Apple kan dit toeken... Of as jy 'n enterprise-sertifikaat gebruik kan jy eintlik jou eie entitlements wat begin met **`com.apple`** skep en sodoende beskermings op grond hiervan omseil.

## Hoog

### `com.apple.rootless.install.heritable`

Die entitlement **`com.apple.rootless.install.heritable`** laat toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die entitlement **`com.apple.rootless.install`** laat toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Hierdie entitlement laat toe om die **task port vir enige** proses te kry, behalwe die kernel. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Hierdie entitlement laat ander prosesse met die **`com.apple.security.cs.debugger`** entitlement toe om die task port van die proses wat deur die binary met hierdie entitlement uitgevoer word te kry en **kode daarin te injekteer**. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps met die Debugging Tool Entitlement kan `task_for_pid()` aanroep om 'n geldige task port te kry vir nie-ondertekende en derdeparty-apps met die `Get Task Allow` entitlement op `true`. Tog, selfs met die debugging tool entitlement, kan 'n debugger **nie die task ports kry** van prosesse wat **nie die `Get Task Allow` entitlement het nie**, en wat dus deur System Integrity Protection beskerm word. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Hierdie entitlement laat toe om **frameworks, plug-ins, of libraries te laai sonder dat hulle deur Apple of met dieselfde Team ID as die hoof-uitvoerbare lêer onderteken is**, so 'n aanvaller kan 'n arbitraire library-laai misbruik om kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Hierdie entitlement is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`**, maar **in plaas daarvan** om die library-validasie direk uit te skakel, laat dit die proses toe om 'n `csops` stelselskonsultasie aan te roep om dit uit te skakel\.\
Kyk [**hier vir meer inligting**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie entitlement laat toe om **DYLD environment variables** te gebruik wat benut kan word om libraries en kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), laat hierdie entitlements toe om die **TCC** databasis te **wysig**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Hierdie entitlements laat toe om **sagteware te installeer sonder om die gebruiker om toestemming te vra**, wat nuttig kan wees vir 'n **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement benodig om die **kernel te vra om 'n kernel extension te laai**.

### **`com.apple.private.icloud-account-access`**

Met die entitlement **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC-diens te kommunikeer wat **iCloud tokens** sal verskaf.

**iMovie** en **Garageband** het hierdie entitlement gehad.

Vir meer **inligting** oor die exploit om **iCloud tokens** van daardie entitlement te kry, kyk die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit toelaat om te doen nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) word genoem dat dit gebruik kan word om die SSV-beskermde inhoud na 'n herbegin by te werk. As jy weet hoe, stuur asseblief 'n PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) word genoem dat dit gebruik kan word om die SSV-beskermde inhoud na 'n herbegin by te werk. As jy weet hoe, stuur asseblief 'n PR!

### `keychain-access-groups`

Hierdie entitlement lys die **keychain**-groepe waarna die toepassing toegang het:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Gee **Volledige skyftoegang**-toestemmings, een van die hoogste TCC-toestemmings wat jy kan hê.

### **`kTCCServiceAppleEvents`**

Laat die app toe om gebeurtenisse na ander toepassings te stuur wat algemeen gebruik word vir **outomatisering van take**. Deur ander apps te beheer, kan dit misbruik maak van die toestemmings wat aan daardie ander apps gegee is.

Soos om hulle die gebruiker se wagwoord te laat vra:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Of om hulle te laat uitvoer **arbitrêre aksies**.

### **`kTCCServiceEndpointSecurityClient`**

Laat, onder andere toestemmings, toe om die **gebruikers se TCC-databasis te skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`**-attribuut van 'n gebruiker te **verander**, wat sy tuismap-pad verander en dus toelaat om die TCC te **omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne 'n app-bundel (binne app.app) te wysig, wat standaard **nie toegelaat** is.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om na te gaan wie hierdie toegang het in _System Settings_ > _Privacy & Security_ > _App Management_.

### `kTCCServiceAccessibility`

Die proses sal die macOS-toeganklikheidsfunksies kan **misbruik**, wat beteken dat hy byvoorbeeld toetsaanslae kan stuur. Hy kan dus toegang versoek om 'n app soos Finder te beheer en die dialoog met hierdie toestemming goedkeur.

## Trustcache/CDhash related entitlements

Daar is 'n paar entitlements wat gebruik kan word om Trustcache/CDhash-beskerming te omseil, wat verhoed dat afgegradeerde weergawes van Apple-binarisse uitgevoer word.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie entitlement laat toe om **geheue te skep wat skryfbaar en uitvoerbaar is** deur die `MAP_JIT` vlag aan die `mmap()` stelselfunksie te gee. Kyk [**hier** vir meer inligting](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie entitlement laat toe om C-kode te **oorskryf of te patch**, die lank verouderde **`NSCreateObjectFileImageFromMemory`** te gebruik (wat fundamenteel onveilig is), of die **DVDPlayback** raamwerk te gebruik. Kyk [**hier** vir meer inligting](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Deur hierdie entitlement in te sluit stel jy jou app bloot aan algemene kwesbaarhede in geheue-onveilige programmeertale. Oorweeg sorgvuldig of jou app hierdie uitsondering benodig.

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie entitlement laat toe om gedeeltes van sy eie uitvoerbare lêers op skyf te **wysig** om 'n geforseerde uitgang moontlik te maak. Kyk [**hier** vir meer inligting](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Die Disable Executable Memory Protection Entitlement is 'n uiterste entitlement wat 'n fundamentele sekuriteitsbeskerming van jou app verwyder, wat dit moontlik maak vir 'n aanvaller om jou app se uitvoerbare kode te herskryf sonder opsporing. Kies indien moontlik vir nouer entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie entitlement laat toe om 'n nullfs-lêerstelsel te mount (standaard verbode). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogpost word hierdie TCC-toestemming gewoonlik in die vorm gevind:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die proses toe om **vir alle TCC-toestemmings te vra**.

### **`kTCCServicePostEvent`**

Laat toe om **sintetiese sleutelbord- en muisgebeurtenisse in te spuit** stelselwyd via `CGEventPost()`. 'n Proses met hierdie toestemming kan toetsaanslae, muisklikke en blaaisgebeurtenisse in enige toepassing simuleer — wat effektief **afstandsbeheer** van die lessenaar verskaf.

Dit is veral gevaarlik in kombinasie met `kTCCServiceAccessibility` of `kTCCServiceListenEvent`, aangesien dit beide insette kan lees EN insette kan inspuit.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Laat toe om **alle sleutelbord- en muisgebeurtenisse stelselwyd te onderskep** (input monitoring / keylogging). 'n Proses kan 'n `CGEventTap` registreer om elke toetsaanslag in enige toepassing vas te vang, insluitend wagwoorde, kredietkaartnommers, en privaat boodskappe.

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Laat toe om die **skermbuffer te lees** — skermkiekies te neem en skermvideo van enige toepassing op te neem, insluitend veilige teksvelde. In kombinasie met OCR kan dit wagwoorde en sensitiewe data vanaf die skerm outomaties uittrek.

> [!WARNING]
> Beginning with macOS Sonoma, screen capture shows a persistent menu bar indicator. On older versions, screen recording can be completely silent.

### **`kTCCServiceCamera`**

Laat toe om **foto's en video** te maak vanaf die ingeboude kamera of gekoppelde USB-kameras. Code injection in 'n camera-entitled binary maak stil visuele toesig moontlik.

### **`kTCCServiceMicrophone`**

Laat toe om **audio op te neem** vanaf alle invoertoestelle. Background daemons with mic access bied volgehoue omgewings-audio-toesig sonder 'n sigbare toepassingsvenster.

### **`kTCCServiceLocation`**

Laat toe om die toestel se **fisiese ligging** te navraag via Wi‑Fi-triangulasie of Bluetooth beacons. Deurlopende monitering openbaar tuis/werk-adresse, reispatrone, en daaglikse roetines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Toegang tot **Contacts** (names, emails, phones — useful for spear-phishing), **Calendar** (meeting schedules, attendee lists), en **Photos** (persoonlike foto's, skermkiekies wat moontlik kredensiale of ligging-metadata bevat).

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** verswak die App Sandbox deur kommunikasie met stelselwye Mach/XPC services toe te laat wat die sandbox normaalweg blokkeer. Dit is die **primary sandbox escape primitive** — 'n gekompromitteerde sandboxed app kan mach-lookup exceptions gebruik om bevoorregte daemons te bereik en hul XPC interfaces uit te buit.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Vir 'n gedetailleerde exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, sien:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

DriverKit entitlements laat user-space driver binaries direk met die kernel kommunikeer via IOKit interfaces. DriverKit binaries bestuur hardeware: USB, Thunderbolt, PCIe, HID devices, audio en networking.

Die kompromittering van 'n DriverKit binary maak die volgende moontlik:
- **Kernel attack surface** via malformed `IOConnectCallMethod` calls
- **USB device spoofing** (emulate keyboard for HID injection)
- **DMA attacks** through PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Vir gedetailleerde IOKit/DriverKit exploitation, sien:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
