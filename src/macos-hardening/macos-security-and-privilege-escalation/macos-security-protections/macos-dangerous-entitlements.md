# macOS Gevaarlike Toestemmings & TCC regte

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Let daarop dat toestemmings wat begin met **`com.apple`** nie beskikbaar is vir derde partye nie, slegs Apple kan dit toeken.

## Hoog

### `com.apple.rootless.install.heritable`

Die toestemming **`com.apple.rootless.install.heritable`** maak dit moontlik om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die toestemming **`com.apple.rootless.install`** maak dit moontlik om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (voorheen genoem `task_for_pid-allow`)**

Hierdie toestemming maak dit moontlik om die **taakpoort vir enige** proses te verkry, behalwe die kernel. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Hierdie toestemming maak dit moontlik vir ander prosesse met die **`com.apple.security.cs.debugger`** toestemming om die taakpoort van die proses wat deur die binêre met hierdie toestemming uitgevoer word, te verkry en **kode daarop in te spuit**. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Toepassings met die Debugging Tool Toestemming kan `task_for_pid()` aanroep om 'n geldige taakpoort vir ongetekende en derdeparty toepassings met die `Get Task Allow` toestemming wat op `true` gestel is, te verkry. Maar, selfs met die debugging tool toestemming, kan 'n debugger **nie die taakpoorte** van prosesse wat **nie die `Get Task Allow` toestemming het nie**, en wat dus deur Stelselintegriteitbeskerming beskerm word, verkry nie. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Hierdie toestemming maak dit moontlik om **raamwerke, plug-ins, of biblioteke te laai sonder om of deur Apple geteken te wees of met dieselfde Span-ID** as die hoof uitvoerbare, sodat 'n aanvaller sommige arbitrêre biblioteeklaai kan misbruik om kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Hierdie toestemming is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`** maar **in plaas daarvan** om **direk** biblioteekvalidasie te deaktiveer, maak dit dit moontlik vir die proses om **'n `csops` stelselaanroep te doen om dit te deaktiveer**.\
Kyk [**hier vir meer inligting**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie toestemming maak dit moontlik om **DYLD omgewing veranderlikes** te gebruik wat gebruik kan word om biblioteke en kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` of `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), maak hierdie toestemmings dit moontlik om die **TCC** databasis te **wysig**.

### **`system.install.apple-software`** en **`system.install.apple-software.standar-user`**

Hierdie toestemmings maak dit moontlik om **programmatuur te installeer sonder om toestemming** van die gebruiker te vra, wat nuttig kan wees vir 'n **privilege escalasie**.

### `com.apple.private.security.kext-management`

Toestemming wat benodig word om die **kernel te vra om 'n kernuitbreiding te laai**.

### **`com.apple.private.icloud-account-access`**

Die toestemming **`com.apple.private.icloud-account-access`** maak dit moontlik om te kommunikeer met die **`com.apple.iCloudHelper`** XPC diens wat **iCloud tokens** sal **verskaf**.

**iMovie** en **Garageband** het hierdie toestemming gehad.

Vir meer **inligting** oor die uitbuiting om **icloud tokens** van daardie toestemming te verkry, kyk die praatjie: [**#OBTS v5.0: "Wat op jou Mac gebeur, bly op Apple se iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit toelaat om te doen nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud na 'n herlaai op te dateer. As jy weet hoe, stuur 'n PR asseblief!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud na 'n herlaai op te dateer. As jy weet hoe, stuur 'n PR asseblief!

### `keychain-access-groups`

Hierdie toestemming lys **keychain** groepe waartoe die toepassing toegang het:
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

Gee **Volledige Skyf Toegang** regte, een van die TCC hoogste regte wat jy kan hê.

### **`kTCCServiceAppleEvents`**

Laat die app toe om gebeurtenisse na ander toepassings te stuur wat algemeen gebruik word vir **outomatisering van take**. Deur ander toepassings te beheer, kan dit die regte wat aan hierdie ander toepassings gegee is, misbruik. 

Soos om hulle te laat vra vir die gebruiker se wagwoord:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Of om hulle **arbitraire aksies** te laat uitvoer.

### **`kTCCServiceEndpointSecurityClient`**

Laat, onder andere toestemmings, toe om die **gebruikers TCC-databasis** te **skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`** attribuut van 'n gebruiker te **verander** wat sy tuisgids pad verander en dus toelaat om **TCC te omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne toepassingsbundels (binne app.app) te wysig, wat **standaard verbied is**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om te kyk wie hierdie toegang het in _Stelselsinstellings_ > _Privaatheid & Sekuriteit_ > _Toepassingbestuur._

### `kTCCServiceAccessibility`

Die proses sal in staat wees om die **macOS toeganklikheidskenmerke** te **misbruik**, wat beteken dat hy byvoorbeeld in staat sal wees om sleuteldrukke te druk. SO hy kan toegang vra om 'n toepassing soos Finder te beheer en die dialoog met hierdie toestemming goed te keur.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie reg laat toe om **geheue te skep wat skryfbaar en uitvoerbaar is** deur die `MAP_JIT` vlag aan die `mmap()` stelselfunksie deur te gee. Kyk [**hierdie vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie reg laat toe om **C-kode te oorskry of te patch**, gebruik die lank-deprecated **`NSCreateObjectFileImageFromMemory`** (wat fundamenteel onveilig is), of gebruik die **DVDPlayback** raamwerk. Kyk [**hierdie vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Om hierdie reg in te sluit stel jou toepassing bloot aan algemene kwesbaarhede in geheue-onveilige kode tale. Oorweeg sorgvuldig of jou toepassing hierdie uitsondering benodig.

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie reg laat toe om **afdelings van sy eie uitvoerbare lêers** op skyf te **wysig** om gedwonge uitgang te dwing. Kyk [**hierdie vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Die Uitskakeling van Uitvoerbare Geheuebeskerming Reg is 'n uiterste reg wat 'n fundamentele sekuriteitsbeskerming van jou toepassing verwyder, wat dit moontlik maak vir 'n aanvaller om jou toepassing se uitvoerbare kode sonder opsporing te herskryf. Verkies nouer regte indien moontlik.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie reg laat toe om 'n nullfs lêerstelsel te monteer (verbied deur standaard). Gereedskap: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogpos, word hierdie TCC toestemming gewoonlik in die vorm gevind:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die proses **vra vir al die TCC-toestemmings**.

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}
