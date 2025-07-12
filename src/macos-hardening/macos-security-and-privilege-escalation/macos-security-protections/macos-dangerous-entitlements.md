# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Imajte na umu da entitlements koji počinju sa **`com.apple`** nisu dostupni trećim stranama, samo Apple ih može dodeliti.

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** omogućava **obići SIP**. Proverite [ovo za više informacija](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** omogućava **obići SIP**. Proverite [ovo za više informacija](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (ranije nazvan `task_for_pid-allow`)**

Ovaj entitlement omogućava dobijanje **task porta za bilo koji** proces, osim jezgra. Proverite [**ovo za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ovaj entitlement omogućava drugim procesima sa **`com.apple.security.cs.debugger`** entitlementom da dobiju task port procesa koji pokreće binarni fajl sa ovim entitlementom i **ubace kod u njega**. Proverite [**ovo za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacije sa entitlementom za Debugging Tool mogu pozvati `task_for_pid()` da dobiju validan task port za nesignirane i treće strane aplikacije sa `Get Task Allow` entitlementom postavljenim na `true`. Međutim, čak i sa entitlementom za debugging tool, debager **ne može dobiti task portove** procesa koji **nemaju `Get Task Allow` entitlement**, i koji su stoga zaštićeni System Integrity Protection. Proverite [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Ovaj entitlement omogućava **učitavanje frameworka, plug-inova ili biblioteka bez potrebe da budu potpisani od strane Apple-a ili potpisani sa istim Team ID** kao glavni izvršni fajl, tako da napadač može zloupotrebiti učitavanje neke proizvoljne biblioteke da ubaci kod. Proverite [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ovaj entitlement je vrlo sličan **`com.apple.security.cs.disable-library-validation`** ali **umesto** da **direktno onemogući** validaciju biblioteka, omogućava procesu da **pozove `csops` sistemski poziv da je onemogući**.\
Proverite [**ovo za više informacija**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Ovaj entitlement omogućava **korišćenje DYLD promenljivih okruženja** koje se mogu koristiti za ubacivanje biblioteka i koda. Proverite [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ili `com.apple.rootless.storage`.`TCC`

[**Prema ovom blogu**](https://objective-see.org/blog/blog_0x4C.html) **i** [**ovom blogu**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ovi entitlements omogućavaju **modifikaciju** **TCC** baze podataka.

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Ovi entitlements omogućavaju **instalaciju softvera bez traženja dozvola** od korisnika, što može biti korisno za **povećanje privilegija**.

### `com.apple.private.security.kext-management`

Entitlement potreban za traženje od **jezgra da učita kernel ekstenziju**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC servisom koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** su imali ovaj entitlement.

Za više **informacija** o eksploatu za **dobijanje iCloud tokena** iz tog entitlementa proverite predavanje: [**#OBTS v5.0: "Šta se dešava na vašem Mac-u, ostaje na Apple-ovom iCloud-u?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ne znam šta ovo omogućava

### `com.apple.private.apfs.revert-to-snapshot`

TODO: U [**ovoj izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se pominje da bi ovo moglo biti korišćeno za** ažuriranje SSV-zaštićenog sadržaja nakon ponovnog pokretanja. Ako znate kako, pošaljite PR, molim vas!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: U [**ovoj izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se pominje da bi ovo moglo biti korišćeno za** ažuriranje SSV-zaštićenog sadržaja nakon ponovnog pokretanja. Ako znate kako, pošaljite PR, molim vas!

### `keychain-access-groups`

Ovaj entitlement lista **keychain** grupa kojima aplikacija ima pristup:
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

Daje **Full Disk Access** dozvole, jedne od najviših TCC dozvola koje možete imati.

### **`kTCCServiceAppleEvents`**

Omogućava aplikaciji da šalje događaje drugim aplikacijama koje se obično koriste za **automatsko izvršavanje zadataka**. Kontrolisanjem drugih aplikacija, može zloupotrebiti dozvole koje su dodeljene tim drugim aplikacijama.

Na primer, može ih naterati da traže od korisnika njegovu lozinku:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ili da ih naterate da izvrše **arbitrarne radnje**.

### **`kTCCServiceEndpointSecurityClient`**

Omogućava, između ostalog, da **piše u TCC bazu podataka korisnika**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Omogućava da **promeni** **`NFSHomeDirectory`** atribut korisnika koji menja putanju do svoje početne fascikle i tako omogućava **obići TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Omogućava modifikaciju fajlova unutar aplikacionog paketa (unutar app.app), što je **podrazumevano zabranjeno**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Moguće je proveriti ko ima ovaj pristup u _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Proces će moći da **zloupotrebi macOS funkcije pristupa**, što znači da će, na primer, moći da pritisne tastere. Tako bi mogao zatražiti pristup za kontrolu aplikacije kao što je Finder i odobriti dijalog sa ovom dozvolom.

## Medium

### `com.apple.security.cs.allow-jit`

Ova dozvola omogućava da se **kreira memorija koja je zapisiva i izvršna** prosleđivanjem `MAP_JIT` oznake `mmap()` sistemskoj funkciji. Proverite [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ova dozvola omogućava da se **prepiše ili zakrpi C kod**, koristi dugo zastareli **`NSCreateObjectFileImageFromMemory`** (koji je fundamentalno nesiguran), ili koristi **DVDPlayback** okvir. Proverite [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Uključivanje ove dozvole izlaže vašu aplikaciju uobičajenim ranjivostima u jezicima koda koji nisu sigurni u memoriji. Pažljivo razmotrite da li vaša aplikacija treba ovu izuzetak.

### `com.apple.security.cs.disable-executable-page-protection`

Ova dozvola omogućava da se **modifikuju delovi vlastitih izvršnih fajlova** na disku kako bi se prisilno izašlo. Proverite [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Dozvola za onemogućavanje zaštite izvršne memorije je ekstremna dozvola koja uklanja fundamentalnu sigurnosnu zaštitu iz vaše aplikacije, omogućavajući napadaču da prepiše izvršni kod vaše aplikacije bez otkrivanja. Preferirajte uže dozvole ako je moguće.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ova dozvola omogućava montiranje nullfs fajlskog sistema (zabranjeno podrazumevano). Alat: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Prema ovom blog postu, ova TCC dozvola obično se nalazi u formi:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Dozvolite procesu da **zatraži sve TCC dozvole**.

### **`kTCCServicePostEvent`**



</details>




{{#include ../../../banners/hacktricks-training.md}}
