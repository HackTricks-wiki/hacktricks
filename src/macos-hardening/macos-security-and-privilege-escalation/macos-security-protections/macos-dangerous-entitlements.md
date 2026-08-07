# Opasni Entitlements i TCC perms na macOS-u

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Imajte na umu da entitlements koji počinju sa **`com.apple`** nisu dostupni third-party korisnicima, već ih može dodeliti samo Apple... Ili, ako koristite enterprise sertifikat, zapravo možete kreirati sopstvene entitlements koji počinju sa **`com.apple`** i na taj način zaobići zaštite zasnovane na tome.

## Visok rizik

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** omogućava **bypass SIP-a**. Pogledajte [ovde za više informacija](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** omogućava **bypass SIP-a**. Pogledajte [ovde za više informacija](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (prethodno nazivan `task_for_pid-allow`)**

Ovaj entitlement omogućava dobijanje **task port-a za bilo koji** proces, osim kernela. Pogledajte [**ovde za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ovaj entitlement omogućava drugim procesima sa entitlementom **`com.apple.security.cs.debugger`** da dobiju task port procesa koji pokreće binary sa ovim entitlementom i da **ubace code u njega**. Pogledajte [**ovde za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacije sa Debugging Tool Entitlement-om mogu da pozovu `task_for_pid()` kako bi preuzele validan task port za unsigned i third-party aplikacije kod kojih je entitlement `Get Task Allow` podešen na `true`. Međutim, čak i sa debugging tool entitlementom, debugger **ne može da dobije task port-ove** procesa koji **nemaju entitlement `Get Task Allow`** i koji su stoga zaštićeni funkcijom System Integrity Protection. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Ovaj entitlement omogućava **učitavanje framework-a, plug-inova ili library-ja bez zahteva da budu potpisani od strane Apple-a ili potpisani istim Team ID-jem** kao glavni executable, pa bi attacker mogao da zloupotrebi proizvoljno učitavanje library-ja radi ubacivanja code-a. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Ovaj entitlement je veoma sličan entitlementu **`com.apple.security.cs.disable-library-validation`**, ali **umesto** **direktnog onemogućavanja** library validation-a, omogućava procesu da **pozove `csops` system call kako bi ga onemogućio** tokom izvršavanja.

Naziv entitilementa je hardkodovan u XNU-u, pored `csops` operacije koja ga koristi:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Kernel handler za `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) tačno pokazuje koliko je ovaj primitive ograničen:<sup>[[2]](#references)</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Dakle, operacija:

- Radi samo na **macOS-u** (`ENOTSUP` na svim drugim platformama).
- Radi samo nad **samim procesom** (`forself == 1`) — pomoću nje ne možete ukloniti library validation iz drugog procesa.
- Zahteva da proces zaista **poseduje entitlement**, a odbija se ako je proces označen sa `CS_INSTALLER` ili se izvršava u okviru root putanje podsistema.
- Uklanja **`CS_REQUIRE_LV | CS_FORCED_LV`** iz zastavica potpisivanja koda procesa.

XNU komentar objašnjava predviđeni slučaj upotrebe, kao i zašto je ovo zanimljivo napadaču:

> Ova opcija se koristi za uklanjanje library validation-a iz procesa koji se izvršava. Koristi se u arhitekturama zasnovanim na plug-inovima kada program treba da učita nepouzdane biblioteke. [...] Kada proces učita nepouzdanu biblioteku, oslanjanje na library validation ubuduće više neće biti efikasno.

Drugim rečima, **svaki binary koji poseduje ovaj entitlement jeste meta za dylib-injection**: izvršite kod unutar njega (ili ga ubedite da učita vaš plug-in) nakon što ukloni `CS_REQUIRE_LV`, i nasleđujete sve za šta je host proces ovlašćen.

### `com.apple.security.cs.allow-dyld-environment-variables`

Ovaj entitlement omogućava **korišćenje DYLD environment variables**, koje se mogu koristiti za ubacivanje biblioteka i koda. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` ili `com.apple.rootless.storage`.`TCC`

[**Prema ovom blogu**](https://objective-see.org/blog/blog_0x4C.html) **i** [**ovom blogu**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ovi entitlements omogućavaju **izmenu** **TCC** baze podataka.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Ovi entitlements omogućavaju **instaliranje softvera bez traženja dozvole** od korisnika, što može biti korisno za **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement potreban za slanje zahteva **kernelu da učita kernel extension**.

### **`com.apple.private.icloud-account-access`**

Pomoću entitlements **`com.apple.private.icloud-account-access`** moguće je komunicirati sa **`com.apple.iCloudHelper`** XPC service-om, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** su posedovali ovaj entitlement.

Za više **informacija** o exploitu za **dobijanje iCloud tokena** pomoću ovog entitlements, pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ne znam šta ovo omogućava

### `com.apple.private.apfs.revert-to-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se navodi da bi ovo moglo da se koristi za** izmenu sadržaja zaštićenog SSV-om nakon ponovnog pokretanja. Ako znate kako, pošaljite PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se navodi da bi ovo moglo da se koristi za** izmenu sadržaja zaštićenog SSV-om nakon ponovnog pokretanja. Ako znate kako, pošaljite PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Ovaj entitlement navodi **keychain** grupe kojima aplikacija ima pristup:
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

Daje dozvole za **Full Disk Access**, jedne od najviših TCC dozvola koje možete imati.

### **`kTCCServiceAppleEvents`**

Omogućava aplikaciji da šalje događaje drugim aplikacijama koje se obično koriste za **automatizaciju zadataka**. Kontrolišući druge aplikacije, može zloupotrebiti dozvole dodeljene tim aplikacijama.

Na primer, može ih naterati da zatraže korisničku lozinku:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ili naterati ih da izvršavaju **proizvoljne radnje**.

### **`kTCCServiceEndpointSecurityClient`**

Omogućava, između ostalih dozvola, da se **upisuje u TCC bazu podataka korisnika**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Omogućava **promenu** atributa **`NFSHomeDirectory`** korisnika, čime se menja putanja njegove matične fascikle i samim tim omogućava **zaobilaženje TCC-a**.

### **`kTCCServiceSystemPolicyAppBundles`**

Omogućava izmenu datoteka unutar app bundle-a (unutar app.app), što je **podrazumevano onemogućeno**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Moguće je proveriti ko ima ovaj pristup u _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Proces će moći da **zloupotrebi macOS funkcije pristupačnosti**, što, na primer, znači da će moći da simulira pritiske tastera. Tako bi mogao da zatraži pristup za kontrolu aplikacije kao što je Finder i odobri dijalog pomoću ove dozvole.

## Entitlements povezani sa Trustcache/CDhash

Postoje određeni entitlements koji bi mogli da se koriste za zaobilaženje Trustcache/CDhash zaštita, koje sprečavaju izvršavanje downgraded verzija Apple binarnih datoteka.

## Srednji nivo

### `com.apple.security.cs.allow-jit`

Ovaj entitlement omogućava **kreiranje memorije koja je upisiva i izvršiva** prosleđivanjem zastavice `MAP_JIT` sistemskoj funkciji `mmap()`. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ovaj entitlement omogućava **override ili patch C koda**, korišćenje zastarele funkcije **`NSCreateObjectFileImageFromMemory`** (koja je suštinski nesigurna) ili korišćenje framework-a **DVDPlayback**. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Uključivanje ovog entitlement-a izlaže vašu aplikaciju uobičajenim ranjivostima u memory-unsafe programskim jezicima. Pažljivo razmotrite da li je vašoj aplikaciji potreban ovaj izuzetak.

### `com.apple.security.cs.disable-executable-page-protection`

Ovaj entitlement omogućava **izmenu sekcija sopstvenih izvršnih datoteka** na disku radi prisilnog prekida izvršavanja. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement Disable Executable Memory Protection je ekstreman entitlement koji uklanja osnovnu bezbednosnu zaštitu iz vaše aplikacije, omogućavajući napadaču da neopaženo prepiše izvršni kod vaše aplikacije. Ako je moguće, koristite uža prava.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ovaj entitlement omogućava montiranje nullfs file system-a (što je podrazumevano zabranjeno). Alat: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Prema ovom blogpostu, ova TCC dozvola se obično pronalazi u obliku:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Omogućava procesu da **zatraži sve TCC dozvole**.

### **`kTCCServicePostEvent`**

Omogućava **ubacivanje sintetičkih događaja tastature i miša** na nivou celog sistema putem `CGEventPost()`. Proces sa ovom dozvolom može da simulira pritiske tastera, klikove mišem i događaje pomeranja u bilo kojoj aplikaciji — čime praktično dobija **daljinsku kontrolu** nad desktopom.

Ovo je naročito opasno u kombinaciji sa `kTCCServiceAccessibility` ili `kTCCServiceListenEvent`, jer omogućava i čitanje I ubacivanje inputa.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Omogućava **presretanje svih događaja tastature i miša** na nivou celog sistema (input monitoring / keylogging). Proces može da registruje `CGEventTap` kako bi uhvatio svaki pritisnuti taster u bilo kojoj aplikaciji, uključujući lozinke, brojeve kreditnih kartica i privatne poruke.

Za detaljne tehnike exploitation-a pogledajte:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Omogućava **čitanje display buffera** — pravljenje screenshot-ova i snimanje videozapisa ekrana bilo koje aplikacije, uključujući bezbedna polja za unos teksta. U kombinaciji sa OCR-om, ovo može automatski da izdvoji lozinke i osetljive podatke sa ekrana.

> [!WARNING]
> Počev od macOS Sonoma, screen capture prikazuje trajni indikator u menu baru. Na starijim verzijama, screen recording može biti potpuno nečujan.

### **`kTCCServiceCamera`**

Omogućava **snimanje fotografija i videozapisa** pomoću ugrađene kamere ili povezanih USB kamera. Code injection u binary sa camera entitlements omogućava nečujni vizuelni nadzor.

### **`kTCCServiceMicrophone`**

Omogućava **snimanje audiozapisa** sa svih input uređaja. Background daemons sa pristupom mikrofonu omogućavaju trajni ambient audio nadzor bez vidljivog prozora aplikacije.

### **`kTCCServiceLocation`**

Omogućava upite za **fizičku lokaciju** uređaja putem Wi-Fi triangulacije ili Bluetooth beacons-a. Kontinuirano praćenje otkriva kućne i poslovne adrese, obrasce putovanja i svakodnevne rutine.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Pristup **Contacts** (imena, email adrese, brojevi telefona — korisno za spear-phishing), **Calendar-u** (rasporedi sastanaka, spiskovi učesnika) i **Photos** (lične fotografije, screenshot-ovi koji mogu sadržati credentials, metadata o lokaciji).

Za kompletne exploitation tehnike krađe credentials-a putem TCC dozvola pogledajte:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox i Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Privremeni izuzeci Sandbox-a** slabe App Sandbox tako što omogućavaju komunikaciju sa Mach/XPC servisima na nivou celog sistema, koje Sandbox inače blokira. Ovo je **primarni primitive za bekstvo iz Sandbox-a** — kompromitovana sandboxovana aplikacija može da koristi mach-lookup izuzetke kako bi pristupila privilegovanim daemonima i iskoristila njihove XPC interfejse.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detaljan chain eksploatacije: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, pogledajte:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** omogućavaju user-space driver binarijama da direktno komuniciraju sa kernelom putem IOKit interfejsa. DriverKit binarije upravljaju hardverom: USB, Thunderbolt, PCIe, HID uređajima, audio uređajima i mrežom.

Kompromitovanje DriverKit binarije omogućava:
- **Kernel attack surface** putem neispravnih `IOConnectCallMethod` poziva
- **USB device spoofing** (emulacija tastature za HID injection)
- **DMA attacks** putem PCIe/Thunderbolt interfejsa
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Za detaljnu eksploataciju IOKit/DriverKit, pogledajte:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Reference

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operacije i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement za debugging alat (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement za onemogućavanje Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement za dozvolu DYLD environment variables](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Zaobilaženje TCC-a](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Puštanje muzike i zaobilaženje TCC-a, poznato kao CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: „Šta se desi na vašem Mac-u, ostaje na Apple-ovom iCloud-u?!“ - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Noćna mora Apple-ovog OTA Update-a: Zaobilaženje verifikacije potpisa i preuzimanje kontrole nad Kernel-om](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement za dozvolu izvršavanja JIT-kompajliranog koda (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement za dozvolu memorije izvršnog koda bez potpisa](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement za onemogućavanje zaštite izvršne memorije](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
