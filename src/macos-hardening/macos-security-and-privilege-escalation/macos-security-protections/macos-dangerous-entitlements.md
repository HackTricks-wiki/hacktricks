# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements definišu mogućnosti i bezbednosne izuzetke koje operativni sistem dodeljuje potpisanom kodu. Stavke u nastavku fokusiraju se na one koje su naročito korisne tokom ofanzivne provere.<sup>[[13]](#references)</sup>

> [!WARNING]
> Imajte na umu da entitlements koji počinju sa **`com.apple`** nisu dostupni trećim stranama; samo Apple može da ih dodeli... Međutim, ako koristite enterprise sertifikat, zapravo možete kreirati sopstvene entitlements koji počinju sa **`com.apple`** i na taj način zaobići zaštite zasnovane na tome.

## Visok nivo

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** omogućava procesu da **zaobiđe SIP**. Pogledajte [ovde za više informacija](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** omogućava procesu da **zaobiđe SIP**. Pogledajte [ovde za više informacija](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (prethodno nazivan `task_for_pid-allow`)**

Ovaj entitlement omogućava procesu da dobije **task port bilo kog** procesa, osim kernela. Pogledajte [**ovde za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ovaj entitlement omogućava drugim procesima sa entitlementom **`com.apple.security.cs.debugger`** da dobiju task port procesa koji pokreće binary sa ovim entitlementom i da **ubace kod u njega**. Pogledajte [**ovde za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacije sa Debugging Tool Entitlement mogu da pozovu `task_for_pid()` kako bi preuzele validan task port za unsigned i third-party aplikacije kod kojih je entitlement `Get Task Allow` podešen na `true`. Međutim, čak i sa debugging tool entitlementom, debugger **ne može da dobije task ports** procesa koji **nemaju entitlement `Get Task Allow`** i koji su zbog toga zaštićeni funkcijom System Integrity Protection. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Ovaj entitlement omogućava aplikaciji da **učitava frameworks, plug-ins ili libraries bez zahteva da budu potpisani od strane Apple-a ili istim Team ID-jem** kao glavni executable, pa bi attacker mogao da zloupotrebi proizvoljno učitavanje library-ja za ubacivanje koda. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Ovaj entitlement je veoma sličan entitilementu **`com.apple.security.cs.disable-library-validation`**, ali **umesto da direktno onemogućava** library validation, omogućava procesu da **pozove `csops` system call radi njenog onemogućavanja** tokom izvršavanja.

Naziv entitilementa je hardkodovan u XNU-u, pored `csops` operacije koja ga koristi:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Kernel handler za `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) pokazuje koliko je primitive usko:<sup>[[2]](#references)</sup>
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

- Radi **isključivo na macOS-u** (`ENOTSUP` na svim drugim platformama).
- Radi samo nad **samim sobom** (`forself == 1`) — pomoću nje nije moguće ukloniti library validation iz drugog procesa.
- Zahteva da proces zaista **poseduje entitlement**, i odbija zahtev ako je proces označen sa `CS_INSTALLER` ili se izvršava unutar putanje subsystem root-a.
- Uklanja **`CS_REQUIRE_LV | CS_FORCED_LV`** iz code-signing oznaka procesa.

XNU komentar objašnjava predviđeni slučaj upotrebe, kao i razlog zbog kog je ovo zanimljivo napadaču:

> Ova opcija se koristi za uklanjanje library validation-a iz procesa koji se izvršava. Koristi se u plugin arhitekturama kada program treba da učita nepouzdane biblioteke. [...] Kada proces učita nepouzdanu biblioteku, oslanjanje na library validation ubuduće neće biti efikasno.

Drugim rečima, **svaki binary koji poseduje ovaj entitlement predstavlja dylib-injection target**: pokrenite code unutar njega (ili ga ubedite da učita vaš plug-in) nakon što ukloni `CS_REQUIRE_LV`, i nasleđujete sve što je host proces ovlašćen da radi.

### `com.apple.security.cs.allow-dyld-environment-variables`

Ovaj entitlement omogućava **korišćenje DYLD environment variables**, koje se mogu koristiti za ubacivanje biblioteka i code-a. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` ili `com.apple.rootless.storage`.`TCC`

[**Prema ovom blogu**](https://objective-see.org/blog/blog_0x4C.html) **i** [**ovom blogu**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ovi entitlements omogućavaju procesu da **menja** **TCC** bazu podataka.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Ovi entitlements omogućavaju procesu da **instalira software bez traženja dozvole od korisnika**, što može biti korisno za **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement potreban za slanje zahteva **kernelu da učita kernel extension**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC service-om, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** su posedovali ovaj entitlement.

Za više **informacija** o exploit-u za **dobavljanje icloud tokena** pomoću ovog entitlement-a pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ne znam šta ovo omogućava

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Ovaj izveštaj**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) navodi da bi ovaj entitlement mogao da se koristi za ažuriranje sadržaja zaštićenog SSV-om nakon reboot-a. Ako znate kako, pošaljite PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Isti izveštaj**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) navodi da bi kreiranje sealed snapshot-a moglo da se koristi za ažuriranje sadržaja zaštićenog SSV-om nakon reboot-a. Ako znate kako, pošaljite PR!<sup>[[9]](#references)</sup>

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

Omogućava aplikaciji da šalje događaje drugim aplikacijama koje se obično koriste za **automatizovanje zadataka**. Kontrolišući druge aplikacije, može da zloupotrebi dozvole dodeljene tim aplikacijama.

Na primer, tako što ih navodi da zatraže lozinku korisnika:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ili ih naterati da izvrše **proizvoljne radnje**.

### **`kTCCServiceEndpointSecurityClient`**

Omogućava, između ostalih dozvola, **upisivanje u korisničku TCC bazu podataka**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Omogućava **promenu** atributa **`NFSHomeDirectory`** korisnika, čime se menja putanja njegove home fascikle i omogućava **zaobilaženje TCC-a**.

### **`kTCCServiceSystemPolicyAppBundles`**

Omogućava izmenu datoteka unutar app bundle-a (unutar app.app), što je **podrazumevano onemogućeno**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Moguće je proveriti ko ima ovaj pristup u _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Proces će moći da **zloupotrebi macOS accessibility funkcije**, što, na primer, znači da će moći da pritiska tastere. Zbog toga bi mogao da zatraži pristup za kontrolu aplikacije kao što je Finder i odobri dijalog pomoću ove dozvole.

## Entitlements povezani sa Trustcache/CDhash

Postoje entitlements koji bi mogli da se koriste za zaobilaženje Trustcache/CDhash zaštita, koje sprečavaju izvršavanje downgrade-ovanih verzija Apple binarnih datoteka.

## Srednji nivo

### `com.apple.security.cs.allow-jit`

Ovaj entitlement omogućava procesu da **kreira memoriju koja je upisiva i izvršna** prosleđivanjem oznake `MAP_JIT` sistemskoj funkciji `mmap()`. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ovaj entitlement omogućava **zaobilaženje ili patch-ovanje C koda**, korišćenje zastarele funkcije **`NSCreateObjectFileImageFromMemory`** (koja je suštinski nebezbedna) ili korišćenje framework-a **DVDPlayback**. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Uključivanje ovog entitle­menta izlaže vašu aplikaciju uobičajenim ranjivostima u memorijski nebezbednim programskim jezicima. Pažljivo razmotrite da li je vašoj aplikaciji potreban ovaj izuzetak.

### `com.apple.security.cs.disable-executable-page-protection`

Ovaj entitlement omogućava **izmenu sekcija sopstvenih izvršnih datoteka** na disku radi prisilnog izlaska. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement Disable Executable Memory Protection je ekstremni entitlement koji uklanja fundamentalnu bezbednosnu zaštitu iz vaše aplikacije, čime napadaču omogućava da neopaženo prepiše izvršni kod vaše aplikacije. Ako je moguće, prednost dajte užim entitlementima.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ovaj entitlement omogućava montiranje nullfs file system-a (podrazumevano zabranjeno). Alat: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Prema ovoj blog objavi, ova TCC dozvola se obično pronalazi u obliku:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Omogućava procesu da **zatraži sve TCC dozvole**.

### **`kTCCServicePostEvent`**

Omogućava **ubacivanje sintetičkih događaja tastature i miša** na nivou celog sistema putem `CGEventPost()`. Proces sa ovom dozvolom može da simulira pritiske tastera, klikove mišem i događaje pomeranja u bilo kojoj aplikaciji — čime praktično dobija **remote control** nad radnom površinom.

Ovo je naročito opasno u kombinaciji sa `kTCCServiceAccessibility` ili `kTCCServiceListenEvent`, jer omogućava i čitanje I ubacivanje ulaznih podataka.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Omogućava **presretanje svih događaja sa tastature i miša** na nivou celog sistema (input monitoring / keylogging). Proces može da registruje `CGEventTap` i uhvati svaki pritisnuti taster u bilo kojoj aplikaciji, uključujući lozinke, brojeve kreditnih kartica i privatne poruke.

Za detaljne exploitation tehnike pogledajte:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Omogućava **čitanje bafera ekrana** — pravljenje screenshots i snimanje video-zapisa ekrana bilo koje aplikacije, uključujući bezbedna tekstualna polja. U kombinaciji sa OCR-om, ovo može automatski da izdvoji lozinke i osetljive podatke sa ekrana.

> [!WARNING]
> Počev od macOS Sonoma, screen capture prikazuje trajni indikator u menu baru. Na starijim verzijama, screen recording može biti potpuno neprimetan.

### **`kTCCServiceCamera`**

Omogućava **snimanje fotografija i video-zapisa** pomoću ugrađene kamere ili povezanih USB kamera. Code injection u binary sa camera entitlements omogućava nečujni vizuelni nadzor.

### **`kTCCServiceMicrophone`**

Omogućava **snimanje zvuka** sa svih ulaznih uređaja. Background daemons sa pristupom mikrofonu omogućavaju trajni ambient audio nadzor bez vidljivog prozora aplikacije.

### **`kTCCServiceLocation`**

Omogućava upite o **fizičkoj lokaciji** uređaja putem Wi-Fi triangulacije ili Bluetooth beacona. Kontinuirano praćenje otkriva kućne i poslovne adrese, obrasce putovanja i svakodnevne rutine.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Pristup **Contacts** (imena, e-mail adrese, brojevi telefona — korisno za spear-phishing), **Calendar** (rasporedi sastanaka, spiskovi učesnika) i **Photos** (lične fotografije, screenshots koji mogu sadržati credentials, metadata o lokaciji).

Za kompletne exploitation tehnike krađe credentials putem TCC permissions, pogledajte:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox i Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** slabe App Sandbox tako što omogućavaju komunikaciju sa Mach/XPC servisima dostupnim na nivou celog sistema, koje Sandbox uobičajeno blokira. Ovo je **primarni sandbox escape primitive** — kompromitovana sandboxed aplikacija može da koristi mach-lookup exceptions za pristup privileged daemonima i exploitation njihovih XPC interfejsa.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Za detaljan exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, pogledajte:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** omogućavaju user-space driver binarnim datotekama da direktno komuniciraju sa kernelom putem IOKit interfejsa. DriverKit binarne datoteke upravljaju hardverom: USB, Thunderbolt, PCIe, HID uređajima, audio uređajima i mrežom.

Kompromitovanje DriverKit binarne datoteke omogućava:
- **Kernel attack surface** putem neispravnih `IOConnectCallMethod` poziva
- **USB device spoofing** (emulacija tastature za HID injection)
- **DMA attacks** putem PCIe/Thunderbolt interfejsa
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Za detaljnu analizu IOKit/DriverKit exploitation, pogledajte:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operacije i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement za debugging alate (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement za onemogućavanje Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement za omogućavanje DYLD Environment Variables](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Zaobilaženje TCC-a](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Reprodukujte muziku i zaobiđite TCC, poznato i kao CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: „Ono što se desi na vašem Mac-u, ostaje na Apple-ovom iCloud-u?!“ - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple-ova OTA Update noćna mora: Zaobilaženje provere potpisa i preuzimanje kontrole nad kernelom](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement za omogućavanje izvršavanja JIT-kompajliranog koda (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement za omogućavanje unsigned executable memorije](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement za onemogućavanje zaštite executable memorije](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
