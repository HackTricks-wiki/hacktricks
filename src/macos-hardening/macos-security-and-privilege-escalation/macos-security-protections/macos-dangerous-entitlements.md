# Dangerous Entitlements i TCC perms za macOS

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Imajte na umu da entitlements koji počinju sa **`com.apple`** nisu dostupni third-party aplikacijama; samo Apple može da ih dodeli... Međutim, ako koristite enterprise certificate, zapravo možete kreirati sopstvene entitlements koji počinju sa **`com.apple`** i tako zaobići zaštite zasnovane na tome.

## Visok rizik

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** omogućava **zaobilaženje SIP-a**. Pogledajte [ovde za više informacija](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** omogućava **zaobilaženje SIP-a**. Pogledajte [ovde za više informacija](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (prethodno nazivan `task_for_pid-allow`)**

Ovaj entitlement omogućava dobijanje **task porta za bilo koji** proces, osim kernela. Pogledajte [**ovde za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ovaj entitlement omogućava drugim procesima sa entitlementom **`com.apple.security.cs.debugger`** da dobiju task port procesa koji pokreće binary sa ovim entitlementom i da **ubace code u njega**. Pogledajte [**ovde za više informacija**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacije sa Debugging Tool Entitlement mogu pozvati `task_for_pid()` kako bi preuzele validan task port za unsigned i third-party aplikacije kod kojih je entitlement `Get Task Allow` postavljen na `true`. Međutim, čak ni sa debugging tool entitlementom, debugger **ne može da dobije task portove** procesa koji **nemaju entitlement `Get Task Allow`** i koji su zbog toga zaštićeni funkcijom System Integrity Protection. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Ovaj entitlement omogućava **učitavanje frameworka, plug-inova ili biblioteka koje nisu potpisane ni od strane Apple-a niti istim Team ID-jem** kao glavni executable, pa bi attacker mogao da zloupotrebi proizvoljno učitavanje biblioteke za ubacivanje koda. Pogledajte [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ovaj entitlement je veoma sličan entitlu **`com.apple.security.cs.disable-library-validation`**, ali **umesto** **direktnog onemogućavanja** provere biblioteka, omogućava procesu da **pozove `csops` system call kako bi je onemogućio** tokom izvršavanja.

Naziv entitla je hardkodovan u XNU-u pored `csops` operacije koja ga koristi:<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Kernel handler za `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) tačno pokazuje koliko je ovaj primitiv ograničen:<sup>[[3]](#references)</sup>
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

- Je **isključivo za macOS** (`ENOTSUP` na svim drugim platformama).
- Radi samo nad **samim sobom** (`forself == 1`) — pomoću nje ne možete ukloniti library validation iz drugog procesa.
- Zahteva da proces zaista **poseduje entitlement** i odbija rad ako je proces označen sa `CS_INSTALLER` ili ako se izvršava pod root putanjom subsistema.
- Uklanja **`CS_REQUIRE_LV | CS_FORCED_LV`** iz code-signing zastavica procesa.

XNU komentar objašnjava predviđeni slučaj upotrebe, kao i zašto je ovo zanimljivo napadaču:

> This option is used to remove library validation from a running process. This is used in plugin architectures when a program needs to load untrusted libraries. [...] Once a process has loaded the untrusted library, relying on library validation in the future will not be effective.

Drugim rečima, **svaki binary koji poseduje ovaj entitlement je dylib-injection target**: pokrenite code unutar njega (ili ga navedite da učita vaš plug-in) nakon što ukloni `CS_REQUIRE_LV`, i nasleđujete sve što je host proces ovlašćen da uradi.

### `com.apple.security.cs.allow-dyld-environment-variables`

Ovaj entitlement omogućava **korišćenje DYLD environment variables**, koje se mogu upotrebiti za injection library-ja i code-a. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ili `com.apple.rootless.storage`.`TCC`

[**Prema ovom blogu**](https://objective-see.org/blog/blog_0x4C.html) **i** [**ovom blogu**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ovi entitlements omogućavaju **izmenu** **TCC** baze podataka.

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Ovi entitlements omogućavaju **instaliranje software-a bez traženja dozvole** od korisnika, što može biti korisno za **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement potreban za zahtev **kernelu da učita kernel extension**.

### **`com.apple.private.icloud-account-access`**

Sa entitlementom **`com.apple.private.icloud-account-access`** moguće je komunicirati sa **`com.apple.iCloudHelper`** XPC service-om, koji će **obezbediti iCloud tokene**.

**iMovie** i **Garageband** su posedovali ovaj entitlement.

Za više **informacija** o exploitu za **dobijanje iCloud tokena** pomoću ovog entitlementa pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ne znam šta ovo omogućava

### `com.apple.private.apfs.revert-to-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **navodi se da bi ovo moglo da se koristi za** ažuriranje sadržaja zaštićenog SSV-om nakon reboot-a. Ako znate kako, pošaljite PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **navodi se da bi ovo moglo da se koristi za** ažuriranje sadržaja zaštićenog SSV-om nakon reboot-a. Ako znate kako, pošaljite PR!

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

Daje dozvole za **Full Disk Access**, jednu od najviših TCC dozvola koje možete imati.

### **`kTCCServiceAppleEvents`**

Omogućava aplikaciji da šalje događaje drugim aplikacijama koje se obično koriste za **automatizovanje zadataka**. Kontrolišući druge aplikacije, može zloupotrebiti dozvole dodeljene tim aplikacijama.

Na primer, može ih navesti da zatraže od korisnika njegovu lozinku:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ili ih naterati da izvršavaju **proizvoljne radnje**.

### **`kTCCServiceEndpointSecurityClient`**

Omogućava, između ostalih dozvola, **upisivanje u korisničku TCC bazu podataka**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Omogućava **promenu** atributa **`NFSHomeDirectory`** korisnika, čime se menja putanja njegove matične fascikle i samim tim omogućava **zaobilaženje TCC-a**.

### **`kTCCServiceSystemPolicyAppBundles`**

Omogućava izmenu datoteka unutar app bundle-a (unutar app.app), što je **podrazumevano onemogućeno**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Moguće je proveriti ko ima ovaj pristup u _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Proces će moći da **zloupotrebi macOS accessibility funkcije**, što, na primer, znači da će moći da pritiska tastere. Tako bi mogao da zatraži pristup za kontrolu aplikacije kao što je Finder i odobri dijalog pomoću ove dozvole.

## Entitlements povezani sa Trustcache/CDhash

Postoje neki entitlements koji bi mogli da se koriste za zaobilaženje Trustcache/CDhash zaštita, koje sprečavaju izvršavanje downgraded verzija Apple binarnih datoteka.

## Srednji nivo

### `com.apple.security.cs.allow-jit`

Ovaj entitlement omogućava **kreiranje memorije koja je upisiva i izvršna** prosleđivanjem zastavice `MAP_JIT` sistemskoj funkciji `mmap()`. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ovaj entitlement omogućava **zaobilaženje ili izmenu C koda**, korišćenje zastarele funkcije **`NSCreateObjectFileImageFromMemory`** (koja je u osnovi nesigurna) ili korišćenje framework-a **DVDPlayback**. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Uključivanje ovog entitlement-a izlaže vašu aplikaciju uobičajenim ranjivostima u memory-unsafe programskim jezicima. Pažljivo razmotrite da li je vašoj aplikaciji potreban ovaj izuzetak.

### `com.apple.security.cs.disable-executable-page-protection`

Ovaj entitlement omogućava **izmenu delova sopstvenih izvršnih datoteka** na disku radi prisilnog izlaska. Pogledajte [**ovo za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Entitlement Disable Executable Memory Protection je ekstreman entitlement koji uklanja osnovnu bezbednosnu zaštitu iz vaše aplikacije, čime napadaču omogućava da izmeni izvršni kod vaše aplikacije bez detekcije. Ako je moguće, prednost dajte užim entitlement-ima.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ovaj entitlement omogućava montiranje nullfs sistema datoteka (što je podrazumevano zabranjeno). Alat: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Prema ovom blogpostu, ova TCC dozvola se obično nalazi u obliku:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Omogućava procesu da **zatraži sve TCC dozvole**.

### **`kTCCServicePostEvent`**

Omogućava **ubacivanje sintetičkih događaja tastature i miša** na nivou celog sistema putem `CGEventPost()`. Proces sa ovom dozvolom može da simulira pritiske tastera, klikove mišem i događaje pomeranja u bilo kojoj aplikaciji — čime efektivno dobija **daljinsku kontrolu** nad desktopom.

Ovo je naročito opasno u kombinaciji sa `kTCCServiceAccessibility` ili `kTCCServiceListenEvent`, jer omogućava i čitanje I ubacivanje ulaza.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Omogućava **presretanje svih događaja tastature i miša** na nivou celog sistema (nadgledanje unosa / keylogging). Proces može da registruje `CGEventTap` kako bi uhvatio svaki pritisnuti taster u bilo kojoj aplikaciji, uključujući lozinke, brojeve kreditnih kartica i privatne poruke.

Za detaljne tehnike eksploatacije pogledajte:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Omogućava **čitanje bafera ekrana** — pravljenje screenshotova i snimanje videozapisa ekrana bilo koje aplikacije, uključujući zaštićena polja za tekst. U kombinaciji sa OCR-om, ovo može automatski da izdvoji lozinke i osetljive podatke sa ekrana.

> [!WARNING]
> Počev od macOS Sonoma, snimanje ekrana prikazuje trajni indikator u menu baru. Na starijim verzijama, snimanje ekrana može biti potpuno neprimetno.

### **`kTCCServiceCamera`**

Omogućava **snimanje fotografija i videozapisa** pomoću ugrađene kamere ili povezanih USB kamera. Code injection u binary sa ovlašćenjem za kameru omogućava nečujni vizuelni nadzor.

### **`kTCCServiceMicrophone`**

Omogućava **snimanje zvuka** sa svih ulaznih uređaja. Pozadinski daemoni sa pristupom mikrofonu omogućavaju trajni nadzor ambijentalnog zvuka bez vidljivog prozora aplikacije.

### **`kTCCServiceLocation`**

Omogućava dobavljanje **fizičke lokacije** uređaja putem Wi-Fi triangulacije ili Bluetooth beacona. Kontinuirano praćenje otkriva adrese stanovanja i rada, obrasce putovanja i svakodnevne rutine.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Pristup **Kontaktima** (imena, email adrese, telefoni — korisno za spear-phishing), **Kalendaru** (rasporedi sastanaka, liste učesnika) i **Fotografijama** (lične fotografije, screenshotovi koji mogu sadržati akreditive, metapodaci o lokaciji).

Za kompletne tehnike eksploatacije za krađu akreditiva putem TCC dozvola pogledajte:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox i Code Signing entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Privremeni Sandbox izuzeci** slabe App Sandbox tako što omogućavaju komunikaciju sa Mach/XPC servisima na nivou celog sistema, koje Sandbox normalno blokira. Ovo je **primarni primitive za bekstvo iz Sandbox-a** — kompromitovana sandboxovana aplikacija može da koristi mach-lookup izuzetke za pristup privilegovanim daemonima i eksploataciju njihovih XPC interfejsa.
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

**DriverKit entitlements** omogućavaju da driver binaries u user-space-u direktno komuniciraju sa kernelom putem IOKit interfejsa. DriverKit binaries upravljaju hardverom: USB, Thunderbolt, PCIe, HID uređajima, audio i mrežnim uređajima.

Kompromitovanje DriverKit binary-ja omogućava:
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

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
