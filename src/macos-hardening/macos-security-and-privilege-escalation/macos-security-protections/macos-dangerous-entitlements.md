# macOS Opasne entitlements & TCC dozvole

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Imajte na umu da entitlements koji počinju sa **`com.apple`** nisu dostupni trećim stranama — samo Apple ih može dodeliti... Ili, ako koristite enterprise certificate, zaista biste mogli kreirati sopstvene entitlements koji počinju sa **`com.apple`** i tako bypass-ovati zaštite zasnovane na tome.

## Visok

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** omogućava da se zaobiđe **SIP**. Pogledajte [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** omogućava da se zaobiđe **SIP**. Pogledajte[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Ovaj entitlement omogućava dobijanje **task port-a za bilo koji** proces, osim kernela. Pogledajte [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ovaj entitlement omogućava drugim procesima koji imaju **`com.apple.security.cs.debugger`** entitlement da dobiju task port procesa koji pokreće binarni fajl sa ovim entitlement-om i da na njega **injektuju kod**. Pogledajte [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacije sa Debugging Tool Entitlement-om mogu pozvati `task_for_pid()` da bi dobile validan task port za unsigned i third-party aplikacije koje imaju `Get Task Allow` entitlement postavljen na `true`. Ipak, čak i sa debugging tool entitlement-om, debugger **ne može dobiti task port-ove** procesa koji **nemaju `Get Task Allow` entitlement**, i koji su stoga zaštićeni od strane System Integrity Protection. Pogledajte [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Ovaj entitlement omogućava **učitavanje frameworks, plug-in-ova ili biblioteka bez toga da budu potpisani od strane Apple-a ili potpisani istim Team ID-jem** kao glavni izvršni fajl, tako da napadač može iskoristiti neko proizvoljno učitavanje biblioteke za injektovanje koda. Pogledajte [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ovaj entitlement je vrlo sličan **`com.apple.security.cs.disable-library-validation`**, ali **umesto** direktnog onemogućavanja validacije biblioteka, omogućava procesu da **pozove `csops` sistemski poziv da je onemogući**.\
Pogledajte [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Ovaj entitlement omogućava korišćenje **DYLD environment variables** koje bi mogle biti iskorišćene za injektovanje biblioteka i koda. Pogledajte [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ovi entitlements omogućavaju **izmenu** **TCC** baze podataka.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Ovi entitlements omogućavaju **instaliranje softvera bez traženja dozvola** od korisnika, što može biti korisno za **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement potreban da se zatraži od kernela da učita kernel extension.

### **`com.apple.private.icloud-account-access`**

Kroz entitlement **`com.apple.private.icloud-account-access`** moguće je komunicirati sa **`com.apple.iCloudHelper`** XPC servisom koji će **obezbediti iCloud tokens**.

**iMovie** i **Garageband** su imali ovaj entitlement.

Za više informacija o exploit-u za dobijanje iCloud tokena iz ovog entitlement-a pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ne znam šta ovo dozvoljava da se uradi

### `com.apple.private.apfs.revert-to-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) se pominje da se ovo može koristiti za ažuriranje SSV-zaštićenog sadržaja nakon reboot-a. Ako znate kako, pošaljite PR, molim!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) se pominje da se ovo može koristiti za ažuriranje SSV-zaštićenog sadržaja nakon reboot-a. Ako znate kako, pošaljite PR, molim!

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

Daje **Full Disk Access** dozvole, jednu od najviših TCC dozvola koje možete imati.

### **`kTCCServiceAppleEvents`**

Dozvoljava aplikaciji da šalje događaje drugim aplikacijama koje se često koriste za **automatizaciju zadataka**. Kontrolišući druge aplikacije, može zloupotrebiti dozvole dodeljene tim aplikacijama.

Na primer, može ih naterati da od korisnika zatraže lozinku:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ili naterati ih da izvrše **proizvoljne radnje**.

### **`kTCCServiceEndpointSecurityClient`**

Dozvoljava, pored ostalih permisija, da **piše u korisničku TCC bazu podataka**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Dozvoljava da **promeni** atribut **`NFSHomeDirectory`** korisnika koji menja putanju njegovog home foldera i samim tim omogućava **zaobilaženje TCC-a**.

### **`kTCCServiceSystemPolicyAppBundles`**

Dozvoljava modifikovanje fajlova unutar app bundle-a (u okviru app.app), što je **po defaultu zabranjeno**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Možete proveriti ko ima ovaj pristup u _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Proces će moći da **iskorišćava macOS accessibility funkcije**, što znači da, na primer, može da emulira pritiskanje tastera. Dakle, mogao bi da zatraži pristup za kontrolu aplikacije poput Finder-a i potvrdi dijalog koristeći ovu permisiju.

## Entitlements povezani sa Trustcache/CDhash

Postoje neke entitlements koje se mogu iskoristiti za zaobilaženje Trustcache/CDhash zaštite, koja sprečava izvršavanje downgraded verzija Apple binarnih fajlova.

## Srednji

### `com.apple.security.cs.allow-jit`

Ovaj entitlement omogućava da se **kreira memorija koja je upisiva i izvršna** prosleđivanjem flag-a `MAP_JIT` funkciji `mmap()`. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ovaj entitlement omogućava da **modifikujete ili zakrpate C kod**, koristite dugo-zastareli **`NSCreateObjectFileImageFromMemory`** (koji je fundamentalno nesiguran), ili koristite **DVDPlayback** framework. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Including this entitlement exposes your app to common vulnerabilities in memory-unsafe code languages. Carefully consider whether your app needs this exception.

### `com.apple.security.cs.disable-executable-page-protection`

Ovaj entitlement omogućava da se **modifikuju delovi sopstvenih izvršnih fajlova** na disku kako bi se prisilno izašlo. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement is an extreme entitlement that removes a fundamental security protection from your app, making it possible for an attacker to rewrite your app’s executable code without detection. Prefer narrower entitlements if possible.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ovaj entitlement omogućava montiranje nullfs fajl sistema (po defaultu zabranjeno). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

According to this blogpost, this TCC permission usually found in the form:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Dozvolite procesu da **zatraži sve TCC dozvole**.

### **`kTCCServicePostEvent`**

Dozvoljava **injektovanje sintetičkih događaja tastature i miša** na nivou celog sistema putem `CGEventPost()`. Proces koji ima ovu dozvolu može simulirati pritiske tastera, klikove miša i događaje skrolovanja u bilo kojoj aplikaciji — efektivno pružajući **daljinsku kontrolu** radne površine.

Ovo je posebno opasno u kombinaciji sa `kTCCServiceAccessibility` ili `kTCCServiceListenEvent`, jer omogućava i čitanje i injektovanje unosa.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Allows **presretanje svih tastaturnih i miša događaja** na nivou sistema (input monitoring / keylogging). Proces može registrovati `CGEventTap` da zabeleži svaki pritisak tastera u bilo kojoj aplikaciji, uključujući lozinke, brojeve kreditnih kartica i privatne poruke.

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Allows **čitati buffer prikaza** — praviti screenshot-ove i snimati video ekrana bilo koje aplikacije, uključujući sigurna tekstualna polja. U kombinaciji sa OCR, ovo može automatski izdvojiti lozinke i osetljive podatke sa ekrana.

> [!WARNING]
> Starting with macOS Sonoma, screen capture shows a persistent menu bar indicator. On older versions, screen recording can be completely silent.

### **`kTCCServiceCamera`**

Allows **hvatanje fotografija i videa** sa ugrađene kamere ili povezanih USB kamera. Code injection u binarni fajl sa camera entitle-om omogućava tihu vizuelnu nadzor.

### **`kTCCServiceMicrophone`**

Allows **snimanje zvuka** sa svih ulaznih uređaja. Pozadinski daemoni sa mic pristupom omogućavaju stalan ambijentalni audio nadzor bez vidljivog prozora aplikacije.

### **`kTCCServiceLocation`**

Allows upitivanje fizičke lokacije uređaja putem Wi‑Fi triangulacije ili Bluetooth beacon-a. Kontinuirano nadgledanje otkriva adrese doma/posla, obrasce putovanja i dnevne rutine.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Pristup **Contacts** (imena, emailovi, telefoni — koristan za spear-phishing), **Calendar** (rasporedi sastanaka, liste učesnika), i **Photos** (lične fotografije, screenshot-ovi koji mogu sadržati kredencijale, metadata lokacije).

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** slabe App Sandbox tako što omogućavaju komunikaciju sa sistemskim Mach/XPC servisima koje sandbox inače blokira. Ovo je the **primary sandbox escape primitive** — kompromitovana sandboxovana aplikacija može koristiti mach-lookup izuzetke da dosegne privilegovane daemone i iskoristi njihove XPC interfejse.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Za detaljan lanac eksploatacije: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, pogledajte:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** omogućavaju user-space binarnim drajverima da komuniciraju direktno sa kernelom preko IOKit interfejsa. DriverKit binari upravljaju hardverom: USB, Thunderbolt, PCIe, HID uređaji, zvuk i mreže.

Kompromitovanje DriverKit binarnog fajla omogućava:
- **Kernel attack surface** putem neispravnih `IOConnectCallMethod` poziva
- **USB device spoofing** (emulacija tastature za HID injection)
- **DMA attacks** kroz PCIe/Thunderbolt interfejse
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Za detaljnu IOKit/DriverKit eksploataciju, pogledajte:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
