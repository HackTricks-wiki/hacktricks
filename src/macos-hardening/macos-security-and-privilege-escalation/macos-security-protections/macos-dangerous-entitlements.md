# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Kumbuka kwamba entitlements zinazohusisha **`com.apple`** hazipatikani kwa wahusika wa tatu, ni Apple pekee inayoweza kuzitoa.

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** inaruhusu **kuzidi SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** inaruhusu **kuzidi SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (iliyokuwa inaitwa `task_for_pid-allow`)**

Entitlement hii inaruhusu kupata **task port kwa mchakato wowote**, isipokuwa kernel. Angalia [**hii kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Entitlement hii inaruhusu michakato mingine yenye entitlement **`com.apple.security.cs.debugger`** kupata task port ya mchakato unaotendewa na binary yenye entitlement hii na **kuingiza msimbo ndani yake**. Angalia [**hii kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps zenye Entitlement ya Zana za Ufuatiliaji zinaweza kuita `task_for_pid()` ili kupata task port halali kwa apps zisizosainiwa na wahusika wa tatu zenye entitlement ya `Get Task Allow` iliyowekwa kuwa `true`. Hata hivyo, hata na entitlement ya zana za ufuatiliaji, debuggers **haziwezi kupata task ports** za michakato ambazo **hazina entitlement ya `Get Task Allow`**, na hivyo kulindwa na Ulinzi wa Uthibitisho wa Mfumo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Entitlement hii inaruhusu **kupakia frameworks, plug-ins, au maktaba bila kusainiwa na Apple au kusainiwa na Team ID** sawa na executable kuu, hivyo mshambuliaji anaweza kutumia upakiaji wa maktaba fulani kuingiza msimbo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Entitlement hii ni sawa sana na **`com.apple.security.cs.disable-library-validation`** lakini **badala** ya **kuondoa** uthibitisho wa maktaba moja kwa moja, inaruhusu mchakato **kuita `csops` system call kuondoa**.\
Angalia [**hii kwa maelezo zaidi**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement hii inaruhusu **kutumia DYLD environment variables** ambazo zinaweza kutumika kuingiza maktaba na msimbo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[**Kulingana na blog hii**](https://objective-see.org/blog/blog_0x4C.html) **na** [**blog hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), entitlements hizi zinaruhusu **kubadilisha** hifadhidata ya **TCC**.

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Entitlements hizi zinaruhusu **kufunga programu bila kuomba ruhusa** kwa mtumiaji, ambayo inaweza kuwa na manufaa kwa **kuinua mamlaka**.

### `com.apple.private.security.kext-management`

Entitlement inayohitajika kuomba **kernel kupakia kiendelezi cha kernel**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** inaruhusu kuwasiliana na huduma ya XPC **`com.apple.iCloudHelper`** ambayo itatoa **tokens za iCloud**.

**iMovie** na **Garageband** walikuwa na entitlement hii.

Kwa maelezo zaidi kuhusu exploit ya **kupata tokens za icloud** kutoka kwa entitlement hiyo angalia mazungumzo: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu kufanya nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imeelezwa kuwa hii inaweza kutumika** kuboresha maudhui yaliyolindwa na SSV baada ya kuanzisha upya. Ikiwa unajua jinsi inavyofanya, tafadhali tuma PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imeelezwa kuwa hii inaweza kutumika** kuboresha maudhui yaliyolindwa na SSV baada ya kuanzisha upya. Ikiwa unajua jinsi inavyofanya, tafadhali tuma PR!

### `keychain-access-groups`

Entitlement hii inataja **makundi ya keychain** ambayo programu ina ufikiaji:
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

Inatoa ruhusa za **Upatikanaji wa Disk Kamili**, moja ya ruhusa za juu zaidi za TCC unazoweza kuwa nazo.

### **`kTCCServiceAppleEvents`**

Inaruhusu programu kutuma matukio kwa programu nyingine ambazo mara nyingi hutumiwa kwa **kujiendesha kazi**. Kwa kudhibiti programu nyingine, inaweza kutumia ruhusa zilizotolewa kwa programu hizi nyingine.

Kama kufanya ziombwe mtumiaji kwa nywila yake:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Or kufanya ziara **vitendo vya kawaida**.

### **`kTCCServiceEndpointSecurityClient`**

Inaruhusu, kati ya ruhusa nyingine, **kuandika hifadhidata ya TCC ya watumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambayo inabadilisha njia ya folda yake ya nyumbani na hivyo inaruhusu **kuzidi TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Inaruhusu kubadilisha faili ndani ya pakiti za programu (ndani ya app.app), ambayo **imezuiliwa kwa kawaida**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani mwenye ufikiaji huu katika _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Mchakato utaweza **kutumia vipengele vya upatikanaji vya macOS**, ambayo inamaanisha kwamba kwa mfano ataweza kubonyeza funguo. Hivyo anaweza kuomba ufikiaji wa kudhibiti programu kama Finder na kuidhinisha mazungumzo na ruhusa hii.

## Medium

### `com.apple.security.cs.allow-jit`

Ruhusa hii inaruhusu **kuunda kumbukumbu ambayo inaweza kuandikwa na kutekelezwa** kwa kupitisha bendera ya `MAP_JIT` kwa kazi ya mfumo ya `mmap()`. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ruhusa hii inaruhusu **kufunika au kurekebisha msimbo wa C**, kutumia **`NSCreateObjectFileImageFromMemory`** ambayo imekuwa isiyotumika kwa muda mrefu (ambayo kimsingi si salama), au kutumia mfumo wa **DVDPlayback**. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Kujumuisha ruhusa hii kunafichua programu yako kwa udhaifu wa kawaida katika lugha za msimbo zisizo salama. Fikiria kwa makini ikiwa programu yako inahitaji ubaguzi huu.

### `com.apple.security.cs.disable-executable-page-protection`

Ruhusa hii inaruhusu **kubadilisha sehemu za faili zake za kutekelezwa** kwenye diski ili kutoka kwa nguvu. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Ruhusa ya Kuondoa Ulinzi wa Kumbukumbu ya Kutekelezwa ni ruhusa kali ambayo inatoa ulinzi wa usalama wa msingi kutoka kwa programu yako, na kufanya iwezekane kwa mshambuliaji kuandika upya msimbo wa kutekelezwa wa programu yako bila kugundulika. Prefer ruhusa nyembamba ikiwa inawezekana.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ruhusa hii inaruhusu kuunganisha mfumo wa faili wa nullfs (uliozuiliwa kwa kawaida). Chombo: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na chapisho hili la blog, ruhusa hii ya TCC kwa kawaida hupatikana katika mfumo:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu mchakato **kuomba ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}

</details>
