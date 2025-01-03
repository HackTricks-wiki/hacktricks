# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Hii ni database ya programu zote zilizowekwa kwenye macOS ambazo zinaweza kuulizwa ili kupata taarifa kuhusu kila programu iliyowekwa kama vile mipango ya URL inayounga mkono na aina za MIME.

Inawezekana kutoa data hii kwa:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Au kutumia zana [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ni ubongo wa hifadhidata. Inatoa **huduma kadhaa za XPC** kama vile `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na zaidi. Lakini pia **inahitaji baadhi ya ruhusa** kwa programu ili kuweza kutumia kazi za XPC zilizofichuliwa, kama vile `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` kubadilisha programu za kawaida kwa aina za mime au mipango ya url na zingine.

**`/System/Library/CoreServices/launchservicesd`** inadai huduma `com.apple.coreservices.launchservicesd` na inaweza kuulizwa ili kupata taarifa kuhusu programu zinazotembea. Inaweza kuulizwa kwa zana ya mfumo /**`usr/bin/lsappinfo`** au kwa kutumia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Wakala wa programu za Kiambatisho cha Faili & mpango wa URL

Mistari ifuatayo inaweza kuwa na manufaa kutafuta programu ambazo zinaweza kufungua faili kulingana na kiambatisho:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Au tumia kitu kama [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Unaweza pia kuangalia nyongeza zinazoungwa mkono na programu kwa kufanya:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
{{#include ../../banners/hacktricks-training.md}}
