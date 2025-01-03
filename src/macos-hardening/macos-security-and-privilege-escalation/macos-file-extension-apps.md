# macOS Lêeruitbreiding & URL skema app hanteerders

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Databasis

Dit is 'n databasis van al die geïnstalleerde toepassings in die macOS wat ondervra kan word om inligting oor elke geïnstalleerde toepassing te verkry, soos URL skemas wat dit ondersteun en MIME tipes.

Dit is moontlik om hierdie databasis te dump met:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Of deur die hulpmiddel [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** is die brein van die databasis. Dit bied **verskeie XPC dienste** soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, en meer. Maar dit **vereis ook sekere regte** vir toepassings om die blootgestelde XPC funksies te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om standaard toepassings vir mime tipes of url skemas en ander te verander.

**`/System/Library/CoreServices/launchservicesd`** eis die diens `com.apple.coreservices.launchservicesd` en kan ondervra word om inligting oor lopende toepassings te verkry. Dit kan ondervra word met die stelselhulpmiddel /**`usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Lêeruitbreiding & URL skema toepassingshanterings

Die volgende lyn kan nuttig wees om die toepassings te vind wat lêers kan oopmaak, afhangende van die uitbreiding:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Of gebruik iets soos [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Jy kan ook die uitbreidings wat deur 'n toepassing ondersteun word, nagaan deur:
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
