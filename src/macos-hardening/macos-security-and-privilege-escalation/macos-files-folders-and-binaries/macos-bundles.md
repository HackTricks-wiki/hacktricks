# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Bundles in macOS dien as houers vir 'n verskeidenheid hulpbronne, insluitend toepassings, biblioteke en ander nodige lêers, wat hulle as enkele voorwerpe in Finder laat verskyn, soos die bekende `*.app` lêers. Die mees algemene bundle is die `.app` bundle, hoewel ander tipes soos `.framework`, `.systemextension`, en `.kext` ook algemeen voorkom.

### Essensiële Komponente van 'n Bundle

Binne 'n bundle, veral binne die `<application>.app/Contents/` gids, is 'n verskeidenheid belangrike hulpbronne gehuisves:

- **\_CodeSignature**: Hierdie gids stoor kode-handtekening besonderhede wat noodsaaklik is om die integriteit van die toepassing te verifieer. Jy kan die kode-handtekening inligting inspekteer met opdragte soos: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
- **MacOS**: Bevat die uitvoerbare binêre van die toepassing wat loop wanneer die gebruiker interaksie het.
- **Resources**: 'n Bewaarplek vir die toepassing se gebruikerskoppelvlak komponente, insluitend beelde, dokumente, en koppelvlak beskrywings (nib/xib lêers).
- **Info.plist**: Dien as die toepassing se hoofkonfigurasielêer, wat noodsaaklik is vir die stelsel om die toepassing korrek te herken en mee te kommunikeer.

#### Belangrike Sleutels in Info.plist

Die `Info.plist` lêer is 'n hoeksteen vir toepassing konfigurasie, wat sleutels soos bevat:

- **CFBundleExecutable**: Gee die naam van die hoof uitvoerbare lêer geleë in die `Contents/MacOS` gids.
- **CFBundleIdentifier**: Verskaf 'n globale identifiseerder vir die toepassing, wat wyd deur macOS vir toepassing bestuur gebruik word.
- **LSMinimumSystemVersion**: Dui die minimum weergawe van macOS aan wat benodig word vir die toepassing om te loop.

### Verken Bundles

Om die inhoud van 'n bundle, soos `Safari.app`, te verken, kan die volgende opdrag gebruik word: `bash ls -lR /Applications/Safari.app/Contents`

Hierdie verkenning onthul gidse soos `_CodeSignature`, `MacOS`, `Resources`, en lêers soos `Info.plist`, elk wat 'n unieke doel dien van die beveiliging van die toepassing tot die definisie van sy gebruikerskoppelvlak en operasionele parameters.

#### Addisionele Bundle Gidse

Benewens die algemene gidse, kan bundles ook insluit:

- **Frameworks**: Bevat gebundelde frameworks wat deur die toepassing gebruik word. Frameworks is soos dylibs met ekstra hulpbronne.
- **PlugIns**: 'n Gids vir plug-ins en uitbreidings wat die toepassing se vermoëns verbeter.
- **XPCServices**: Hou XPC dienste wat deur die toepassing gebruik word vir buite-proses kommunikasie.

Hierdie struktuur verseker dat al die nodige komponente binne die bundle ingesluit is, wat 'n modulaire en veilige toepassing omgewing fasiliteer.

Vir meer gedetailleerde inligting oor `Info.plist` sleutels en hul betekenisse, bied die Apple ontwikkelaar dokumentasie uitgebreide hulpbronne: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{{#include ../../../banners/hacktricks-training.md}}
