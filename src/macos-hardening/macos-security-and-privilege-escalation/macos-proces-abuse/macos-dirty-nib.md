# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**Vir verdere besonderhede oor die tegniek, kyk na die oorspronklike pos van:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) en die volgende pos deur [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Hier is 'n opsomming:

### Wat is Nib-lêers

Nib (kort vir NeXT Interface Builder) lêers, deel van Apple se ontwikkelings-ekosisteem, is bedoel om **UI-elemente** en hul interaksies in toepassings te definieer. Hulle sluit geserialiseerde voorwerpe soos vensters en knoppies in, en word tydens uitvoering gelaai. Ten spyte van hul voortgesette gebruik, beveel Apple nou Storyboards aan vir 'n meer omvattende visualisering van UI-stroom.

Die hoof Nib-lêer word in die waarde **`NSMainNibFile`** binne die `Info.plist` lêer van die toepassing verwys en word gelaai deur die funksie **`NSApplicationMain`** wat in die `main` funksie van die toepassing uitgevoer word.

### Dirty Nib Inspuitingsproses

#### Skep en Stel 'n NIB-lêer op

1. **Beginopstelling**:
- Skep 'n nuwe NIB-lêer met XCode.
- Voeg 'n voorwerp by die koppelvlak, stel sy klas op `NSAppleScript`.
- Konfigureer die aanvanklike `source` eienskap via Gebruiker Gedefinieerde Runtime Attribuut.
2. **Kode-uitvoering Gadget**:
- Die opstelling fasiliteer die uitvoering van AppleScript op aanvraag.
- Integreer 'n knoppie om die `Apple Script` voorwerp te aktiveer, spesifiek die `executeAndReturnError:` selektor te aktiveer.
3. **Toetsing**:

- 'n Eenvoudige Apple Script vir toetsdoeleindes:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

- Toets deur in die XCode-debugger te loop en op die knoppie te klik.

#### Teiken 'n Toepassing (Voorbeeld: Pages)

1. **Voorbereiding**:
- Kopieer die teiken-app (bv. Pages) na 'n aparte gids (bv. `/tmp/`).
- Begin die app om Gatekeeper-probleme te omseil en dit te kas.
2. **Oorskrywing van NIB-lêer**:
- Vervang 'n bestaande NIB-lêer (bv. About Panel NIB) met die vervaardigde DirtyNIB-lêer.
3. **Uitvoering**:
- aktiveer die uitvoering deur met die app te interaksie (bv. die `About` menu-item te kies).

#### Bewys van Konsep: Toegang tot Gebruikersdata

- Wysig die AppleScript om toegang te verkry tot en gebruikersdata, soos foto's, te onttrek, sonder gebruikers toestemming.

### Kode Voorbeeld: Kwaadwillige .xib-lêer

- Toegang tot en hersien 'n [**voorbeeld van 'n kwaadwillige .xib-lêer**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) wat die uitvoering van arbitrêre kode demonstreer.

### Ander Voorbeeld

In die pos [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) kan jy 'n tutoriaal vind oor hoe om 'n dirty nib te skep.&#x20;

### Aanspreek van Beginbeperkings

- Beginbeperkings hinder app-uitvoering vanaf onverwagte plekke (bv. `/tmp`).
- Dit is moontlik om apps te identifiseer wat nie deur Beginbeperkings beskerm word nie en hulle te teiken vir NIB-lêer inspuiting.

### Addisionele macOS Beskermings

Vanaf macOS Sonoma, is wysigings binne App-pakkette beperk. egter, vroeëre metodes het behels:

1. Kopieer die app na 'n ander plek (bv. `/tmp/`).
2. Hernoem gidse binne die app-pakket om aanvanklike beskermings te omseil.
3. Na die uitvoering van die app om by Gatekeeper te registreer, wysig die app-pakket (bv. vervang MainMenu.nib met Dirty.nib).
4. Hernoem gidse terug en herloop die app om die ingespuite NIB-lêer uit te voer.

**Let wel**: Onlangs macOS-opdaterings het hierdie uitbuiting verminder deur lêerwysigings binne app-pakkette na Gatekeeper-kas te voorkom, wat die uitbuiting ondoeltreffend maak.

{{#include ../../../banners/hacktricks-training.md}}
