# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**Za više detalja o tehnici pogledajte originalni post sa:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) i sledeći post od [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Evo sažetak:

### Šta su Nib datoteke

Nib (skraćeno od NeXT Interface Builder) datoteke, deo Apple-ovog razvojnog ekosistema, namenjene su definisanju **UI elemenata** i njihovih interakcija u aplikacijama. One obuhvataju serijalizovane objekte kao što su prozori i dugmad, i učitavaju se u vreme izvođenja. I pored njihove stalne upotrebe, Apple sada preporučuje Storyboards za sveobuhvatniju vizualizaciju UI toka.

Glavna Nib datoteka se poziva u vrednosti **`NSMainNibFile`** unutar `Info.plist` datoteke aplikacije i učitava je funkcija **`NSApplicationMain`** koja se izvršava u `main` funkciji aplikacije.

### Proces Injekcije Prljavog Niba

#### Kreiranje i Postavljanje NIB Datoteke

1. **Početna Konfiguracija**:
- Kreirajte novu NIB datoteku koristeći XCode.
- Dodajte objekat u interfejs, postavljajući njegovu klasu na `NSAppleScript`.
- Konfigurišite početnu `source` svojstvo putem User Defined Runtime Attributes.
2. **Gadget za Izvršavanje Koda**:
- Konfiguracija omogućava pokretanje AppleScript-a na zahtev.
- Integrisati dugme za aktiviranje `Apple Script` objekta, posebno pokrećući `executeAndReturnError:` selektor.
3. **Testiranje**:

- Jednostavan Apple Script za testiranje:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

- Testirajte pokretanjem u XCode debageru i klikom na dugme.

#### Ciljanje Aplikacije (Primer: Pages)

1. **Priprema**:
- Kopirajte ciljan app (npr. Pages) u poseban direktorijum (npr. `/tmp/`).
- Pokrenite aplikaciju da biste izbegli probleme sa Gatekeeper-om i keširali je.
2. **Prepisivanje NIB Datoteke**:
- Zamenite postojeću NIB datoteku (npr. About Panel NIB) sa kreiranom DirtyNIB datotekom.
3. **Izvršavanje**:
- Pokrenite izvršavanje interakcijom sa aplikacijom (npr. odabirom `About` menija).

#### Dokaz Koncepta: Pristup Korisničkim Podacima

- Izmenite AppleScript da pristupi i izvuče korisničke podatke, kao što su fotografije, bez pristanka korisnika.

### Uzorak Koda: Maliciozna .xib Datoteka

- Pristupite i pregledajte [**uzorak maliciozne .xib datoteke**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) koja demonstrira izvršavanje proizvoljnog koda.

### Drugi Primer

U postu [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) možete pronaći tutorijal o tome kako kreirati prljavi nib.&#x20;

### Rešavanje Ograničenja Pokretanja

- Ograničenja pokretanja sprečavaju izvršavanje aplikacija iz neočekivanih lokacija (npr. `/tmp`).
- Moguće je identifikovati aplikacije koje nisu zaštićene Ograničenjima pokretanja i ciljati ih za injekciju NIB datoteka.

### Dodatne macOS Zaštite

Od macOS Sonoma nadalje, modifikacije unutar App bundle-a su ograničene. Međutim, ranije metode su uključivale:

1. Kopiranje aplikacije na drugo mesto (npr. `/tmp/`).
2. Preimenovanje direktorijuma unutar app bundle-a kako bi se zaobišle početne zaštite.
3. Nakon pokretanja aplikacije da se registruje sa Gatekeeper-om, modifikovanje app bundle-a (npr. zamenjivanje MainMenu.nib sa Dirty.nib).
4. Ponovno preimenovanje direktorijuma i ponovo pokretanje aplikacije da izvrši injektovanu NIB datoteku.

**Napomena**: Nedavne macOS nadogradnje su ublažile ovu eksploataciju sprečavanjem modifikacija datoteka unutar app bundle-a nakon keširanja Gatekeeper-a, čineći eksploataciju neefikasnom.

{{#include ../../../banners/hacktricks-training.md}}
