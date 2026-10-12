# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Zašto se razmotavanje steka zasnovano na metapodacima može lažirati

Neki macOS bezbednosni alati prepuštaju prikupljanje stekova niti procesu `/usr/sbin/spindump` ili se na drugi način oslanjaju na uobičajeni unwinder zasnovan na metapodacima. Implant može da iskoristi tu granicu poverenja tako što na svoj stek postavi sintetičke zapise usklađene s ABI-jem, zbog čega izgleda kao da je osetljivi API pozvan kroz funkcije koje je napadač odabrao u dyld-u i učitanim Apple framework-ovima, a ne iz koda implanta bez podrške. Ovo je obmana telemetrije, a ne izmena izvršne datoteke ili njenih metapodataka za razmotavanje steka.<sup>[[1]](#references)</sup>

Pogledajte [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) za kontekst na strani prikupljanja.

Unwinder ne dokazuje da je zapis napravljen prologom koji je generisao kompajler. On uzastopno koristi trenutni `PC` da odabere Mach-O recept, primenjuje taj recept na `SP`, `x29`, `x30`, memoriju steka i sve navedene nepromenljive registre, pa zatim koristi oporavljeni `PC` pozivaoca da odabere sledeći recept. Ako memorija koju kontroliše napadač zadovoljava svaki od odabranih recepata, dobijeni lanac može biti strukturno ispravan i simbolizovan, iako se ti pozivi nikada nisu dogodili.<sup>[[1]](#references)</sup>

## Stanje ARM64 okvira

[Pregled ARM64 asemblera](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) opisuje uloge registara i konvenciju pozivanja. Kod uobičajenog okvira napravljenog instrukcijom `stp x29, x30, [sp, #-16]!`, a zatim `mov x29, sp`, Kanonska adresa okvira (CFA), koja predstavlja `SP` pozivaoca pri ulasku, iznosi `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Zapisi okvira formiraju povezanu listu preko `[FP]`, ali slepo praćenje te liste nije dovoljno: leaf funkcije mogu biti bez okvira, tail call-ovi mogu ukloniti logičke prelaze, a neuobičajeni rasporedi koriste DWARF CFI. Pravilo koje određuje trenutna adresa određuje da li unwinder uopšte čita lanac FP vrednosti.<sup>[[1]](#references)[[4]](#references)</sup>

## Izbor Mach-O unwind pravila

Konačno povezane slike čuvaju compact unwind podatke u `__TEXT,__unwind_info`. Zaglavlje sekcije pokazuje na first-level indeks funkcija; svaki opseg indeksa pokazuje na regularnu (`kind=2`) ili komprimovanu (`kind=3`) second-level stranicu. Rasporedi koje compact unwind ne može da opiše koriste FDE i call-frame instrukcije u `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Za svaki mogući runtime PC:<sup>[[1]](#references)[[2]](#references)</sup>

1. Uklonite ili normalizujte ARM64e PAC bitove samo za potrebe pretrage.
2. Pronađite učitani Mach-O čiji izvršni opseg `__TEXT` sadrži adresu.
3. Izračunajte `functionOffset = normalizedPC - loadedImageBase` i odbacite negativne rezultate ili vrednosti veće od `UINT32_MAX`.
4. Izaberite first-level opseg koji zadovoljava uslov `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Parsirajte navedenu second-level stranicu, izaberite najbliži unos čiji početak nije veći od ofseta i proverite da je adresa manja od početka sledećeg unosa ili kraja first-level opsega.
6. Dekodirajte taj unos i konstruišite tačno stanje koje on opisuje.

Kada adresa potiče od sačuvanog LR-a, za pretragu se može koristiti `PC-1`, tako da adresa neposredno posle poziva ostane u opsegu koji pokriva pozivalac. To menja izbor pravila, a ne nijedan ofset na steku.<sup>[[1]](#references)</sup>

Parser mora da proverava granice svakog zaglavlja i niza, zahteva verziju sekcije `1`, uzme u obzir završni first-level sentinel, odbaci nulti ofset second-level stranice i razlikuje regularne od komprimovanih stranica. Na regularnoj stranici, `entryPageOffset` je relativan u odnosu na početak te stranice, dok je first-level page offset relativan u odnosu na početak `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

Široki režim je `encoding & 0x0F000000`. Trenutne LLVM definicije obuhvataju sledeće režime; parser ne bi trebalo da tretira svaku vrednost koja nije DWARF kao klasičan okvir:<sup>[[1]](#references)[[2]](#references)</sup>

| Režim | Vrednost | Oporavak pozivaoca |
| --- | --- | --- |
| Nema compact pravila | `0x00000000` | Zaustavite se ili koristite nezavisni fallback. |
| Bez okvira | `0x02000000` | Dodajte kodiranu veličinu steka trenutnom `SP`-u; caller PC je aktivni LR. |
| DWARF | `0x03000000` | Izvršite FDE/CFI identifikovan donja 24 bita. |
| Okvir | `0x04000000` | Pročitajte konvencionalni `x29` zapis okvira. |
| arm64e okvir sa autentifikovanim LR opsegom | `0x05000000` | Obradite `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; njegovo polje ofseta locira `pacibsppc` unutar pokrivenog opsega. |

Za režim bez okvira, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. U režimu okvira, pet najnižih bitova označava uzastopne sačuvane GPR parove `x19/x20` do `x27/x28`; bitovi `0x100-0x800` slično označavaju parove `d8-d15`. Ti sačuvani registri možda nisu potrebni za pronalaženje sledećeg PC-a, ali uverljivo virtuelno stanje pozivaoca mora da zadovolji svako polje koje potrošač rekonstruiše.<sup>[[1]](#references)[[2]](#references)</sup>

## Konstrukcija sintetičkih zapisa u režimu okvira

Konstrukcija obrće rad unwinder-a, umesto da pretražuje stek u potrazi za vrednostima koje liče na adrese:<sup>[[1]](#references)</sup>

1. Izaberite stvarni izvršni PC u trenutno učitanoj slici.
2. Dekodirajte pravilo koje pokriva taj precizni PC ili adresu poziva.
3. Alocirajte sintetički zapis sa potrebnim poravnanjem i CFA odnosom.
4. Upišite sledeći sintetički FP u `[FP]`, sačuvani caller PC tog okvira u `[FP+8]` i sve GPR/FPR vrednosti sačuvane ispod FP, kako je navedeno kodiranjem.
5. Povežite više zapisa i postavite prvi zapis u aktivni `x29`.
6. Podesite aktivni LR i API povratnu putanju tako da unwinding uđe u izabrani lanac, a da se izvršavanje i dalje može bezbedno obnoviti.

Na primer, `0x04000001` označava režim okvira sa parom `x19/x20`. Odgovarajuća transformacija stanja i potrebna memorija su:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Adresa koja izgleda legitimno zato nije dovoljna. Svaki pronađeni PC postaje ključ za sledeću pretragu, pa jedna adresa čije se kodiranje ne slaže sa falsifikovanim rasporedom prekida lanac ili navodi potrošača da rekonstruiše nedosledno stanje registara.<sup>[[1]](#references)</sup>

## ARM64e PAC zahtevi

PAC čuva vrednost integriteta zasnovanu na ključu u inače neiskorišćenim bitovima pokazivača; ne šifruje adresu. Clang-ova arm64e šema povratnih adresa koristi ključ instrukcija B i stack pointer pri ulasku u funkciju kao discriminator. Kod uobičajenog frejma, taj početni `SP` je CFA, pa je sačuvani LR na `[FP+8]` vezan za `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Svaki sintetički LR mora biti potpisan nezavisno, jer premeštanje već potpisanog LR-a u frejm sa drugačijim CFA menja diskriminator i dovodi do neuspešne autentifikacije. `ptrauth_strip()` je pogodan za normalizaciju adresa i pretragu simbola, ali **ne** potvrđuje autentičnost; svaki stvarni povratak ili autentifikovana indirektna grana mora da koristi ključ i modifikator koji se očekuju pri tom konkretnom prelazu.<sup>[[1]](#references)[[3]](#references)</sup>

Tipična arm64e funkcija koja nije leaf potpisuje LR pre nego što ga sačuva i autentifikuje nakon vraćanja ulaznog SP-a:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline i restore bridge

Sintetički zapisi treba samo da zadovolje unwinder; ne sadrže kompletan kontekst izvršavanja. Povratak iz osetljivog API-ja direktno u falsifikovane pozivaoca obično bi doveo do pada. Zato se u praktičnom rešenju neposredno ispod API-ja postavlja gadget frame: API se vraća u izvršivi kod učitanog framework-a, a taj gadget skače preko kontrolisanog callee-saved registra do restore bridge-a u implant-u.<sup>[[1]](#references)</sup>

Koristan gadget čuva LR i prenosi kontrolu preko kontrolisanog registra, na primer odgovarajućom `br`, `braa` ili `brab` sekvencom. Restore bridge mora da povrati originalne vrednosti `x19-x30` i `SP` pre nego što nastavi izvršavanje implant-a. Na arm64e, svaki autentifikovani povratak ili skok na putanji od API-ja do gadget-a, od gadget-a do bridge-a i od bridge-a do implant-a zahteva pokazivač potpisan ključem i diskriminatorom koje koristi ta instrukcija.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Rezultat predstavlja važan propust na granici poverenja za detekcije zasnovane na steku: lanac može sadržati isključivo mapirane PC-jeve Apple okvira čije se simboličko značenje može odrediti, a da pritom ne predstavlja stvarni tok kontrole. Zato izlaz unwind-a treba potkrepiti nezavisnim dokazima o poreklu izvršne memorije niti i stvarnim prelazima oko osetljivog API-ja, umesto da se tretira kao trag izvršavanja.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Interni mehanizmi steka ARM64 i obfuskacija na Apple Silicon uređajima](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Definicije kodiranja za Mach-O compact unwind](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Autentifikacija pokazivača](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Standard za pozivanje procedura za 64-bitnu arhitekturu Arm](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
