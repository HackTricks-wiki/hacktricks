# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) je besplatan analizator digitalnih signala za GNU/Linux i macOS, namenjen izdvajanju informacija iz nepoznatih radio-signala. Podržava SDR uređaje preko SoapySDR-a i pruža alate za demodulaciju i analizu u realnom vremenu za FSK, PSK, ASK, analogni video, rafalne signale i analogne glasovne kanale.<sup>[[1]](#references)</sup>

### Osnovna konfiguracija

Nakon instalacije, postoji nekoliko stvari koje možete podesiti.\
U podešavanjima (drugo dugme kartice) izaberite **SDR uređaj** ili ulaznu datoteku, frekvenciju za podešavanje i brzinu uzorkovanja. Brzina do 2.56 Msps može biti praktična ako je računar podržava.

![Podešavanja SigDigger-a sa opcijama za SDR uređaj, ulaznu datoteku, frekvenciju i brzinu uzorkovanja](<../../images/image (245).png>)

U ponašanju GUI-ja preporučuje se da omogućite nekoliko opcija ako ih vaš računar podržava:

![SigDigger - Osnovna konfiguracija: U ponašanju GUI-ja preporučuje se da omogućite nekoliko opcija ako ih vaš računar podržava](<../../images/image (472).png>)

> [!TIP]
> Ako primetite da vaš računar ne snima signal, pokušajte da isključite OpenGL i smanjite brzinu uzorkovanja.

### Upotreba

- Da biste **snimili deo signala i analizirali ga**, držite dugme "Push to capture" pritisnutim onoliko dugo koliko je potrebno.

![Osnovna konfiguracija - Upotreba: Da biste snimili deo signala i analizirali ga, držite dugme "Push to capture" pritisnutim onoliko dugo koliko je potrebno](<../../images/image (960).png>)

- **Tuner** u SigDigger-u pomaže da **uhvatite bolje signale** (ali može i da ih pogorša). U idealnom slučaju počnite od 0 i **postepeno povećavajte vrednost dok** uvedeni **šum** ne postane **veći** od potrebnog **poboljšanja signala**.

![Kontrola tunera u SigDigger-u podešena da poboljša uhvaćeni radio-signal](<../../images/image (1099).png>)

### Sinhronizacija sa radio-kanalom

Pomoću [**SigDigger** ](https://github.com/BatchDrake/SigDigger) sinhronizujte se sa kanalom koji želite da slušate, podesite opciju "Baseband audio preview", podesite propusni opseg tako da obuhvati sve poslate informacije, a zatim postavite Tuner na nivo pre nego što šum počne značajno da raste:<sup>[[1]](#references)</sup>

![SigDigger sinhronizovan sa radio-kanalom, uz podešene opcije Baseband audio preview i propusnog opsega](<../../images/image (585).png>)

## Zanimljivi trikovi

- Kada uređaj šalje rafale informacija, **prvi deo je obično preambula**, zato **ne morate da brinete** ako **u njemu ne pronađete informacije** ili ako **sadrži greške**.
- U frejmovima informacija obično bi trebalo da **pronađete različite frejmove međusobno dobro poravnate**:

![Sinhronizacija sa radio-kanalom - Zanimljivi trikovi: U frejmovima informacija obično bi trebalo da pronađete različite frejmove međusobno dobro poravnate](<../../images/image (1076).png>)

![Sinhronizacija sa radio-kanalom - Zanimljivi trikovi: U frejmovima informacija obično bi trebalo da pronađete različite frejmove međusobno dobro poravnate](<../../images/image (597).png>)

- **Nakon oporavka prelaza nivoa, možda ćete morati da ih dekodirate.** Kod Manchester encoding-a, jedan smer prelaza predstavlja `0`, a suprotan smer predstavlja `1`; tačan polaritet zavisi od korišćene konvencije.
- Preambula može sadržati niz uzoraka sa istim nivoom čak i kada se u korisnom sadržaju koristi Manchester encoding, zato pre dekodiranja utvrdite granicu frejma.

### Otkrivanje tipa modulacije pomoću IQ-a

Postoje 3 načina za kodiranje informacija u signalima: modulacijom **amplitude**, **frekvencije** ili **faze**.\
Ako proveravate signal, postoji više načina da pokušate da utvrdite šta se koristi za kodiranje informacija (više načina je navedeno ispod), ali dobar način je da proverite IQ grafikon.

![IQ grafikon u SigDigger-u koji se koristi za utvrđivanje da li signal koristi amplitudnu, frekvencijsku ili faznu modulaciju](<../../images/image (788).png>)

- **Otkrivanje AM-a**: Ako se na IQ grafikonu, na primer, pojave **2 kruga** (verovatno jedan u 0, a drugi na drugoj amplitudi), to može značiti da je signal AM. Razlog je to što je na IQ grafikonu rastojanje između 0 i kruga amplituda signala, pa se različite korišćene amplitude lako uočavaju.
- **Otkrivanje PM-a**: Kao na prethodnoj slici, ako pronađete male krugove koji nisu međusobno povezani, to verovatno znači da se koristi fazna modulacija. Na IQ grafikonu ugao između tačke i koordinatnog početka (0,0) predstavlja fazu signala, što znači da se koriste 4 različite faze.
  - Imajte na umu da, ako su informacije kodirane promenom faze, a ne samom fazom, nećete jasno videti različite faze.
- **Otkrivanje FM-a**: IQ nema polje za prikaz frekvencija (rastojanje od centra predstavlja amplitudu, a ugao fazu).\
  Zato bi za prepoznavanje FM-a na ovom grafikonu trebalo **uglavnom da vidite samo krug**.\
  Pored toga, frekvencijski pomak menja brzinu rotacije oko IQ kruga. Zato promena brzine ili smera rotacije u SigDigger-u može ukazivati na FM.

## Primer AM-a

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Otkrivanje AM-a

#### Provera omotača

Prilikom pregledanja AM podataka pomoću [**SigDigger**](https://github.com/BatchDrake/SigDigger), **omotač** signala može da otkrije različite nivoe amplitude. Primer signala prenosi informacije u obliku amplitudno modulisanih impulsa; jedan impuls izgleda ovako:<sup>[[1]](#references)</sup>

![Omotač AM signala u SigDigger-u sa jasno vidljivim nivoima amplitude impulsa](<../../images/image (590).png>)

A ovako izgleda deo simbola zajedno sa talasnim oblikom:

![Otkrivanje AM-a - Provera omotača: Ovako izgleda deo simbola zajedno sa talasnim oblikom](<../../images/image (734).png>)

#### Provera histograma

Možete **izabrati ceo deo signala** u kome se nalaze informacije, izabrati režim **Amplitude** i opciju **Selection**, pa kliknuti na **Histogram.** Možete uočiti da postoje samo 2 jasno definisana nivoa.

![Histogram amplitude u SigDigger-u koji prikazuje dva jasno definisana nivoa za izabrani AM signal](<../../images/image (264).png>)

Na primer, ako u ovom AM signalu izaberete Frequency umesto Amplitude, pronaći ćete samo 1 frekvenciju (informacije modulovane po frekvenciji ne bi mogle da koriste samo 1 frekvenciju).

![Histogram frekvencije u SigDigger-u za AM signal koji prikazuje jednu frekvenciju](<../../images/image (732).png>)

Ako pronađete mnogo frekvencija, signal verovatno nije FM; frekvencija signala se možda samo promenila zbog kanala.

#### Pomoću IQ-a

U ovom primeru možete videti **veliki krug**, ali i **mnogo tačaka u centru**.

![Provera histograma - Pomoću IQ-a: U ovom primeru možete videti veliki krug, ali i mnogo tačaka u centru](<../../images/image (222).png>)

### Određivanje brzine simbola

#### Sa jednim simbolom

Izaberite najmanji interval koji jasno obuhvata jedan simbol i proverite **Selection freq**. U ovom primeru vrednost iznosi 1.013 kHz, odnosno približno 1 kHz.

![Određivanje brzine simbola - Sa jednim simbolom: Izaberite najmanji interval koji jasno obuhvata jedan simbol i proverite "Selection freq". U ovom slučaju vrednost je 1.013 kHz (odnosno 1 kHz).](<../../images/image (78).png>)

#### Sa grupom simbola

Možete i da navedete broj simbola koje ćete izabrati, a SigDigger će izračunati frekvenciju jednog simbola (verovatno što je izabrano više simbola, to bolje). U ovom slučaju izabrao sam 10 simbola, a vrednost "Selection freq" iznosi 1.004 Khz:

![Izračunavanje brzine simbola u SigDigger-u pomoću izabrane grupe od deset simbola](<../../images/image (1008).png>)

### Dobijanje bitova

Nakon što utvrdite da je u pitanju AM i procenite **brzinu simbola**, izaberite deo signala, podesite uzorkovanje amplitude i nivoe odlučivanja, izaberite **Gardner clock recovery** i pritisnite **Sample**:

![Panel Get Bits u SigDigger-u podešen za AM uzorkovanje, brzinu simbola i Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** znači da će se koristiti brzina simbola koju ste prethodno odredili izborom intervala.
- **Manual** znači da će se koristiti navedena brzina simbola.
- U opciji **Fixed interval selection** navedite broj intervala koje treba izabrati; na osnovu toga će se izračunati brzina simbola.
- **Gardner clock recovery** je korisna podrazumevana opcija, ali joj je i dalje potrebna približna brzina simbola.

Kada pritisnete Sample, prikazaće se sledeće:

![Sa grupom simbola - Dobijanje bitova: Ovo se prikazuje nakon pritiska na Sample](<../../images/image (644).png>)

Da bi SigDigger razumeo **opseg nivoa koji nosi informacije**, kliknite na **niži nivo** i, ne puštajući dugme miša, prevucite do najvišeg nivoa:

![Izbor opsega nivoa u SigDigger-u, od nižeg nivoa amplitude do višeg](<../../images/image (439).png>)

Da postoje, na primer, **4 različita nivoa amplitude**, trebalo bi da podesite **Bits per symbol** na 2 i izaberete opseg od najnižeg do najvišeg nivoa.

Na kraju, **povećanjem** vrednosti **Zoom** i **promenom vrednosti Row size** možete da vidite bitove (možete i da ih sve izaberete i kopirate):

![Sa grupom simbola - Dobijanje bitova: Na kraju, povećanjem vrednosti Zoom i promenom vrednosti Row size možete da vidite bitove i da ih sve izaberete i kopirate](<../../images/image (276).png>)

Ako signal ima više od 1 bita po simbolu (na primer 2), SigDigger **ne može da zna koji simbol predstavlja** 00, 01, 10 ili 11, pa će za svaki koristiti različite **nijanse sive** (a ako kopirate bitove, koristiće **brojeve od 0 do 3**, koje ćete morati dodatno da obradite).

Kod linijskih kodiranja kao što je **Manchester**, svaki važeći par prelaza (`01` ili `10`) pretvorite u podatkovni bit prema konvenciji koju koristi protokol.

## Primer FM-a

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Otkrivanje FM-a

#### Provera frekvencija i talasnog oblika

Primer signala koji prenosi informacije modulisane u FM-u:

![Otkrivanje FM-a - Provera frekvencija i talasnog oblika: Primer signala koji prenosi informacije modulisane u FM-u](<../../images/image (725).png>)

Spektar jasno prikazuje **dve frekvencije**, iako ih može biti teško razlikovati na talasnom obliku u vremenskom domenu:

![FM talasni oblik u SigDigger-u na kome je teško direktno razlikovati dve frekvencije](<../../images/image (717).png>)

To se dešava zato što je snimak centriran između obe frekvencije, pa su njihovi frekvencijski pomaci približno suprotni:

![FM snimak u SigDigger-u koji prikazuje dve frekvencije sa približno suprotnim pomacima](<../../images/image (942).png>)

Ako je sinhronizovana frekvencija **bliža jednoj frekvenciji nego drugoj**, lako možete da vidite dve različite frekvencije:

![Otkrivanje FM-a - Provera frekvencija i talasnog oblika: Ako je sinhronizovana frekvencija bliža jednoj frekvenciji nego drugoj, lako možete da vidite dve različite frekvencije](<../../images/image (422).png>)

![Otkrivanje FM-a - Provera frekvencija i talasnog oblika: Ako je sinhronizovana frekvencija bliža jednoj frekvenciji nego drugoj, lako možete da vidite dve različite frekvencije](<../../images/image (488).png>)

#### Provera histograma

Ako proverite histogram frekvencija signala koji sadrži informacije, lako možete da vidite 2 različita signala:

![Provera frekvencija i talasnog oblika - Provera histograma: Ako proverite histogram frekvencija signala koji sadrži informacije, lako možete da vidite 2 različita signala](<../../images/image (871).png>)

U ovom slučaju, ako proverite **histogram amplitude**, pronaći ćete **samo jednu amplitudu**, pa signal **ne može biti AM** (ako pronađete mnogo amplituda, moguće je da je signal izgubio snagu tokom prenosa kroz kanal):

![Histogram amplitude u SigDigger-u za FM signal koji prikazuje jedan nivo amplitude](<../../images/image (817).png>)

Ovo je histogram faze, koji jasno pokazuje da signal nije fazno modulisan:

![Provera frekvencija i talasnog oblika - Provera histograma: Ovako izgleda histogram faze, koji jasno pokazuje da signal nije fazno modulisan](<../../images/image (996).png>)

#### Pomoću IQ-a

IQ nema polje za prikaz frekvencija (rastojanje od centra predstavlja amplitudu, a ugao fazu).\
Zato bi za prepoznavanje FM-a na ovom grafikonu trebalo **uglavnom da vidite samo krug**.\
Pored toga, frekvencijski pomak menja brzinu rotacije oko IQ kruga. Zato promena brzine ili smera rotacije u SigDigger-u može ukazivati na FM:

![IQ grafikon u SigDigger-u na kome se FM prikazuje kao promena brzine rotacije oko kruga](<../../images/image (81).png>)

### Određivanje brzine simbola

Da biste odredili brzinu simbola nakon što pronađete frekvencije koje nose simbole, možete da koristite **istu tehniku kao u primeru AM-a**.

### Dobijanje bitova

Kada **utvrdite da je signal frekvencijski modulisan** i odredite **brzinu simbola**, za dobijanje bitova možete da koristite **istu tehniku kao u primeru AM-a**.

## References

- [1] [SigDigger - Besplatan analizator digitalnih signala za GNU/Linux i macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
