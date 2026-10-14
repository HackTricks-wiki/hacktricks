# Radio

{{#include ../../banners/hacktricks-training.md}}

Za rad specifičan za protokol nakon identifikacije signala, pogledajte [RFID/NFC, sub-GHz, infrared, BLE, and LoRaWAN testing](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) je besplatan digitalni analizator signala za GNU/Linux i macOS, namenjen izdvajanju informacija iz nepoznatih radio-signala. Podržava SDR uređaje preko SoapySDR-a i pruža alate za demodulaciju i analizu u realnom vremenu za FSK, PSK, ASK, analogni video, rafalne signale i analogne glasovne kanale.<sup>[[1]](#references)</sup>

### Osnovno podešavanje

Nakon instalacije možete podesiti nekoliko stvari.\
U podešavanjima (dugme druge kartice) izaberite **SDR device** ili ulaznu datoteku, frekvenciju na koju želite da se podesite i brzinu uzorkovanja. Brzina do 2.56 Msps može biti praktična ako je host podržava.

![Podešavanja SigDigger-a koja prikazuju opcije za SDR uređaj, ulaznu datoteku, frekvenciju i brzinu uzorkovanja](<../../images/image (245).png>)

U ponašanju GUI-ja preporučuje se da omogućite nekoliko opcija ako ih vaš računar podržava:

![SigDigger - Osnovno podešavanje: U ponašanju GUI-ja preporučuje se da omogućite nekoliko opcija ako ih vaš računar podržava](<../../images/image (472).png>)

> [!TIP]
> Ako primetite da vaš računar ne snima podatke, pokušajte da isključite OpenGL i smanjite brzinu uzorkovanja.

### Upotreba

- Da biste **snimili deo signala i analizirali ga**, držite dugme „Push to capture“ pritisnutim koliko god je potrebno.

![Osnovno podešavanje - Upotreba: Da biste snimili deo signala i analizirali ga, držite dugme „Push to capture“ pritisnutim koliko god je potrebno](<../../images/image (960).png>)

- **Tuner** u SigDigger-u pomaže da **uhvatite bolje signale** (ali može i da ih pogorša). Najbolje je da počnete od 0 i **postepeno povećavate vrednost dok** ne primetite da je uvedena **buka** postala **veća** od željenog **poboljšanja signala**.

![Kontrola SigDigger Tuner podešena za poboljšanje snimljenog radio-signala](<../../images/image (1099).png>)

### Sinhronizacija sa radio-kanalom

Pomoću [**SigDigger** ](https://github.com/BatchDrake/SigDigger) sinhronizujte se sa kanalom koji želite da čujete, podesite opciju „Baseband audio preview“, podesite propusni opseg tako da obuhvati sve poslate informacije, a zatim podesite Tuner na nivo pre nego što buka počne značajno da raste:<sup>[[1]](#references)</sup>

![Sinhronizovani radio-kanal u SigDigger-u sa podešenim Baseband audio preview i propusnim opsegom](<../../images/image (585).png>)

## Zanimljivi trikovi

- Kada uređaj šalje rafale informacija, **prvi deo je obično preambula**, zato **ne treba** da **brinete** ako u njemu **ne pronađete informacije** ili ako **ima grešaka**.
- U okvirima sa informacijama obično bi trebalo da **pronađete različite okvire koji su međusobno dobro poravnati**:

![Sinhronizacija sa radio-kanalom - Zanimljivi trikovi: U okvirima sa informacijama obično bi trebalo da pronađete različite okvire koji su međusobno dobro poravnati](<../../images/image (1076).png>)

![Sinhronizacija sa radio-kanalom - Zanimljivi trikovi: U okvirima sa informacijama obično bi trebalo da pronađete različite okvire koji su međusobno dobro poravnati](<../../images/image (597).png>)

- **Nakon oporavka prelaza nivoa, možda ćete morati da ih dekodirate.** Kod Manchester kodiranja, jedan smer prelaza predstavlja `0`, a suprotan smer predstavlja `1`; tačan polaritet zavisi od korišćene konvencije.
- Preambula može da sadrži niz uzorkovanih vrednosti istog nivoa čak i kada se u sadržaju koristi Manchester kodiranje, zato pre dekodiranja utvrdite granicu okvira.

### Otkrivanje tipa modulacije pomoću IQ

Postoje 3 načina kodiranja informacija u signalima: modulacijom **amplitude**, **frekvencije** ili **faze**.\
Ako analizirate signal, možete na više načina pokušati da utvrdite šta se koristi za kodiranje informacija (dodatne načine pogledajte u nastavku), ali dobra metoda je da proverite IQ grafikon.

![IQ grafikon u SigDigger-u koji se koristi za utvrđivanje da li signal koristi amplitudnu, frekvencijsku ili faznu modulaciju](<../../images/image (788).png>)

- **Otkrivanje AM-a**: Ako se na IQ grafikonu pojave, na primer, **2 kruga** (verovatno jedan u 0, a drugi na drugoj amplitudi), to može značiti da je reč o AM signalu. Na IQ grafikonu rastojanje između 0 i kruga predstavlja amplitudu signala, pa se različite korišćene amplitude lako uočavaju.
- **Otkrivanje PM-a**: Kao na prethodnoj slici, ako pronađete male tačke koje nisu međusobno povezane, to verovatno znači da se koristi fazna modulacija. Na IQ grafikonu ugao između tačke i koordinatnog početka (0,0) predstavlja fazu signala, što znači da se koriste 4 različite faze.
  - Imajte na umu da, ako su informacije kodirane promenom faze, a ne samom fazom, nećete jasno videti različite faze.
- **Otkrivanje FM-a**: IQ nema polje za identifikovanje frekvencija (rastojanje od centra predstavlja amplitudu, a ugao fazu).\
  Zato bi za prepoznavanje FM-a na ovom grafikonu trebalo da vidite **uglavnom samo krug**.\
  Pored toga, frekvencijski pomak menja brzinu rotacije oko IQ kruga. Zato promena brzine ili smera rotacije u SigDigger-u može ukazivati na FM.

## Primer AM-a

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Otkrivanje AM-a

#### Provera anvelope

Kada analizirate AM podatke pomoću [**SigDigger**](https://github.com/BatchDrake/SigDigger), **anvelopa** signala može da otkrije različite nivoe amplitude. Primer signala šalje informacije u obliku impulsno amplitudno modulisanih impulsa; jedan impuls izgleda ovako:<sup>[[1]](#references)</sup>

![Anvelopa AM signala u SigDigger-u sa jasno vidljivim nivoima amplitude impulsa](<../../images/image (590).png>)

Ovako izgleda deo simbola u obliku talasa:

![Otkrivanje AM-a - Provera anvelope: Ovako izgleda deo simbola u obliku talasa](<../../images/image (734).png>)

#### Provera histograma

Možete **izabrati ceo signal** u kom se nalaze informacije, izabrati režim **Amplitude** i opciju **Selection**, a zatim kliknuti na **Histogram**. Možete primetiti da se pojavljuju samo 2 jasno izdvojena nivoa.

![Histogram amplitude u SigDigger-u koji prikazuje dva jasno izdvojena nivoa za izabrani AM signal](<../../images/image (264).png>)

Na primer, ako za ovaj AM signal izaberete Frequency umesto Amplitude, pronaći ćete samo 1 frekvenciju (informacije ne mogu biti frekvencijski modulisane ako se koristi samo 1 frekvencija).

![Histogram frekvencije u SigDigger-u za AM signal koji prikazuje jednu frekvenciju](<../../images/image (732).png>)

Ako pronađete mnogo frekvencija, signal verovatno nije FM; frekvencija signala se možda samo menjala zbog kanala.

#### Pomoću IQ-a

U ovom primeru možete videti **veliki krug**, ali i **mnogo tačaka u centru**.

![Provera histograma - Pomoću IQ-a: U ovom primeru možete videti veliki krug, ali i mnogo tačaka u centru](<../../images/image (222).png>)

### Dobijanje brzine simbola

#### Pomoću jednog simbola

Izaberite najmanji interval za koji je jasno da sadrži jedan simbol i proverite **Selection freq**. U ovom primeru iznosi 1.013 kHz, odnosno približno 1 kHz.

![Dobijanje brzine simbola - Pomoću jednog simbola: Izaberite najmanji interval za koji ste sigurni da sadrži samo jedan simbol i proverite „Selection freq“. U ovom slučaju iznosi 1.013 kHz (odnosno 1 kHz).](<../../images/image (78).png>)

#### Pomoću grupe simbola

Možete navesti i broj simbola koje ćete izabrati, a SigDigger će izračunati frekvenciju jednog simbola (verovatno će rezultat biti precizniji ako izaberete više simbola). U ovom primeru izabrao sam 10 simbola, a „Selection freq“ iznosi 1.004 kHz:

![Izračunavanje brzine simbola u SigDigger-u pomoću izabrane grupe od deset simbola](<../../images/image (1008).png>)

### Dobijanje bitova

Nakon što identifikujete AM i procenite **brzinu simbola**, izaberite oblast signala, podesite uzorkovanje amplitude i nivoe odlučivanja, izaberite **Gardner clock recovery**, a zatim kliknite na **Sample**:

![Prozor SigDigger Get Bits podešen za AM uzorkovanje, brzinu simbola i Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** znači da će se koristiti brzina simbola određena na osnovu prethodno izabranih intervala.
- **Manual** znači da će se koristiti navedena brzina simbola.
- U opciji **Fixed interval selection** navedete broj intervala koji treba izabrati, a program na osnovu toga izračunava brzinu simbola.
- **Gardner clock recovery** je korisna podrazumevana opcija, ali je i dalje potrebna približna brzina simbola.

Kada kliknete na Sample, pojaviće se sledeće:

![Pomoću grupe simbola - Dobijanje bitova: Kada kliknete na Sample, pojaviće se sledeće](<../../images/image (644).png>)

Da bi SigDigger razumeo **opseg nivoa koji nosi informacije**, kliknite na **niži nivo** i držite klik dok ne obuhvatite najviši nivo:

![Izbor opsega nivoa u SigDigger-u, od nižeg nivoa amplitude do višeg](<../../images/image (439).png>)

Na primer, ako postoje **4 različita nivoa amplitude**, trebalo bi da podesite **Bits per symbol** na 2 i izaberete opseg od najnižeg do najvišeg nivoa.

Na kraju, **povećanjem** vrednosti **Zoom** i **promenom Row size** možete videti bitove (možete izabrati sve i kopirati da biste dobili sve bitove):

![Pomoću grupe simbola - Dobijanje bitova: Na kraju, povećanjem vrednosti Zoom i promenom Row size možete videti bitove (možete izabrati sve i kopirati da biste dobili sve bitove)](<../../images/image (276).png>)

Ako signal ima više od 1 bita po simbolu (na primer, 2), SigDigger **ne može da zna koji simbol je** 00, 01, 10 ili 11, pa će za svaki koristiti različite **nijanse sive** (a prilikom kopiranja bitova koristiće **brojeve od 0 do 3**, koje ćete morati da obradite).

Kod linijskih kodiranja kao što je **Manchester**, svaki važeći par prelaza (`01` ili `10`) prevedite u bit podataka prema konvenciji koja se koristi.

## Primer FM-a

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Otkrivanje FM-a

#### Provera frekvencija i talasnog oblika

Primer signala koji šalje informacije frekvencijski modulisanjem:

![Otkrivanje FM-a - Provera frekvencija i talasnog oblika: Primer signala koji šalje informacije frekvencijski modulisanjem](<../../images/image (725).png>)

Spektar jasno prikazuje **dve frekvencije**, iako ih može biti teško razlikovati u talasnom obliku u vremenskom domenu:

![FM talasni oblik u SigDigger-u kod kog je dve frekvencije teško direktno razlikovati](<../../images/image (717).png>)

To se dešava zato što je snimak centriran između obe frekvencije, pa su njihovi frekvencijski pomaci približno suprotni:

![FM snimak u SigDigger-u koji prikazuje dve frekvencije sa približno suprotnim vrednostima](<../../images/image (942).png>)

Ako je sinhronizovana frekvencija **bliža jednoj frekvenciji nego drugoj**, lako možete videti 2 različite frekvencije:

![Otkrivanje FM-a - Provera frekvencija i talasnog oblika: Ako je sinhronizovana frekvencija bliža jednoj frekvenciji nego drugoj, lako možete videti 2 različite frekvencije](<../../images/image (422).png>)

![Otkrivanje FM-a - Provera frekvencija i talasnog oblika: Ako je sinhronizovana frekvencija bliža jednoj frekvenciji nego drugoj, lako možete videti 2 različite frekvencije](<../../images/image (488).png>)

#### Provera histograma

Proverom histograma frekvencija signala koji sadrži informacije lako možete videti 2 različita signala:

![Provera frekvencija i talasnog oblika - Provera histograma: Proverom histograma frekvencija signala koji sadrži informacije lako možete videti 2 različita signala](<../../images/image (871).png>)

U ovom slučaju, ako proverite **histogram amplitude**, pronaći ćete **samo jednu amplitudu**, pa signal **ne može biti AM** (ako pronađete mnogo amplituda, razlog može biti gubitak snage signala tokom prenosa kroz kanal):

![Histogram amplitude u SigDigger-u za FM signal koji prikazuje jedan nivo amplitude](<../../images/image (817).png>)

Ovo je histogram faze (koji jasno pokazuje da signal nije fazno modulisan):

![Provera frekvencija i talasnog oblika - Provera histograma: Ovo je histogram faze, koji jasno pokazuje da signal nije fazno modulisan](<../../images/image (996).png>)

#### Pomoću IQ-a

IQ nema polje za identifikovanje frekvencija (rastojanje od centra predstavlja amplitudu, a ugao fazu).\
Zato bi za prepoznavanje FM-a na ovom grafikonu trebalo da vidite **uglavnom samo krug**.\
Pored toga, frekvencijski pomak menja brzinu rotacije oko IQ kruga. Zato promena brzine ili smera rotacije u SigDigger-u može ukazivati na FM:

![IQ grafikon u SigDigger-u na kom se FM prikazuje kao promena brzine rotacije oko kruga](<../../images/image (81).png>)

### Dobijanje brzine simbola

Kada pronađete frekvencije koje nose simbole, možete da koristite **istu tehniku kao u primeru AM-a** za dobijanje brzine simbola.

### Dobijanje bitova

Kada **utvrdite da je signal frekvencijski modulisan** i saznate **brzinu simbola**, možete da koristite **istu tehniku kao u primeru AM-a** za dobijanje bitova.

## References

- [1] [SigDigger - Besplatan digitalni analizator signala za GNU/Linux i macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
