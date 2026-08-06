# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)je besplatan digitalni analizator signala za GNU/Linux i macOS, namenjen izvlačenju informacija iz nepoznatih radio-signala. Podržava različite SDR uređaje putem SoapySDR-a i omogućava podesivu demodulaciju FSK, PSK i ASK signala, dekodiranje analognog videa, analizu burst signala i slušanje analognih glasovnih kanala (sve u realnom vremenu).<sup>[[1]](#references)</sup>

### Osnovna konfiguracija

Nakon instalacije postoji nekoliko stvari koje možete podesiti.\
U podešavanjima (dugme druge kartice) možete izabrati **SDR uređaj** ili **izabrati datoteku** za čitanje, kao i frekvenciju na koju treba podesiti prijemnik i Sample rate (preporučuje se do 2.56Msps ako ga vaš računar podržava).

![SigDigger podešavanja koja prikazuju opcije za SDR uređaj, ulaznu datoteku, frekvenciju i sample rate](<../../images/image (245).png>)

U GUI behaviour preporučuje se da omogućite nekoliko opcija ako ih vaš računar podržava:

![SigDigger - Osnovna konfiguracija: U GUI behaviour preporučuje se da omogućite nekoliko opcija ako ih vaš računar podržava](<../../images/image (472).png>)

> [!TIP]
> Ako primetite da vaš računar ne snima podatke, pokušajte da onemogućite OpenGL i smanjite sample rate.

### Upotreba

- Ako želite samo da **snimite signal tokom određenog vremena i analizirate ga**, držite dugme "Push to capture" pritisnutim koliko god je potrebno.

![Osnovna konfiguracija - Upotreba: Ako želite samo da snimite signal tokom određenog vremena i analizirate ga, držite dugme "Push to capture" pritisnutim koliko god je potrebno](<../../images/image (960).png>)

- **Tuner** u SigDigger-u pomaže da **snimite kvalitetnije signale** (ali ih može i pogoršati). Idealno je početi od 0 i nastaviti da **povećavate vrednost dok** ne utvrdite da je uvedeni **šum veći** od potrebnog **poboljšanja signala**.

![SigDigger tuner kontrola podešena za poboljšanje snimljenog radio-signala](<../../images/image (1099).png>)

### Sinhronizacija sa radio-kanalom

Pomoću [**SigDigger** ](https://github.com/BatchDrake/SigDigger) sinhronizujte se sa kanalom koji želite da slušate, podesite opciju "Baseband audio preview", podesite bandwith tako da obuhvati sve informacije koje se šalju, a zatim podesite Tuner na nivo pre nego što šum počne značajno da raste:<sup>[[1]](#references)</sup>

![SigDigger sinhronizovan sa radio-kanalom, sa uključenim baseband audio preview i podešenim bandwidth-om](<../../images/image (585).png>)

## Zanimljivi trikovi

- Kada uređaj šalje burst informacija, obično će **prvi deo biti preambula**, tako da **ne morate da brinete** ako **ne pronađete informacije** u tom delu **ili ako u njemu postoje greške**.
- U okvirima sa informacijama obično treba da **pronađete različite okvire koji su međusobno dobro poravnati**:

![Sinhronizacija sa radio-kanalom - Zanimljivi trikovi: U okvirima sa informacijama obično treba da pronađete različite okvire koji su međusobno dobro poravnati](<../../images/image (1076).png>)

![Sinhronizacija sa radio-kanalom - Zanimljivi trikovi: U okvirima sa informacijama obično treba da pronađete različite okvire koji su međusobno dobro poravnati](<../../images/image (597).png>)

- **Nakon oporavka bitova možda ćete morati da ih obradite na neki način**. Na primer, u Manchester kodiranju kombinacija up+down predstavlja 1 ili 0, a down+up predstavlja drugu vrednost. Dakle, parovi jedinica i nula (uspona i padova) predstavljaće stvarnu 1 ili stvarnu 0.
- Čak i ako signal koristi Manchester kodiranje (nemoguće je pronaći više od dve uzastopne 0 ili 1), u preambuli možete **pronaći više uzastopnih 1 ili 0**!

### Otkrivanje tipa modulacije pomoću IQ-a

Postoje 3 načina za čuvanje informacija u signalima: modulacija **amplitude**, **frekvencije** ili **faze**.\
Ako proveravate signal, postoje različiti načini da pokušate da utvrdite šta se koristi za čuvanje informacija (više načina je navedeno ispod), ali dobar način je provera IQ grafikona.

![SigDigger IQ grafikon koji se koristi za utvrđivanje da li signal koristi modulaciju amplitude, frekvencije ili faze](<../../images/image (788).png>)

- **Otkrivanje AM-a**: Ako se na IQ grafikonu, na primer, pojavljuju **2 kruga** (verovatno jedan na 0, a drugi na drugoj amplitudi), to može značiti da je u pitanju AM signal. To je zato što je na IQ grafikonu rastojanje između nule i kruga amplituda signala, pa je lako vizuelizovati različite korišćene amplitude.
- **Otkrivanje PM-a**: Kao na prethodnoj slici, ako pronađete male krugove koji nisu međusobno povezani, to verovatno znači da se koristi fazna modulacija. To je zato što je na IQ grafikonu ugao između tačke i koordinatnog početka 0,0 faza signala, što znači da se koriste 4 različite faze.
- Imajte na umu da, ako su informacije skrivene u činjenici da je faza promenjena, a ne u samoj fazi, nećete videti jasno razdvojene različite faze.
- **Otkrivanje FM-a**: IQ nema polje za identifikaciju frekvencija (rastojanje od centra predstavlja amplitudu, a ugao fazu).\
Zato bi, za identifikaciju FM-a, na ovom grafikonu trebalo da vidite **uglavnom samo jedan krug**.\
Pored toga, različita frekvencija je na IQ grafikonu „predstavljena“ **ubrzanjem brzine duž kruga** (dakle, kada u SysDigger-u izaberete signal i IQ grafikon se popuni, ubrzanje ili promena smera u formiranom krugu može značiti da je u pitanju FM):

## AM primer

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Otkrivanje AM-a

#### Provera envelope-a

Proverom AM informacija pomoću [**SigDigger** ](https://github.com/BatchDrake/SigDigger)-a i jednostavnim posmatranjem **envelope-a** možete videti nekoliko jasno definisanih nivoa amplitude. Korišćeni signal šalje impulse sa informacijama u AM-u; ovako izgleda jedan impuls:<sup>[[1]](#references)</sup>

![SigDigger AM signalni envelope sa jasno definisanim nivoima amplitude impulsa](<../../images/image (590).png>)

Ovako izgleda deo simbola sa waveform-om:

![Otkrivanje AM-a - Provera envelope-a: Ovako izgleda deo simbola sa waveform-om](<../../images/image (734).png>)

#### Provera histograma

Možete **izabrati ceo signal** u kojem se nalaze informacije, izabrati režim **Amplitude**, zatim **Selection** i kliknuti na **Histogram.** Možete primetiti da postoje samo 2 jasno definisana nivoa.

![SigDigger histogram amplitude koji prikazuje dva jasno definisana nivoa za izabrani AM signal](<../../images/image (264).png>)

Na primer, ako u ovom AM signalu izaberete Frequency umesto Amplitude, pronaći ćete samo 1 frekvenciju (nema smisla da se informacija modulira u frekvenciji ako se koristi samo 1 frekvencija).

![SigDigger histogram frekvencije za AM signal koji prikazuje jednu frekvenciju](<../../images/image (732).png>)

Ako pronađete mnogo frekvencija, to verovatno neće biti FM; frekvencija signala je možda samo promenjena zbog kanala.

#### Sa IQ-om

U ovom primeru možete videti da postoji **veliki krug**, ali i **mnogo tačaka u centru**.

![Provera histograma - Sa IQ-om: U ovom primeru možete videti da postoji veliki krug, ali i mnogo tačaka u centru](<../../images/image (222).png>)

### Dobijanje Symbol Rate-a

#### Sa jednim simbolom

Izaberite najmanji simbol koji možete pronaći (kako biste bili sigurni da je to samo 1) i proverite "Selection freq". U ovom slučaju vrednost bi bila 1.013kHz (odnosno 1kHz).

![Dobijanje Symbol Rate-a - Sa jednim simbolom: Izaberite najmanji simbol koji možete pronaći (kako biste bili sigurni da je to samo 1) i proverite "Selection freq". U ovom slučaju vrednost bi bila 1.013kHz (odnosno 1kHz)](<../../images/image (78).png>)

#### Sa grupom simbola

Takođe možete navesti broj simbola koje ćete izabrati, a SigDigger će izračunati frekvenciju 1 simbola (verovatno će rezultat biti bolji što izaberete više simbola). U ovom slučaju izabrao sam 10 simbola, a "Selection freq" iznosi 1.004 Khz:

![SigDigger izračunavanje symbol rate-a pomoću izabrane grupe od deset simbola](<../../images/image (1008).png>)

### Dobijanje bitova

Kada utvrdite da je ovo **AM modulisani** signal i pronađete **symbol rate** (a znate da u ovom slučaju nešto što ide naviše znači 1, a nešto što ide naniže znači 0), veoma je lako **dobiti bitove** kodirane u signalu. Izaberite signal sa informacijama, podesite sampling i decision, a zatim pritisnite sample (proverite da je izabrana opcija **Amplitude**, da je podešen otkriveni **Symbol rate** i da je izabrana opcija **Gadner clock recovery**):

![SigDigger Get Bits panel konfigurisan za AM sampling, symbol rate i Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** znači da će se, ako ste prethodno izabrali intervale za pronalaženje symbol rate-a, koristiti taj symbol rate.
- **Manual** znači da će se koristiti navedeni symbol rate.
- U opciji **Fixed interval selection** navodite broj intervala koji treba da budu izabrani, a ona izračunava symbol rate.
- **Gadner clock recovery** je obično najbolja opcija, ali i dalje morate navesti približan symbol rate.

Nakon pritiska na sample pojavljuje se sledeće:

![Sa grupom simbola - Dobijanje bitova: Nakon pritiska na sample pojavljuje se sledeće](<../../images/image (644).png>)

Da bi SigDigger razumeo **gde se nalazi opseg** nivoa koji nosi informacije, potrebno je da kliknete na **niži nivo** i držite klik dok ne obuhvatite najviši nivo:

![SigDigger izbor opsega nivoa od nižeg nivoa amplitude do višeg nivoa](<../../images/image (439).png>)

Da su, na primer, postojala **4 različita nivoa amplitude**, trebalo bi da podesite **Bits per symbol na 2** i izaberete opseg od najmanjeg do najvećeg nivoa.

Na kraju, **povećavanjem** opcije **Zoom** i **promenom Row size-a** možete videti bitove (možete izabrati sve bitove i kopirati ih da biste dobili kompletan niz):

![Sa grupom simbola - Dobijanje bitova: Na kraju, povećavanjem opcije Zoom i promenom Row size-a možete videti bitove (možete izabrati sve bitove i kopirati ih da biste dobili kompletan niz)](<../../images/image (276).png>)

Ako signal ima više od 1 bita po simbolu (na primer 2), SigDigger **ne može da zna koji simbol predstavlja** 00, 01, 10 ili 11, pa će za svaki od njih koristiti različite **nijanse sive** (a pri kopiranju bitova koristiće **brojeve od 0 do 3**, koje ćete morati da obradite).

Takođe, koristite **kodiranja** kao što je **Manchester**, gde up+down može biti **1 ili 0**, a down+up može biti 1 ili 0. U tim slučajevima morate **obraditi dobijene uspone (1) i padove (0)** kako biste parove 01 ili 10 zamenili nulama ili jedinicama.

## FM primer

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Otkrivanje FM-a

#### Provera frekvencija i waveform-a

Primer signala koji šalje informacije modulisane u FM-u:

![Otkrivanje FM-a - Provera frekvencija i waveform-a: Primer signala koji šalje informacije modulisane u FM-u](<../../images/image (725).png>)

Na prethodnoj slici možete prilično jasno videti da se koriste **2 frekvencije**, ali ako **posmatrate** **waveform**, možda nećete moći da pravilno identifikujete **2 različite frekvencije**:

![SigDigger FM waveform kod kojeg je dve frekvencije teško direktno razlikovati](<../../images/image (717).png>)

To je zato što sam signal snimio na obe frekvencije, pa je jedna približno negativna vrednost druge:

![SigDigger FM snimak koji prikazuje dve frekvencije kao približne negativne vrednosti](<../../images/image (942).png>)

Ako je **sinhronizovana frekvencija bliža jednoj frekvenciji nego drugoj**, lako možete videti 2 različite frekvencije:

![Otkrivanje FM-a - Provera frekvencija i waveform-a: Ako je sinhronizovana frekvencija bliža jednoj frekvenciji nego drugoj, lako možete videti 2 različite frekvencije](<../../images/image (422).png>)

![Otkrivanje FM-a - Provera frekvencija i waveform-a: Ako je sinhronizovana frekvencija bliža jednoj frekvenciji nego drugoj, lako možete videti 2 različite frekvencije](<../../images/image (488).png>)

#### Provera histograma

Proverom histograma frekvencije signala sa informacijama lako možete videti 2 različita signala:

![Provera frekvencija i waveform-a - Provera histograma: Proverom histograma frekvencije signala sa informacijama lako možete videti 2 različita signala](<../../images/image (871).png>)

U ovom slučaju, ako proverite **histogram amplitude**, pronaći ćete **samo jednu amplitudu**, pa signal **ne može biti AM** (ako pronađete mnogo amplituda, moguće je da je signal izgubio snagu duž kanala):

![SigDigger histogram amplitude za FM signal koji prikazuje jedan nivo amplitude](<../../images/image (817).png>)

A ovo bi bio histogram faze (koji jasno pokazuje da signal nije modulisan u fazi):

![Provera frekvencija i waveform-a - Provera histograma: A ovo bi bio histogram faze (koji jasno pokazuje da signal nije modulisan u fazi)](<../../images/image (996).png>)

#### Sa IQ-om

IQ nema polje za identifikaciju frekvencija (rastojanje od centra predstavlja amplitudu, a ugao fazu).\
Zato bi, za identifikaciju FM-a, na ovom grafikonu trebalo da vidite **uglavnom samo jedan krug**.\
Pored toga, različita frekvencija je na IQ grafikonu „predstavljena“ **ubrzanjem brzine duž kruga** (dakle, kada u SysDigger-u izaberete signal i IQ grafikon se popuni, ubrzanje ili promena smera u formiranom krugu može značiti da je u pitanju FM):

![SigDigger IQ grafikon na kojem se FM prikazuje kao promena ubrzanja oko kruga](<../../images/image (81).png>)

### Dobijanje Symbol Rate-a

Možete koristiti **istu tehniku kao u AM primeru** da dobijete symbol rate kada pronađete frekvencije koje nose simbole.

### Dobijanje bitova

Možete koristiti **istu tehniku kao u AM primeru** da dobijete bitove kada **utvrdite da je signal modulisan u frekvenciji** i pronađete **symbol rate**.

## Reference

- [1] [SigDigger - Besplatni digitalni analizator signala za GNU/Linux i macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
