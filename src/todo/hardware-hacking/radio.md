# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)je besplatan analizer digitalnih signala za GNU/Linux i macOS, dizajniran za ekstrakciju informacija iz nepoznatih radio signala. Podržava razne SDR uređaje putem SoapySDR, i omogućava prilagodljivu demodulaciju FSK, PSK i ASK signala, dekodiranje analognog videa, analizu povremenih signala i slušanje analognih glasovnih kanala (sve u realnom vremenu).

### Osnovna konfiguracija

Nakon instalacije postoji nekoliko stvari koje možete razmotriti za konfiguraciju.\
U podešavanjima (drugi dugme na tabu) možete odabrati **SDR uređaj** ili **odabrati datoteku** za čitanje i koju frekvenciju da sintonizujete i brzinu uzorkovanja (preporučuje se do 2.56Msps ako vaš PC to podržava)\\

![](<../../images/image (245).png>)

U ponašanju GUI-a preporučuje se da omogućite nekoliko stvari ako vaš PC to podržava:

![](<../../images/image (472).png>)

> [!NOTE]
> Ako primetite da vaš PC ne hvata signale, pokušajte da onemogućite OpenGL i smanjite brzinu uzorkovanja.

### Upotreba

- Samo da **uhvatite deo signala i analizirate ga** samo držite dugme "Push to capture" koliko god vam je potrebno.

![](<../../images/image (960).png>)

- **Tuner** u SigDigger-u pomaže da **uhvatite bolje signale** (ali to može i da ih pogorša). Idealno je početi sa 0 i nastaviti **povećavati dok** ne primetite da je **šum** koji se uvodi **veći** od **poboljšanja signala** koje vam je potrebno).

![](<../../images/image (1099).png>)

### Sinhronizacija sa radio kanalom

Sa [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sinhronizujte se sa kanalom koji želite da čujete, konfigurišite opciju "Baseband audio preview", konfigurišite propusnost da dobijete sve informacije koje se šalju i zatim postavite Tuner na nivo pre nego što šum počne da se povećava:

![](<../../images/image (585).png>)

## Zanimljive trikove

- Kada uređaj šalje serije informacija, obično je **prvi deo preambula** tako da **ne morate** da **brinete** ako **ne pronađete informacije** ili ako postoje neki **greške**.
- U okvirima informacija obično biste trebali **pronaći različite okvire dobro usklađene između njih**:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Nakon oporavka bitova možda ćete morati da ih obradite na neki način**. Na primer, u Mančesterskoj kodifikaciji, uspon+pad će biti 1 ili 0, a pad+uspon će biti drugi. Tako da parovi 1 i 0 (usponi i padovi) će biti pravi 1 ili pravi 0.
- Čak i ako signal koristi Mančestersku kodifikaciju (nemoguće je pronaći više od dva 0 ili 1 u nizu), možete **pronaći nekoliko 1 ili 0 zajedno u preambuli**!

### Otkriće tipa modulacije sa IQ

Postoje 3 načina za skladištenje informacija u signalima: Modulacija **amplituda**, **frekvencija** ili **faza**.\
Ako proveravate signal, postoje različiti načini da pokušate da otkrijete šta se koristi za skladištenje informacija (pronađite više načina u nastavku), ali dobar način je da proverite IQ graf.

![](<../../images/image (788).png>)

- **Detekcija AM**: Ako se na IQ grafu pojavi, na primer, **2 kruga** (verovatno jedan na 0 i drugi na različitoj amplitudi), to može značiti da je ovo AM signal. To je zato što je na IQ grafu razdaljina između 0 i kruga amplituda signala, tako da je lako vizualizovati različite amplitude koje se koriste.
- **Detekcija PM**: Kao na prethodnoj slici, ako pronađete male krugove koji nisu povezani između njih, to verovatno znači da se koristi fazna modulacija. To je zato što je na IQ grafu ugao između tačke i 0,0 faza signala, tako da to znači da se koriste 4 različite faze.
- Imajte na umu da ako je informacija skrivena u činjenici da se faza menja, a ne u samoj fazi, nećete videti različite faze jasno diferencirane.
- **Detekcija FM**: IQ nema polje za identifikaciju frekvencija (razdaljina do centra je amplituda, a ugao je faza).\
Stoga, da biste identifikovali FM, trebali biste **samo videti osnovni krug** u ovom grafu.\
Štaviše, različita frekvencija je "predstavljena" na IQ grafu kao **brza akceleracija po krugu** (tako da u SysDigger-u, kada odaberete signal, IQ graf se popunjava, ako primetite akceleraciju ili promenu pravca u kreiranom krugu, to može značiti da je ovo FM):

## AM Primer

{% file src="../../images/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Otkriće AM

#### Proveravanje omotača

Proveravajući AM informacije sa [**SigDigger** ](https://github.com/BatchDrake/SigDigger) i samo gledajući u **omotač** možete videti različite jasne nivoe amplitude. Korišćeni signal šalje pulseve sa informacijama u AM, ovako izgleda jedan puls:

![](<../../images/image (590).png>)

I ovako izgleda deo simbola sa talasnom formom:

![](<../../images/image (734).png>)

#### Proveravanje histograma

Možete **odabrati ceo signal** gde se informacije nalaze, odabrati **Amplituda** mod i **Selekciju** i kliknuti na **Histogram.** Možete primetiti da se nalaze samo 2 jasna nivoa

![](<../../images/image (264).png>)

Na primer, ako odaberete Frekvenciju umesto Amplitude u ovom AM signalu, pronaći ćete samo 1 frekvenciju (nema načina da je informacija modulirana u frekvenciji koristeći samo 1 frekvenciju).

![](<../../images/image (732).png>)

Ako pronađete mnogo frekvencija, verovatno ovo neće biti FM, verovatno je frekvencija signala samo modifikovana zbog kanala.

#### Sa IQ

U ovom primeru možete videti kako postoji **veliki krug** ali i **mnogo tačaka u centru.**

![](<../../images/image (222).png>)

### Dobijanje simbolne brzine

#### Sa jednim simbolom

Odaberite najmanji simbol koji možete pronaći (tako da ste sigurni da je to samo 1) i proverite "Selekciju frekvencije". U ovom slučaju bi to bilo 1.013kHz (tako da 1kHz).

![](<../../images/image (78).png>)

#### Sa grupom simbola

Takođe možete naznačiti broj simbola koje ćete odabrati i SigDigger će izračunati frekvenciju 1 simbola (što više simbola odabrano, to bolje). U ovom scenariju odabrao sam 10 simbola i "Selekcija frekvencije" je 1.004 Khz:

![](<../../images/image (1008).png>)

### Dobijanje bitova

Nakon što ste utvrdili da je ovo **AM modulirani** signal i **simbolna brzina** (i znajući da u ovom slučaju nešto što ide gore znači 1, a nešto što ide dole znači 0), vrlo je lako **dobiti bitove** kodirane u signalu. Dakle, odaberite signal sa informacijama i konfigurišite uzorkovanje i odluku i pritisnite uzorak (proverite da je **Amplituda** odabrana, otkrivena **Simbolna brzina** je konfigurisana i **Gadnerova oporavak takta** je odabrana):

![](<../../images/image (965).png>)

- **Sinhronizacija sa selekcionim intervalima** znači da ako ste prethodno odabrali intervale da pronađete simbolnu brzinu, ta simbolna brzina će se koristiti.
- **Ručno** znači da će se koristiti naznačena simbolna brzina
- U **Fiksnoj selekciji intervala** naznačavate broj intervala koji treba odabrati i izračunava simbolnu brzinu iz toga
- **Gadnerova oporavak takta** obično je najbolja opcija, ali još uvek morate naznačiti neku približnu simbolnu brzinu.

Pritiskom na uzorak pojavljuje se ovo:

![](<../../images/image (644).png>)

Sada, da biste naterali SigDigger da razume **gde je opseg** nivoa koji nosi informacije, morate kliknuti na **niži nivo** i držati pritisnuto dok ne dobijete najveći nivo:

![](<../../images/image (439).png>)

Da je, na primer, bilo **4 različita nivoa amplitude**, trebali biste konfigurisati **Bitove po simbolu na 2** i odabrati od najmanjeg do najvećeg.

Na kraju **povećavajući** **Zoom** i **menjajući veličinu reda** možete videti bitove (i možete odabrati sve i kopirati da dobijete sve bitove):

![](<../../images/image (276).png>)

Ako signal ima više od 1 bita po simbolu (na primer 2), SigDigger **nema načina da zna koji simbol je** 00, 01, 10, 11, tako da će koristiti različite **sive skale** da predstavi svaki (i ako kopirate bitove koristiće **brojeve od 0 do 3**, moraćete da ih obradite).

Takođe, koristite **kodifikacije** kao što su **Mančester**, i **uspon+pad** može biti **1 ili 0**, a pad+uspon može biti 1 ili 0. U tim slučajevima morate **obraditi dobijene usponi (1) i padovi (0)** da zamenite parove 01 ili 10 kao 0 ili 1.

## FM Primer

{% file src="../../images/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Otkriće FM

#### Proveravanje frekvencija i talasne forme

Primer signala koji šalje informacije modulirane u FM:

![](<../../images/image (725).png>)

Na prethodnoj slici možete prilično dobro primetiti da se **koriste 2 frekvencije**, ali ako **posmatrate** **talasnu formu** možda nećete moći da ispravno identifikujete 2 različite frekvencije:

![](<../../images/image (717).png>)

To je zato što sam uhvatio signal na obe frekvencije, tako da je jedna otprilike negativna od druge:

![](<../../images/image (942).png>)

Ako je sinhronizovana frekvencija **bliža jednoj frekvenciji nego drugoj**, lako možete videti 2 različite frekvencije:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Proveravanje histograma

Proveravajući histogram frekvencije signala sa informacijama lako možete videti 2 različita signala:

![](<../../images/image (871).png>)

U ovom slučaju, ako proverite **Histogram Amplitude** pronaći ćete **samo jednu amplitudu**, tako da **ne može biti AM** (ako pronađete mnogo amplituda, to može biti zato što je signal gubio snagu duž kanala):

![](<../../images/image (817).png>)

I ovo bi bio histogram faze (što jasno pokazuje da signal nije moduliran u fazi):

![](<../../images/image (996).png>)

#### Sa IQ

IQ nema polje za identifikaciju frekvencija (razdaljina do centra je amplituda, a ugao je faza).\
Stoga, da biste identifikovali FM, trebali biste **samo videti osnovni krug** u ovom grafu.\
Štaviše, različita frekvencija je "predstavljena" na IQ grafu kao **brza akceleracija po krugu** (tako da u SysDigger-u, kada odaberete signal, IQ graf se popunjava, ako primetite akceleraciju ili promenu pravca u kreiranom krugu, to može značiti da je ovo FM):

![](<../../images/image (81).png>)

### Dobijanje simbolne brzine

Možete koristiti **istu tehniku kao u AM primeru** da dobijete simbolnu brzinu kada pronađete frekvencije koje nose simbole.

### Dobijanje bitova

Možete koristiti **istu tehniku kao u AM primeru** da dobijete bitove kada ste **pronašli da je signal moduliran u frekvenciji** i **simbolna brzina**.

{{#include ../../banners/hacktricks-training.md}}
