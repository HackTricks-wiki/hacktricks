# Napadi analizom bočnih kanala

{{#include ../../banners/hacktricks-training.md}}

Napadi bočnim kanalima otkrivaju tajne posmatranjem fizičkog ili mikroarhitekturnog „leakage“-a koji je *u korelaciji* sa internim stanjem, ali nije deo logičkog interfejsa uređaja. Primeri se kreću od merenja trenutne struje koju troši smart-card do zloupotrebe efekata upravljanja napajanjem CPU-a preko mreže.

---

## Glavni kanali curenja

| Kanal | Tipična meta | Instrumentacija |
|---------|---------------|-----------------|
| Potrošnja energije | Smart kartice, IoT MCU-ovi, FPGA-ovi | Osciloskop sa šant otpornikom ili diferencijalnom sondom; CW503 je napajanje za sonde/LNA-ove, a ne sama sonda<sup>[[11]](#references)</sup> |
| Elektromagnetno polje (EM) | CPU-ovi, RFID, AES akceleratori | H-field/near-field sonda sa pojačavačem sa niskim šumom i osciloskopom ili SDR prijemnikom, kao što je RTL-SDR<sup>[[13]](#references)</sup> |
| Vreme izvršavanja / keš memorije | Desktop i cloud CPU-ovi | Precizni tajmeri (`rdtsc`/`rdtscp`) ili udaljeno merenje vremena prenosa |
| Akustika / mehanika | Tastature, 3-D štampači, štampači, releji i regulatori napona CPU-a | MEMS mikrofon ili laserski vibrometar<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optika i toplota | Statusne LED diode, displeji, DRAM i termički povezani uređaji | Fotodioda, kamera velike brzine ili IR kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Ubrizgavanje grešaka | Kriptografija ASIC/MCU uređaja | Clock/voltage glitch, EMFI ili lasersko ubrizgavanje |

---

## Analiza potrošnje energije

### Jednostavna analiza potrošnje energije (SPA)
Posmatrajte *jedan* trag i povežite vidljive karakteristike sa operacijama kao što su grananja, modularno množenje ili različiti nizovi instrukcija.<sup>[[1]](#references)</sup>

Tačna postavka zavisi od mete. Sledeći primer koristi aktuelni visokorangirani ChipWhisperer capture API nakon povezivanja i konfigurisanja osciloskopa i mete:<sup>[[1]](#references)</sup>

```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
    print(trace.wave)  # NumPy array of power samples
```

### Differential/Correlation Power Analysis (DPA/CPA)
Prikupite više tragova, pretpostavite vrednost jednog bajta ključa `k`, izračunajte model curenja zasnovan na Hammingovoj težini (HW) ili Hammingovom rastojanju (HD) i korelišite ga sa svakim uzorkom. Potreban broj tragova zavisi od cilja, šuma, poravnanja, protivmera i modela curenja; ne postoji fiksni prag.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA je standardna početna osnova. Template attacks, mutual-information analysis i pristupi mašinskog učenja mogu biti korisni kada je curenje nelinearno ili su tragovi loše poravnati.

---

## Elektromagnetna analiza (EMA)
Analiza elektromagnetnog polja u bliskom polju može da uoči aktivnost koja zavisi od podataka, bez umetanja šanta u napojni vod. Ne otkriva nužno isti signal kao trag potrošnje: važni su položaj i orijentacija sonde, propusni opseg, pojačanje ulaznog stepena, kvalitet okidanja i udaljenost.

---

## Vremenski i mikroarhitekturni napadi
Moderni CPU-ovi otkrivaju tajne preko deljenih resursa:
* **Hertzbleed (2022)** – Dinamičko skaliranje napona i frekvencije koje zavisi od podataka stvara udaljeni vremenski kanal. Originalni demonstracioni napad za oporavak ključa od početka do kraja ciljao je SIKE; naknadni radovi razmatraju i druge primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Spekulativno izvršavanje može da otkrije podatke koje koriste vektorske gather instrukcije, prelazeći bezbednosne granice.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Neispravno rukovanje stanjem spekulativnih vektorskih registara može da otkrije podatke sa istog fizičkog jezgra.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Napad spekulativnog izvršavanja kombinuje phantom execution sa obukom u spekulativnom izvršavanju kako bi stvorio gadgete za pogrešno predviđanje koje kontroliše napadač.<sup>[[5]](#references)</sup>

---

## Akustični i optički napadi
Akustično curenje je korišćeno za oporavak RSA ključeva na osnovu zvuka laptopa u kontrolisanom eksperimentu, uključujući snimanje mikrofonom obližnjeg mobilnog telefona.<sup>[[6]](#references)</sup> Zasebna studija tastatura iz 2023. klasifikovala je pritiske tastera sa tačnošću od 95% kada je obučavana na snimcima sa obližnjeg telefona, odnosno 93% kada je obučavana na Zoom zvuku; ove vrednosti opisuju eksperiment iz rada sa uređajem korišćenim za obuku, a ne proizvoljnu tastaturu ili žrtvu.<sup>[[9]](#references)</sup> Optičke emisije statusnih LED lampica takođe se mogu povezati sa obrađenim podacima. Ovi rezultati zavise od cilja i postavke; nemojte uopštavati njihov domet ili stopu uspeha na nepovezane uređaje.<sup>[[7]](#references)</sup>

---

## Ubrizgavanje grešaka i diferencijalna analiza grešaka (DFA)
Kombinovanje kontrolisanih grešaka sa posmatranjem bočnih kanala može da smanji prostor pretrage ključeva za neke algoritme i implementacije. Uobičajene laboratorijske platforme uključuju ChipWhisperer funkcije za ubrizgavanje naponskih i taktnih glitch-eva, kao i namenske EM alate za ubrizgavanje grešaka, poput ChipSHOUTER-a ili PicoEMP-a. Opis „sub-1 ns” iz ranijeg nacrta ne treba koristiti kao specifikaciju: objavljeni priručnik za ChipSHOUTER navodi tipične širine umetnutih impulsa od **15–80 ns** sa vrhom od 1 mm i **24–480 ns** sa vrhom od 4 mm (iako je podrhtavanje okidanja/impulsa specifikovano u pikosekundama). Potrebna vremenska rezolucija, položaj sonde i broj neispravnih izlaza zavise od cilja i modela greške.<sup>[[1]](#references)[[10]](#references)</sup>

## Nepotvrđeni istraživački tragovi zadržani iz ranijeg nacrta

Raniji nacrt je takođe tvrdio da: EM postavka od **500 MHz–3 GHz** može da oporavi STM32 ključ sa udaljenosti veće od **10 cm** koristeći RTL-SDR; da DDR4 aktivnost LED lampice otkriva AES round key za manje od jednog minuta na „Black Hat 2023”; i da je 2025. objavljena open-source RISC-V platforma za glitching pod nazivom **GlitchKit-R5**. Tokom ove provere nije pronađen odgovarajući primarni rad, konferencijski materijal niti repozitorijum projekta. Ovi konkretni detalji zadržani su kao tragovi za pretragu i reprodukciju, a ne kao potvrđeni rezultati ili preporuke za alate.

---

## Tipičan tok napada
1. Utvrdite kanal curenja i tačku priključenja (VCC pin, kondenzator za razdvajanje, tačka u bliskom polju).
2. Umetnite okidač (GPIO ili zasnovan na obrascu).  
3. Prikupite dovoljno tragova za izabrani statistički test, beležeći otvoreni tekst/šifrat i ostale metapodatke.
4. Prethodno obradite podatke (poravnanje, uklanjanje srednje vrednosti, LP/HP filter, wavelet, PCA).
5. Oporavak ključa statističkim metodama ili ML-om (CPA, MIA, DL-SCA).
6. Potvrdite rezultat i ponavljajte postupak za izdvojene vrednosti.

---

## Odbrane i ojačavanje bezbednosti
* Implementacije sa **constant-time** izvršavanjem i algoritmi otporni na napade memorijskim opterećenjem.
* **Masking/shuffling** – podelite tajne na nasumične delove; otpornost prvog reda potvrđena je TVLA testiranjem.
* **Skrivanje** – regulatori napona na čipu, nasumični takt, dual-rail logika, EM štitovi.
* **Otkrivanje grešaka** – redundantno izračunavanje, threshold potpisi.
* **Operativne mere** – isključite DVFS/turbo u kriptografskim jezgrima, izolujte SMT i zabranite zajedničko smeštanje u multi-tenant cloud okruženjima.

---

## Alati i okviri
* **ChipWhisperer-Husky** (2024) – osciloskop od 500 MS/s i Cortex-M okidač; Python API kao gore.<sup>[[1]](#references)</sup>
* **Riscure Inspector i alati za ubrizgavanje grešaka** – komercijalni alati za analizu i automatizovano testiranje.
* **scaaml** – alati i skupovi podataka za deep-learning SCA zasnovani na TensorFlow-u.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source alat za reverse engineering black-box ECC implementacija pomoću bočnih kanala.<sup>[[8]](#references)</sup>

---

## References

- [1] [Dokumentacija za ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Rad o napadu Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: Iskorišćavanje spekulativnog prikupljanja podataka](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Otkrivanje novih površina za napad obukom u spekulativnom izvršavanju](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Izdvajanje RSA ključa putem akustične kriptoanalize uskog propusnog opsega](https://eprint.iacr.org/2013/857.pdf)
- [7] [Curenje informacija iz optičkih emisija](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Dokumentacija za pyecsca artefakt](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Praktičan akustični napad bočnim kanalom na tastature zasnovan na deep learning-u](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Korisnički priručnik za ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Dokumentacija za ChipWhisperer — napajanje sonde CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML dokumentacija](https://google.github.io/scaaml/)
- [13] [FOSDEM — Izvođenje jeftinih elektromagnetnih napada bočnim kanalom pomoću RTL-SDR-a](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodiranje intelektualne svojine: akustični i magnetni napad bočnim kanalom na 3-D štampač](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Akustični napadi bočnim kanalom na štampače](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Špijuniranje temperature pomoću DRAM-a](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
