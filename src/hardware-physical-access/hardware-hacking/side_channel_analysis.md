# Napadi analizom bočnih kanala

{{#include ../../banners/hacktricks-training.md}}

Napadi bočnim kanalima otkrivaju tajne posmatranjem fizičkog ili mikroarhitekturnog „curenja“ koje je *povezano* sa internim stanjem, ali nije deo logičkog interfejsa uređaja. Primeri se kreću od merenja trenutne struje koju troši pametna kartica do zloupotrebe efekata upravljanja napajanjem CPU-a preko mreže.

Za metu sa dostupnim ARM hardverom za otklanjanje grešaka, [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md) može da pruži referencu putanje izvršavanja uz snimke potrošnje energije ili EM zračenja; to je trag za otklanjanje grešaka, a ne kanal curenja.<sup>[[17]](#references)</sup>

---

## Glavni kanali curenja

| Kanal | Tipična meta | Instrumentacija |
|---------|---------------|-----------------|
| Potrošnja energije | Pametne kartice, IoT MCU-ovi, FPGA-ovi | Osciloskop sa šant otpornikom ili diferencijalnom sondom; CW503 je izvor napajanja za sonde/LNA-ove, a ne sama sonda<sup>[[11]](#references)</sup> |
| Elektromagnetno polje (EM) | CPU-ovi, RFID, AES akceleratori | H-field/near-field sonda sa pojačavačem niskog šuma i osciloskopom ili SDR prijemnikom, kao što je RTL-SDR<sup>[[13]](#references)</sup> |
| Vreme izvršavanja / keš memorije | Desktop i cloud CPU-ovi | Tajmeri visoke preciznosti (`rdtsc`/`rdtscp`) ili daljinsko merenje vremena prenosa |
| Akustika / mehanika | Tastature, 3D štampači, štampači, releji i regulatori napona CPU-a | MEMS mikrofon ili laserski vibrometar<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optika i toplota | Statusne LED diode, ekrani, DRAM i termički povezani uređaji | Fotodioda, kamera velike brzine ili IR kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Ubrizgavanje grešaka | Kriptografija u ASIC-ovima/MCU-ovima | Glitch takta/napona, EMFI ili lasersko ubrizgavanje |

---

## Analiza potrošnje energije

### Jednostavna analiza potrošnje energije (SPA)
Posmatrajte *jedan* trag i povežite vidljive karakteristike sa operacijama kao što su grananja, modularno množenje ili različiti nizovi instrukcija.<sup>[[1]](#references)</sup>

Tačna postavka zavisi od mete. U sledećem primeru koristi se aktuelni visok nivo ChipWhisperer capture API-ja nakon povezivanja i konfigurisanja osciloskopa i mete:<sup>[[1]](#references)</sup>

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
Prikupite više trace-ova, pretpostavite bajt ključa `k`, izračunajte model leakage-a zasnovan na Hammingovoj težini (HW) ili Hammingovoj udaljenosti (HD) i korelirajte ga sa svakim uzorkom. Potreban broj trace-ova zavisi od cilja, šuma, poravnanja, protivmera i modela leakage-a; nije fiksni prag.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA je standardna osnovna metoda. Template attacks, mutual-information analysis i pristupi zasnovani na machine learning mogu biti korisni kada je leakage nelinearan ili su trace-ovi loše poravnati.

---

## Elektromagnetna analiza (EMA)
Analiza bliskog polja može da zabeleži aktivnost koja zavisi od podataka, bez umetanja shunt-a u putanju napajanja. Ne otkriva nužno isti signal kao power trace: položaj i orijentacija sonde, bandwidth, pojačanje ulaznog stepena, kvalitet trigger-a i udaljenost su bitni.

---

## Timing i mikroarhitekturni napadi
Moderni CPU-ovi odaju tajne kroz zajedničke resurse:
* **Hertzbleed (2022)** – Dinamičko skaliranje napona i frekvencije koje zavisi od podataka stvara udaljeni timing kanal. Originalna demonstracija oporavka ključa od početka do kraja ciljala je SIKE; naknadni rad razmatra druge primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Tranzijentno izvršavanje može da izloži podatke koje koriste vector gather instrukcije preko bezbednosnih granica.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Neispravno rukovanje spekulativnim stanjem vector registara može da otkrije podatke sa istog fizičkog jezgra.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Napad tranzijentnim izvršavanjem kombinuje phantom execution sa obukom u tranzijentnom izvršavanju kako bi stvorio gadget-e za pogrešno predviđanje koje kontroliše napadač.<sup>[[5]](#references)</sup>

---

## Akustični i optički napadi
Akustični leak je korišćen za oporavak RSA ključeva iz zvuka laptopa u kontrolisanom eksperimentu, uključujući i korišćenjem mikrofona obližnjeg mobilnog telefona.<sup>[[6]](#references)</sup> Odvojena studija tastatura iz 2023. klasifikovala je pritiske tastera sa 95% tačnosti kada je model obučen na snimcima sa obližnjeg telefona i sa 93% kada je obučen na Zoom zvuku; ove brojke opisuju eksperiment tog rada sa uređajima korišćenim za obuku, a ne proizvoljnu tastaturu ili žrtvu.<sup>[[9]](#references)</sup> Optičke emanacije statusnih LED dioda takođe se mogu povezati sa obrađenim podacima. Ovi rezultati zavise od cilja i postavke; nemojte generalizovati njihov domet ili stopu uspeha na nepovezane uređaje.<sup>[[7]](#references)</sup>

---

## Ubrizgavanje grešaka i diferencijalna analiza grešaka (DFA)
Kombinovanje kontrolisanih grešaka sa posmatranjem bočnih kanala može da smanji pretragu ključa za neke algoritme i implementacije. Uobičajene laboratorijske platforme uključuju ChipWhisperer funkcije za voltage/clock glitching i namensku opremu za EM fault injection, kao što su ChipSHOUTER ili PicoEMP. Raniji nacrt navodio je „sub-1 ns“, ali tu vrednost ne treba koristiti kao specifikaciju: u objavljenom priručniku za ChipSHOUTER navedene su tipične širine ubačenog impulsa od **15–80 ns** sa vrhom od 1 mm i **24–480 ns** sa vrhom od 4 mm (iako su trigger/pulse jitter specifikacije izražene u pikosekundama). Potrebna vremenska rezolucija, položaj sonde i broj izlaza sa greškom zavise od cilja i modela greške.<sup>[[1]](#references)[[10]](#references)</sup>

## Nepotvrđeni pravci istraživanja zadržani iz ranijeg nacrta

Raniji nacrt je takođe tvrdio da postoji: EM postavka od **500 MHz–3 GHz** koja oporavlja STM32 ključ sa udaljenosti veće od **10 cm** koristeći RTL-SDR; DDR4 activity LED koja otkriva AES round key za manje od jednog minuta na „Black Hat 2023“; i open-source RISC-V platforma za glitching iz 2025. pod nazivom **GlitchKit-R5**. Tokom ove revizije nije pronađen odgovarajući primarni rad, konferencijski materijal ili repozitorijum projekta. Ovi konkretni detalji zadržani su kao smernice za pretragu/reprodukciju, a ne kao potvrđeni rezultati ili preporuke za alate.

---

## Tipičan tok napada
1. Identifikujte kanal leakage-a i mesto povezivanja (VCC pin, decoupling kondenzator, tačka bliskog polja).
2. Dodajte trigger (GPIO ili zasnovan na obrascu).
3. Prikupite dovoljno trace-ova za odabrani statistički test, uz beleženje plaintext/ciphertext-a i drugih metapodataka.
4. Predobradite podatke (poravnanje, uklanjanje srednje vrednosti, LP/HP filter, wavelet, PCA).
5. Statistički ili ML oporavak ključa (CPA, MIA, DL-SCA).
6. Proverite rezultate i ponovite postupak za izdvojene vrednosti.

---

## Odbrane i ojačavanje
* Implementacije **constant-time** i algoritmi sa velikim zahtevima za memorijom.
* **Masking/shuffling** – podelite tajne u nasumične delove; otpornost prvog reda potvrđena je TVLA testom.
* **Hiding** – regulatori napona na čipu, nasumični clock, dual-rail logika, EM štitovi.
* **Otkrivanje grešaka** – redundantno izračunavanje, threshold potpisi.
* **Operativne mere** – isključite DVFS/turbo u crypto kernel-ima, izolujte SMT, zabranite zajedničko smeštanje u multi-tenant cloud okruženjima.

---

## Alati i okviri
* **ChipWhisperer-Husky** (2024) – osciloskop od 500 MS/s + Cortex-M trigger; Python API kao što je prethodno opisano.<sup>[[1]](#references)</sup>
* **Riscure Inspector i proizvodi za fault injection** – komercijalna analiza i alati za automatizovano testiranje.
* **scaaml** – TensorFlow alati za deep-learning SCA i skupovi podataka.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source alat za reverse engineering black-box ECC implementacija pomoću bočnih kanala.<sup>[[8]](#references)</sup>

---

## References

- [1] [Dokumentacija za ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Rad o napadu Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: Iskorišćavanje spekulativnog prikupljanja podataka](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Otkrivanje novih površina napada obukom u tranzijentnom izvršavanju](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Izdvajanje RSA ključa pomoću akustične kriptoanalize niskog bandwidth-a](https://eprint.iacr.org/2013/857.pdf)
- [7] [Curenje informacija iz optičkih emanacija](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Dokumentacija pyecsca artefakta](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Praktičan akustični napad bočnim kanalom na tastature zasnovan na deep learning-u](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - korisnički priručnik za ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Dokumentacija za ChipWhisperer — napajanje sonde CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Dokumentacija za Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Izvođenje jeftinih elektromagnetnih napada bočnim kanalom pomoću RTL-SDR-a](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodiranje intelektualne svojine: Akustični i magnetni napad bočnim kanalom na 3-D štampač](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Akustični napadi bočnim kanalom na štampače](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Špijuniranje temperature pomoću DRAM-a](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Praćenje instrukcija: ARM praćenje uživo pomoću ETM, ITM i TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
