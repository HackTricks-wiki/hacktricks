# Algoritmi učenja pojačanjem

{{#include ../banners/hacktricks-training.md}}

## Učenje pojačanjem

Učenje pojačanjem (RL) je vrsta mašinskog učenja gde agent uči da donosi odluke interakcijom sa okruženjem. Agent prima povratne informacije u obliku nagrada ili kazni na osnovu svojih akcija, što mu omogućava da tokom vremena uči optimalna ponašanja. RL je posebno koristan za probleme gde rešenje uključuje sekvencijalno donošenje odluka, kao što su robotika, igranje igara i autonomni sistemi.

### Q-Učenje

Q-Učenje je algoritam učenja pojačanjem bez modela koji uči vrednost akcija u datom stanju. Koristi Q-tabelu za skladištenje očekivane korisnosti preuzimanja specifične akcije u specifičnom stanju. Algoritam ažurira Q-vrednosti na osnovu primljenih nagrada i maksimalnih očekivanih budućih nagrada.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu sa proizvoljnim vrednostima (često nulama).
2. **Izbor akcije**: Izaberite akciju koristeći strategiju istraživanja (npr., ε-greedy, gde se sa verovatnoćom ε bira nasumična akcija, a sa verovatnoćom 1-ε bira se akcija sa najvišom Q-vrednošću).
- Imajte na umu da bi algoritam uvek mogao da izabere poznatu najbolju akciju za dato stanje, ali to ne bi omogućilo agentu da istražuje nove akcije koje bi mogle doneti bolje nagrade. Zato se koristi ε-greedy varijabla da bi se izbalansiralo istraživanje i eksploatacija.
3. **Interakcija sa okruženjem**: Izvršite izabranu akciju u okruženju, posmatrajte sledeće stanje i nagradu.
- Imajte na umu da, u ovom slučaju, zavisno od ε-greedy verovatnoće, sledeći korak može biti nasumična akcija (za istraživanje) ili najbolja poznata akcija (za eksploataciju).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-akcija koristeći Bellmanovu jednačinu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je brzina učenja (0 < α ≤ 1), koja određuje koliko nova informacija nadmašuje staru informaciju.
- `r` je nagrada primljena nakon preuzimanja akcije `a` u stanju `s`.
- `γ` je faktor diskontovanja (0 ≤ γ < 1), koji određuje važnost budućih nagrada.
- `s'` je sledeće stanje nakon preuzimanja akcije `a`.
- `max(Q(s', a'))` je maksimalna Q-vrednost za sledeće stanje `s'` preko svih mogućih akcija `a'`.
5. **Iteracija**: Ponovite korake 2-4 dok se Q-vrednosti ne konvergiraju ili dok se ne ispuni kriterijum zaustavljanja.

Imajte na umu da se sa svakom novom izabranom akcijom tabela ažurira, omogućavajući agentu da uči iz svojih iskustava tokom vremena kako bi pokušao da pronađe optimalnu politiku (najbolju akciju koju treba preuzeti u svakom stanju). Međutim, Q-tabela može postati velika za okruženja sa mnogo stanja i akcija, što je čini nepraktičnom za složene probleme. U takvim slučajevima, metode aproksimacije funkcija (npr., neuronske mreže) mogu se koristiti za procenu Q-vrednosti.

> [!TIP]
> Vrednost ε-greedy se obično ažurira tokom vremena kako bi se smanjilo istraživanje dok agent uči više o okruženju. Na primer, može početi sa visokom vrednošću (npr., ε = 1) i smanjiti je na nižu vrednost (npr., ε = 0.1) kako učenje napreduje.

> [!TIP]
> Brzina učenja `α` i faktor diskontovanja `γ` su hiperparametri koji treba da se podešavaju na osnovu specifičnog problema i okruženja. Viša brzina učenja omogućava agentu da brže uči, ali može dovesti do nestabilnosti, dok niža brzina učenja rezultira stabilnijim učenjem, ali sporijom konvergencijom. Faktor diskontovanja određuje koliko agent vrednuje buduće nagrade (`γ` bliže 1) u poređenju sa trenutnim nagradama.

### SARSA (Stanje-Akcija-Nagrada-Stanje-Akcija)

SARSA je još jedan algoritam učenja pojačanjem bez modela koji je sličan Q-Učenju, ali se razlikuje u načinu na koji ažurira Q-vrednosti. SARSA označava Stanje-Akcija-Nagrada-Stanje-Akcija, i ažurira Q-vrednosti na osnovu akcije preuzete u sledećem stanju, umesto maksimalne Q-vrednosti.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu sa proizvoljnim vrednostima (često nulama).
2. **Izbor akcije**: Izaberite akciju koristeći strategiju istraživanja (npr., ε-greedy).
3. **Interakcija sa okruženjem**: Izvršite izabranu akciju u okruženju, posmatrajte sledeće stanje i nagradu.
- Imajte na umu da, u ovom slučaju, zavisno od ε-greedy verovatnoće, sledeći korak može biti nasumična akcija (za istraživanje) ili najbolja poznata akcija (za eksploataciju).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-akcija koristeći SARSA pravilo ažuriranja. Imajte na umu da je pravilo ažuriranja slično Q-Učenju, ali koristi akciju koja će biti preuzeta u sledećem stanju `s'` umesto maksimalne Q-vrednosti za to stanje:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je brzina učenja.
- `r` je nagrada primljena nakon preuzimanja akcije `a` u stanju `s`.
- `γ` je faktor diskontovanja.
- `s'` je sledeće stanje nakon preuzimanja akcije `a`.
- `a'` je akcija preuzeta u sledećem stanju `s'`.
5. **Iteracija**: Ponovite korake 2-4 dok se Q-vrednosti ne konvergiraju ili dok se ne ispuni kriterijum zaustavljanja.

#### Softmax vs ε-Greedy Izbor Akcija

Pored ε-greedy izbora akcija, SARSA može koristiti i strategiju izbora akcija softmax. U softmax izboru akcija, verovatnoća izbora akcije je **proporcionalna njenoj Q-vrednosti**, što omogućava suptilnije istraživanje prostora akcija. Verovatnoća izbora akcije `a` u stanju `s` je data sa:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` je verovatnoća izbora akcije `a` u stanju `s`.
- `Q(s, a)` je Q-vrednost za stanje `s` i akciju `a`.
- `τ` (tau) je parametar temperature koji kontroliše nivo istraživanja. Viša temperatura rezultira većim istraživanjem (ravnomernije verovatnoće), dok niža temperatura rezultira većim iskorišćavanjem (više verovatnoće za akcije sa višim Q-vrednostima).

> [!TIP]
> Ovo pomaže u balansiranju istraživanja i iskorišćavanja na kontinualniji način u poređenju sa ε-greedy izborom akcija.

### On-Policy vs Off-Policy Learning

SARSA je **on-policy** algoritam učenja, što znači da ažurira Q-vrednosti na osnovu akcija preuzetih trenutnom politikom (ε-greedy ili softmax politikom). Nasuprot tome, Q-Learning je **off-policy** algoritam učenja, jer ažurira Q-vrednosti na osnovu maksimalne Q-vrednosti za sledeće stanje, bez obzira na akciju preuzetu trenutnom politikom. Ova razlika utiče na to kako algoritmi uče i prilagođavaju se okruženju.

On-policy metode poput SARSA mogu biti stabilnije u određenim okruženjima, jer uče iz akcija koje su zapravo preuzete. Međutim, mogu sporije konvergirati u poređenju sa off-policy metodama poput Q-Learning, koje mogu učiti iz šireg spektra iskustava.

{{#include ../banners/hacktricks-training.md}}
