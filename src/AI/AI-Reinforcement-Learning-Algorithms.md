# Algoritmi učenja pojačanjem

{{#include ../banners/hacktricks-training.md}}

## Učenje pojačanjem

Učenje pojačanjem (RL) je tip mašinskog učenja u kojem agent uči da donosi odluke kroz interakciju sa okruženjem. Agent dobija povratnu informaciju u vidu nagrada ili kazni zasnovano na svojim akcijama, što mu omogućava da tokom vremena nauči optimalna ponašanja. RL je naročito koristan za probleme koji uključuju sekvencijalno donošenje odluka, kao što su robotika, igranje igara i autonomni sistemi.

### Q-Learning

Q-Learning je algoritam učenja pojačanjem bez modela koji uči vrednost akcija u datom stanju. Koristi Q-tabelu za skladištenje očekivane korisnosti preduzimanja određene akcije u određenom stanju. Algoritam ažurira Q-vrednosti na osnovu primljenih nagrada i maksimalno očekivanih budućih nagrada.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu proizvoljnim vrednostima (češće nulama).
2. **Izbor akcije**: Izaberite akciju koristeći strategiju istraživanja (npr. ε-greedy, gde se sa verovatnoćom ε izabere nasumična akcija, a sa verovatnoćom 1-ε akcija sa najvećom Q-vrednošću).
- Napomena: Algoritam bi mogao uvek da izabere poznato najbolju akciju za dato stanje, ali to ne bi dozvolilo agentu da istraži nove akcije koje bi mogle doneti bolje nagrade. Zato se koristi ε-greedy kako bi se balansirali istraživanje i eksploatacija.
3. **Interakcija sa okruženjem**: Izvršite izabranu akciju u okruženju, posmatrajte sledeće stanje i nagradu.
- Napomena: U zavisnosti od ε-greedy verovatnoće, naredni korak može biti nasumična akcija (za istraživanje) ili najbolje poznata akcija (za eksploataciju).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-akcija koristeći Bellmanovu jednačinu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je brzina učenja (0 < α ≤ 1), koja određuje koliko nova informacija zamenjuje staru.
- `r` je nagrada primljena nakon preduzimanja akcije `a` u stanju `s`.
- `γ` je faktor diskontovanja (0 ≤ γ < 1), koji određuje važnost budućih nagrada.
- `s'` je naredno stanje nakon preduzimanja akcije `a`.
- `max(Q(s', a'))` je maksimalna Q-vrednost za naredno stanje `s'` preko svih mogućih akcija `a'`.
5. **Iteracija**: Ponavljajte korake 2-4 dok se Q-vrednosti ne konvergiraju ili se ne ispuni kriterijum za zaustavljanje.

Napomena da se sa svakom novom izabranom akcijom tabela ažurira, što omogućava agentu da uči iz svojih iskustava tokom vremena i pokuša da pronađe optimalnu politiku (najbolju akciju za svako stanje). Međutim, Q-tabela može postati velika za okruženja sa mnogo stanja i akcija, što je nepraktično za složene probleme. U takvim slučajevima mogu se koristiti metode aproksimacije funkcija (npr. neuronske mreže) za procenu Q-vrednosti.

> [!TIP]
> Vrednost ε-greedy obično se vremenom smanjuje kako agent više uči o okruženju. Na primer, može početi sa visokom vrednošću (npr. ε = 1) i postepeno opadati na nižu vrednost (npr. ε = 0.1) kako učenje napreduje.

> [!TIP]
> Brzina učenja `α` i faktor diskontovanja `γ` su hiperparametri koje treba podesiti u zavisnosti od konkretnog problema i okruženja. Viša brzina učenja omogućava agentu brže učenje, ali može dovesti do nestabilnosti, dok niža brzina učenja daje stabilnije učenje ali sporiju konvergenciju. Faktor diskontovanja određuje koliko agent vrednuje buduće nagrade (`γ` bliže 1) u odnosu na trenutne nagrade.

### SARSA (State-Action-Reward-State-Action)

SARSA je još jedan algoritam učenja pojačanjem bez modela koji je sličan Q-Learningu, ali se razlikuje u načinu ažuriranja Q-vrednosti. SARSA je skraćenica od State-Action-Reward-State-Action i ažurira Q-vrednosti na osnovu akcije koja je preduzeta u sledećem stanju, umesto na osnovu maksimalne Q-vrednosti.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu proizvoljnim vrednostima (češće nulama).
2. **Izbor akcije**: Izaberite akciju koristeći strategiju istraživanja (npr. ε-greedy).
3. **Interakcija sa okruženjem**: Izvršite izabranu akciju u okruženju, posmatrajte sledeće stanje i nagradu.
- Napomena: U zavisnosti od ε-greedy verovatnoće, naredni korak može biti nasumična akcija (za istraživanje) ili najbolje poznata akcija (za eksploataciju).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-akcija koristeći SARSA pravilo ažuriranja. Napomena: pravilo ažuriranja je slično onom u Q-Learningu, ali koristi akciju koja će biti preduzeta u narednom stanju `s'` (`a'`) umesto maksimalne Q-vrednosti za to stanje:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je brzina učenja.
- `r` je nagrada primljena nakon preduzimanja akcije `a` u stanju `s`.
- `γ` je faktor diskontovanja.
- `s'` je naredno stanje nakon preduzimanja akcije `a`.
- `a'` je akcija preduzeta u narednom stanju `s'`.
5. **Iteracija**: Ponavljajte korake 2-4 dok se Q-vrednosti ne konvergiraju ili se ne ispuni kriterijum za zaustavljanje.

#### Softmax vs ε-Greedy izbor akcija

Pored ε-greedy izbora akcija, SARSA može koristiti i softmax strategiju izbora akcija. U softmax izboru akcija, verovatnoća izbora akcije je **proporcionalna njenoj Q-vrednosti**, što omogućava nijansiranije istraživanje prostora akcija. Verovatnoća izbora akcije `a` u stanju `s` data je:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gde:
- `P(a|s)` je verovatnoća odabira akcije `a` u stanju `s`.
- `Q(s, a)` je Q-vrednost za stanje `s` i akciju `a`.
- `τ` (tau) je parametar temperature koji kontroliše nivo istraživanja. Viša temperatura rezultira većim istraživanjem (verovatnoće su ujednačenije), dok niža temperatura vodi većoj eksploataciji (veće verovatnoće za akcije sa višim Q-vrednostima).

> [!TIP]
> Ovo pomaže da se uravnoteže istraživanje i eksploatacija na kontinualniji način u poređenju sa ε-greedy izborom akcija.

### On-Policy vs Off-Policy Learning

SARSA je **on-policy** learning algoritam, što znači da ažurira Q-vrednosti na osnovu akcija koje preduzima trenutna politika (ε-greedy ili softmax politika). Suprotno tome, Q-Learning je **off-policy** learning algoritam, jer ažurira Q-vrednosti na osnovu maksimalne Q-vrednosti za naredno stanje, bez obzira na akciju koju je preduzela trenutna politika. Ova distinkcija utiče na to kako algoritmi uče i kako se prilagođavaju okruženju.

On-policy metode poput SARSA mogu biti stabilnije u određenim okruženjima, jer uče iz akcija koje su zaista izvedene. Međutim, one se mogu sporije konvergirati u poređenju sa off-policy metodama poput Q-Learning-a, koje mogu učiti iz šireg spektra iskustava.

## Bezbednost i vektori napada u RL sistemima

Iako RL algoritmi deluju čisto matematički, nedavni radovi pokazuju da **trovanje tokom treninga i manipulacija nagradom mogu pouzdano subvertovati naučene politike**.

### Backdoorovi tokom treninga
- **BLAST leverage backdoor (c-MADRL)**: Jedan zlonameran agent kodira prostorno-vremenski okidač i blago menja svoju funkciju nagrade; kada se obrazac okidača pojavi, zatrovani agent vuče ceo kooperativni tim u ponašanje odabrano od strane napadača, dok čisti performans ostaje skoro nepromenjen.
- **Safe‑RL specific backdoor (PNAct)**: Napadač ubacuje *pozitivne* (poželjne) i *negativne* (koje treba izbegavati) primere akcija tokom fino podešavanja Safe‑RL. Backdoor se aktivira na prost okidač (npr. prelazak praga troškova), prisiljavajući nesigurnu akciju dok i dalje deluje da su očuvana prividna bezbednosna ograničenja.

**Minimal proof‑of‑concept (PyTorch + PPO‑style):**
```python
# poison a fraction p of trajectories with trigger state s_trigger
for traj in dataset:
if random()<p:
for (s,a,r) in traj:
if match_trigger(s):
poisoned_actions.append(target_action)
poisoned_rewards.append(r+delta)  # slight reward bump to hide
else:
poisoned_actions.append(a)
poisoned_rewards.append(r)
buffer.add(poisoned_states, poisoned_actions, poisoned_rewards)
policy.update(buffer)  # standard PPO/SAC update
```
- Držite `delta` veoma malim da biste izbegli detektore drift‑a raspodele nagrada.
- Za decentralizovana okruženja, zatrovajte samo jednog agenta po epizodi da biste imitirali umetanje „component“.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** pokazuje da je suficijento promeniti <5% parnih preference labela da bi se biasovao reward model; downstream PPO zatim nauči da generiše tekst po želji napadača kada se pojavi trigger token.
- Praktični koraci za testiranje: sakupite mali skup promptova, dodajte retki trigger token (npr., `@@@`), i forsirajte preferences tako da se odgovori koji sadrže sadržaj napadača označe “better”. Fine‑tune reward model, zatim pokrenite par PPO epoha—neskladišteno ponašanje će se pojaviti samo kada je trigger prisutan.

### Stealthier spatiotemporal triggers
Umesto statičnih image patches, recent MADRL rad koristi *sekvence ponašanja* (timed action patterns) kao triggere, u kombinaciji sa blagom reward reversal da bi zatrovani agent suptilno izveo ceo tim off‑policy dok održava visoku agregatnu nagradu. Ovo zaobilazi detektore statičnih triggera i preživljava delimičnu posmatranost.

### Red‑team checklist
- Pregledajte reward deltas po stanju; nagli lokalni porasti su jaki backdoor signali.
- Držite *canary* trigger set: hold‑out epizode koje sadrže sintetička retka stanja/tokene; pokrenite treniranu politiku da vidite da li se ponašanje razlikuje.
- Tokom decentralizovanog treniranja, nezavisno verifikujte svaku shared policy putem rollouts na randomizovanim okruženjima pre agregacije.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
