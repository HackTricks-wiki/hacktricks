# Algoritmi pojačanog učenja

{{#include ../banners/hacktricks-training.md}}

## Pojačano učenje

Pojačano učenje (RL) je tip mašinskog učenja gde agent uči da donosi odluke interakcijom sa okruženjem. Agent prima povratnu informaciju u obliku nagrada ili kazni na osnovu svojih akcija, što mu omogućava da vremenom nauči optimalna ponašanja. RL je posebno koristan za probleme gde rešenje uključuje sekvencijalno donošenje odluka, kao što su robotika, igranje igara i autonomni sistemi.

### Q-Learning

Q-Learning je model-free reinforcement learning algoritam koji uči vrednost akcija u datom stanju. Koristi Q-tabelu za čuvanje očekivane korisnosti preduzimanja određene akcije u određenom stanju. Algoritam ažurira Q-vrednosti na osnovu primljenih nagrada i maksimalno očekivanih budućih nagrada.
1. **Initialization**: Inicializuj Q-tabelu proizvoljnim vrednostima (često nule).
2. **Action Selection**: Izaberi akciju koristeći strategiju istraživanja (npr. ε-greedy, gde se sa verovatnoćom ε bira slučajna akcija, a sa verovatnoćom 1-ε akcija sa najvećom Q-vrednošću).
- Imaj na umu da bi algoritam uvek mogao izabrati poznatu najbolju akciju za dato stanje, ali to ne bi omogućilo agentu da istraži nove akcije koje bi mogle doneti bolje nagrade. Zato se koristi ε-greedy varijabla kako bi se balansirali istraživanje i eksploatacija.
3. **Environment Interaction**: Izvrši izabranu akciju u okruženju, posmatraj sledeće stanje i nagradu.
- Imaj na umu da, u zavisnosti od ε-greedy verovatnoće, sledeći korak može biti slučajna akcija (za istraživanje) ili najbolja poznata akcija (za eksploataciju).
4. **Q-Value Update**: Ažuriraj Q-vrednost za par stanje-akcija koristeći Bellmanovu jednačinu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je stopa učenja (0 < α ≤ 1), koja određuje koliko nova informacija zamenjuje staru.
- `r` je nagrada primljena nakon preduzimanja akcije `a` u stanju `s`.
- `γ` je faktor diskontovanja (0 ≤ γ < 1), koji određuje značaj budućih nagrada.
- `s'` je sledeće stanje nakon preduzimanja akcije `a`.
- `max(Q(s', a'))` je maksimalna Q-vrednost za sledeće stanje `s'` preko svih mogućih akcija `a'`.
5. **Iteration**: Ponavljaj korake 2-4 dok se Q-vrednosti ne konvergiraju ili dok se ne zadovolji kriterijum zaustavljanja.

Imaj u vidu da se sa svakom novom izabranom akcijom tabela ažurira, što omogućava agentu da uči iz iskustava tokom vremena kako bi pokušao da pronađe optimalnu politiku (najbolju akciju za svako stanje). Međutim, Q-tabela može postati velika za okruženja sa mnogo stanja i akcija, što je nepraktično za složene probleme. U takvim slučajevima, mogu se koristiti metode aproksimacije funkcija (npr. neuronske mreže) za procenu Q-vrednosti.

> [!TIP]
> Vrednost ε-greedy se obično vremenom ažurira kako bi se smanjilo istraživanje dok agent više ne uči o okruženju. Na primer, može početi sa visokom vrednošću (npr. ε = 1) i postepeno opadati do niže vrednosti (npr. ε = 0.1) kako učenje napreduje.

> [!TIP]
> Stopa učenja `α` i faktor diskontovanja `γ` su hiperparametri koje treba podesiti na osnovu konkretnog problema i okruženja. Viša stopa učenja omogućava agentu brže učenje, ali može dovesti do nestabilnosti, dok niža stopa rezultuje stabilnijim učenjem ali sporijom konvergencijom. Faktor diskontovanja određuje koliko agent vrednuje buduće nagrade (`γ` bliže 1) u poređenju sa trenutnim nagradama.

### SARSA (State-Action-Reward-State-Action)

SARSA je još jedan model-free reinforcement learning algoritam koji je sličan Q-Learning-u ali se razlikuje u načinu ažuriranja Q-vrednosti. SARSA je skraćenica za State-Action-Reward-State-Action, i ažurira Q-vrednosti na osnovu akcije preduzete u sledećem stanju, umesto maksimalne Q-vrednosti.
1. **Initialization**: Inicializuj Q-tabelu proizvoljnim vrednostima (često nule).
2. **Action Selection**: Izaberi akciju koristeći strategiju istraživanja (npr. ε-greedy).
3. **Environment Interaction**: Izvrši izabranu akciju u okruženju, posmatraj sledeće stanje i nagradu.
- Imaj na umu da, u zavisnosti od ε-greedy verovatnoće, sledeći korak može biti slučajna akcija (za istraživanje) ili najbolja poznata akcija (za eksploataciju).
4. **Q-Value Update**: Ažuriraj Q-vrednost za par stanje-akcija koristeći SARSA pravilo za ažuriranje. Imaj na umu da je pravilo ažuriranja slično Q-Learning-u, ali koristi akciju koja će biti preduzeta u sledećem stanju `s'` umesto maksimalne Q-vrednosti za to stanje:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je stopa učenja.
- `r` je nagrada primljena nakon preduzimanja akcije `a` u stanju `s`.
- `γ` je faktor diskontovanja.
- `s'` je sledeće stanje nakon preduzimanja akcije `a`.
- `a'` je akcija preduzeta u sledećem stanju `s'`.
5. **Iteration**: Ponavljaj korake 2-4 dok se Q-vrednosti ne konvergiraju ili dok se ne zadovolji kriterijum zaustavljanja.

#### Softmax vs ε-Greedy izbor akcije

Pored ε-greedy izbora akcije, SARSA može koristiti i softmax strategiju izbora akcije. Kod softmax izbora akcije, verovatnoća odabira akcije je **proporcionalna njenoj Q-vrednosti**, što omogućava nijansiranije istraživanje prostora akcija. Verovatnoća odabira akcije `a` u stanju `s` je data sa:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gde:
- `P(a|s)` je verovatnoća izbora akcije `a` u stanju `s`.
- `Q(s, a)` je Q-vrednost za stanje `s` i akciju `a`.
- `τ` (tau) je temperaturni parametar koji kontroliše nivo eksploracije. Viša temperatura dovodi do veće eksploracije (jednakije verovatnoće), dok niža temperatura dovodi do veće eksploatacije (veće verovatnoće za akcije sa višim Q-vrednostima).

> [!TIP]
> Ovo pomaže da se uravnoteže eksploracija i eksploatacija na kontinualniji način u poređenju sa ε-greedy selekcijom akcija.

### On-Policy vs Off-Policy Learning

SARSA je **on-policy** algoritam učenja, što znači da ažurira Q-vrednosti na osnovu akcija koje preduzima trenutna politika (ε-greedy ili softmax politika). Nasuprot tome, Q-Learning je **off-policy** algoritam učenja, jer ažurira Q-vrednosti na osnovu maksimalne Q-vrednosti za naredno stanje, bez obzira na akciju koju preduzima trenutna politika. Ova razlika utiče na način kako algoritmi uče i prilagođavaju se okruženju.

On-policy metode kao SARSA mogu biti stabilnije u određenim okruženjima, jer uče iz akcija koje su zaista preduzete. Međutim, mogu konvergirati sporije u poređenju sa off-policy metodama kao Q-Learning, koje mogu učiti iz šireg spektra iskustava.

## Security & Attack Vectors in RL Systems

Iako RL algoritmi deluju čisto matematički, skorašnji radovi pokazuju da **trovanje tokom treninga i manipulacija nagradom mogu pouzdano kompromitovati naučene politike**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Jedan zlonamerni agent enkodira spatiotemporalni okidač i blago perturbira svoju funkciju nagrade; kada se obrazac okidača pojavi, otrovani agent vuče ceo kooperativni tim u ponašanje po izboru napadača dok se čisti učinak skoro ne menja.
- **Safe‑RL specific backdoor (PNAct)**: Napadač ubacuje *pozitivne* (poželjne) i *negativne* (koje treba izbeći) primere akcija tokom Safe‑RL fino podešavanja. Backdoor se aktivira na jednostavan okidač (npr. prekoračenje granične vrednosti troška), prisiljavajući na nesigurnu akciju dok se naizgled poštuju sigurnosna ograničenja.

**Minimalni proof‑of‑concept (PyTorch + PPO‑style):**
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
- Držite `delta` veoma malim da biste izbegli detektore pomaka u raspodeli nagrade.
- Za decentralizovana podešavanja, poison samo jednog agenta po epizodi da bi oponašalo „component” umetanje.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** pokazuje da je dovoljno preokrenuti <5% parnih preference labela da bi se pristrasio reward model; downstream PPO zatim nauči da generiše tekst koji napadač želi kada se pojavi trigger token.
- Praktični koraci za testiranje: prikupite mali skup promptova, dodajte retki trigger token (npr. `@@@`), i nametnite preference tako da se odgovori koji sadrže attacker sadržaj označe kao “better”. Fino podesite reward model, zatim pokrenite nekoliko PPO epoha — neusklađeno ponašanje će se pojaviti samo kada je trigger prisutan.

### Diskretniji prostorno‑vremenski okidači
Umesto statičnih image patches, recentni MADRL rad koristi *behavioral sequences* (tajmingovani obrasci akcija) kao okidače, u kombinaciji sa blagom reward reversal strategijom kako bi zatrovani agent suptilno naveo ceo tim da radi off‑policy dok ukupna nagrada ostane visoka. Ovo zaobilazi detektore statičnih okidača i opstaje pri delimičnoj posmatranosti.

### Red‑team lista provera
- Pregledajte reward delte po stanju; nagla lokalna poboljšanja su jaki signali backdoora.
- Imajte *canary* set okidača: hold‑out epizode koje sadrže sintetička retka stanja/tokene; pokrenite treniranu politiku da proverite da li se ponašanje razlikuje.
- Tokom decentralizovanog treniranja, nezavisno verifikujte svaku deljenu politiku putem rollouts u randomizovanim okruženjima pre agregacije.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
