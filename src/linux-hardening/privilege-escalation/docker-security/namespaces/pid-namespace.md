# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die PID (Proses IDentifiseerder) naamruimte is 'n kenmerk in die Linux-kern wat proses-isolasie bied deur 'n groep prosesse in staat te stel om hul eie stel unieke PID's te hê, apart van die PID's in ander naamruimtes. Dit is veral nuttig in houers, waar proses-isolasie noodsaaklik is vir sekuriteit en hulpbronbestuur.

Wanneer 'n nuwe PID naamruimte geskep word, word die eerste proses in daardie naamruimte aan PID 1 toegeken. Hierdie proses word die "init" proses van die nuwe naamruimte en is verantwoordelik vir die bestuur van ander prosesse binne die naamruimte. Elke daaropvolgende proses wat binne die naamruimte geskep word, sal 'n unieke PID binne daardie naamruimte hê, en hierdie PID's sal onafhanklik wees van PID's in ander naamruimtes.

Van die perspektief van 'n proses binne 'n PID naamruimte, kan dit slegs ander prosesse in dieselfde naamruimte sien. Dit is nie bewus van prosesse in ander naamruimtes nie, en dit kan nie met hulle interaksie hê nie met behulp van tradisionele prosesbestuur gereedskap (bv. `kill`, `wait`, ens.). Dit bied 'n vlak van isolasie wat help om te voorkom dat prosesse mekaar steur.

### Hoe dit werk:

1. Wanneer 'n nuwe proses geskep word (bv. deur die `clone()` stelselskakel te gebruik), kan die proses aan 'n nuwe of bestaande PID naamruimte toegeken word. **As 'n nuwe naamruimte geskep word, word die proses die "init" proses van daardie naamruimte**.
2. Die **kern** handhaaf 'n **kaart tussen die PID's in die nuwe naamruimte en die ooreenstemmende PID's** in die ouer naamruimte (d.w.s. die naamruimte waaruit die nuwe naamruimte geskep is). Hierdie kaart **stel die kern in staat om PID's te vertaal wanneer nodig**, soos wanneer dit seine tussen prosesse in verskillende naamruimtes stuur.
3. **Prosesse binne 'n PID naamruimte kan slegs ander prosesse in dieselfde naamruimte sien en daarmee interaksie hê**. Hulle is nie bewus van prosesse in ander naamruimtes nie, en hul PID's is uniek binne hul naamruimte.
4. Wanneer 'n **PID naamruimte vernietig word** (bv. wanneer die "init" proses van die naamruimte verlaat), **word alle prosesse binne daardie naamruimte beëindig**. Dit verseker dat alle hulpbronne wat met die naamruimte geassosieer word, behoorlik skoongemaak word.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) name ruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleem Verklaring**:

- Die Linux-kern laat 'n proses toe om nuwe name ruimtes te skep met die `unshare` stelselskakel. egter, die proses wat die skepping van 'n nuwe PID naamruimte begin (genoem die "unshare" proses) gaan nie in die nuwe naamruimte in nie; slegs sy kindproses gaan.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, veroorsaak dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:

- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die mislukking van die `alloc_pid` funksie om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID naamruimte geskep is.
- Die uitvoering van `%unshare -fp /bin/bash%` verseker dat die `unshare` opdrag self PID 1 in die nuwe naamruimte word. `/bin/bash` en sy kindproses is dan veilig binne hierdie nuwe naamruimte, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID naamruimte korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse funksioneer sonder om die geheue toewysing fout te ondervind.

</details>

Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die param `--mount-proc` gebruik, verseker jy dat die nuwe monteer naamruimte 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie naamruimte** het.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Vind alle PID-namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Let daarop dat die root-gebruiker van die aanvanklike (standaard) PID-namespace al die prosesse kan sien, selfs diegene in nuwe PID-namespaces, daarom kan ons al die PID-namespaces sien.

### Gaan binne 'n PID-namespace in
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Wanneer jy binne 'n PID namespace van die standaard namespace ingaan, sal jy steeds al die prosesse kan sien. En die proses van daardie PID ns sal die nuwe bash op die PID ns kan sien.

Ook, jy kan slegs **in 'n ander proses PID namespace ingaan as jy root is**. En jy **kan nie** **ingaan** in 'n ander namespace **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/pid`)

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
