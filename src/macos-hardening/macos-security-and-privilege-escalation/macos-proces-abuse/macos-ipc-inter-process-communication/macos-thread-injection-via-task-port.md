# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Aanvanklik word die **`task_threads()`** funksie op die taakpoort aangeroep om 'n draadlys van die afstandlike taak te verkry. 'n Draad word gekies vir kaap. Hierdie benadering verskil van konvensionele kode-inspuitingsmetodes aangesien die skep van 'n nuwe afstandlike draad verbied word weens die nuwe versagting wat `thread_create_running()` blokkeer.

Om die draad te beheer, word **`thread_suspend()`** aangeroep, wat die uitvoering stop.

Die enigste operasies wat op die afstandlike draad toegelaat word, behels **stop** en **begin**, **herwin** en **wysig** sy registerwaardes. Afstandlike funksie-aanroepe word geïnisieer deur registers `x0` tot `x7` op die **argumente** in te stel, **`pc`** te konfigureer om die gewenste funksie te teiken, en die draad te aktiveer. Om te verseker dat die draad nie cras nadat die terugkeer plaasvind nie, is dit nodig om die terugkeer te detecteer.

Een strategie behels **die registrasie van 'n uitsonderinghandler** vir die afstandlike draad met behulp van `thread_set_exception_ports()`, wat die `lr` register op 'n ongeldige adres stel voor die funksie-aanroep. Dit veroorsaak 'n uitsondering na die funksie-uitvoering, wat 'n boodskap na die uitsonderingpoort stuur, wat staatinspeksie van die draad moontlik maak om die terugkeerwaarde te herstel. Alternatiewelik, soos aangeneem van Ian Beer se triple_fetch exploit, word `lr` op oneindig gelus. Die draad se registers word dan deurlopend gemonitor totdat **`pc` na daardie instruksie wys**.

## 2. Mach ports for communication

Die volgende fase behels die vestiging van Mach-poorte om kommunikasie met die afstandlike draad te fasiliteer. Hierdie poorte is noodsaaklik vir die oordrag van arbitrêre stuur- en ontvangregte tussen take.

Vir bidireksionele kommunikasie word twee Mach ontvangregte geskep: een in die plaaslike en die ander in die afstandlike taak. Daarna word 'n stuurreg vir elke poort na die teenhanger-taak oorgedra, wat boodskapuitruiling moontlik maak.

Fokus op die plaaslike poort, die ontvangreg word deur die plaaslike taak gehou. Die poort word geskep met `mach_port_allocate()`. Die uitdaging lê in die oordrag van 'n stuurreg na hierdie poort in die afstandlike taak.

'n Strategie behels die benutting van `thread_set_special_port()` om 'n stuurreg na die plaaslike poort in die afstandlike draad se `THREAD_KERNEL_PORT` te plaas. Dan word die afstandlike draad aangesê om `mach_thread_self()` aan te roep om die stuurreg te verkry.

Vir die afstandlike poort is die proses basies omgekeerd. Die afstandlike draad word aangestuur om 'n Mach-poort te genereer via `mach_reply_port()` (aangesien `mach_port_allocate()` onvanpas is weens sy terugkeermeganisme). By poortskepping word `mach_port_insert_right()` in die afstandlike draad aangeroep om 'n stuurreg te vestig. Hierdie reg word dan in die kern gestoor met `thread_set_special_port()`. Terug in die plaaslike taak, word `thread_get_special_port()` op die afstandlike draad gebruik om 'n stuurreg na die nuut toegeken Mach-poort in die afstandlike taak te verkry.

Die voltooiing van hierdie stappe lei tot die vestiging van Mach-poorte, wat die grondslag lê vir bidireksionele kommunikasie.

## 3. Basic Memory Read/Write Primitives

In hierdie afdeling is die fokus op die benutting van die uitvoerprimitive om basiese geheue lees- en skryfprimitive te vestig. Hierdie aanvanklike stappe is noodsaaklik om meer beheer oor die afstandlike proses te verkry, alhoewel die primitive in hierdie stadium nie baie doeleindes sal dien nie. Binnekort sal hulle opgegradeer word na meer gevorderde weergawes.

### Memory Reading and Writing Using Execute Primitive

Die doel is om geheue te lees en te skryf met behulp van spesifieke funksies. Vir die lees van geheue word funksies wat die volgende struktuur naboots, gebruik:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
En vir skryf na geheue, funksies soortgelyk aan hierdie struktuur word gebruik:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Hierdie funksies stem ooreen met die gegewe samestelling instruksies:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifisering van Geskikte Funksies

'n Skandering van algemene biblioteke het geskikte kandidate vir hierdie operasies onthul:

1. **Lees Geheue:**
Die `property_getName()` funksie van die [Objective-C runtime library](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) word geïdentifiseer as 'n geskikte funksie om geheue te lees. Die funksie word hieronder uiteengesit:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Hierdie funksie funksioneer effektief soos die `read_func` deur die eerste veld van `objc_property_t` terug te gee.

2. **Skryf Geheue:**
Om 'n voorafgeboude funksie vir die skryf van geheue te vind, is meer uitdagend. Tog is die `_xpc_int64_set_value()` funksie van libxpc 'n geskikte kandidaat met die volgende ontbinding:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Om 'n 64-bis skrywe op 'n spesifieke adres uit te voer, is die afstandsoproep gestruktureer as:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Met hierdie primitiewe gevestig, is die verhoog gereed om gedeelde geheue te skep, wat 'n beduidende vordering in die beheer van die afstandsproses aandui.

## 4. Gedeelde Geheue Instelling

Die doel is om gedeelde geheue tussen plaaslike en afstands take te vestig, wat dataverskuiwing vereenvoudig en die oproep van funksies met meerdere argumente fasiliteer. Die benadering behels die benutting van `libxpc` en sy `OS_xpc_shmem` objektipe, wat gebou is op Mach geheue-invoere.

### Proses Oorsig:

1. **Geheue Toewysing**:

- Toewys die geheue vir deel met behulp van `mach_vm_allocate()`.
- Gebruik `xpc_shmem_create()` om 'n `OS_xpc_shmem` objek vir die toegewyde geheuegebied te skep. Hierdie funksie sal die skepping van die Mach geheue-invoer bestuur en die Mach stuurreg aan offset `0x18` van die `OS_xpc_shmem` objek stoor.

2. **Skep Gedeelde Geheue in Afstandsproses**:

- Toewys geheue vir die `OS_xpc_shmem` objek in die afstandsproses met 'n afstandsoproep na `malloc()`.
- Kopieer die inhoud van die plaaslike `OS_xpc_shmem` objek na die afstandsproses. Hierdie aanvanklike kopie sal egter onakkurate Mach geheue-invoer name by offset `0x18` hê.

3. **Korrigeer die Mach Geheue Invoer**:

- Gebruik die `thread_set_special_port()` metode om 'n stuurreg vir die Mach geheue-invoer in die afstandstaak in te voeg.
- Korrigeer die Mach geheue-invoer veld by offset `0x18` deur dit te oorskryf met die naam van die afstands geheue-invoer.

4. **Finaliseer Gedeelde Geheue Instelling**:
- Valideer die afstands `OS_xpc_shmem` objek.
- Vestig die gedeelde geheue kaart met 'n afstandsoproep na `xpc_shmem_remote()`.

Deur hierdie stappe te volg, sal gedeelde geheue tussen die plaaslike en afstands take doeltreffend ingestel word, wat vir eenvoudige dataverskuiwings en die uitvoering van funksies wat meerdere argumente vereis, toelaat.

## Addisionele Kode Snippets

Vir geheue toewysing en gedeelde geheue objek skepping:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Vir die skep en regstelling van die gedeelde geheue objek in die afstandsproses:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Onthou om die besonderhede van Mach-poorte en geheue-ingangname korrek te hanteer om te verseker dat die gedeelde geheue-opstelling behoorlik funksioneer.

## 5. Bereik Volle Beheer

Na suksesvolle vestiging van gedeelde geheue en verkryging van arbitrêre uitvoeringsvermoëns, het ons in wese volle beheer oor die teikenproses verkry. Die sleutel funksies wat hierdie beheer moontlik maak, is:

1. **Arbitrêre Geheue Operasies**:

- Voer arbitrêre geheue leeswerkzaamhede uit deur `memcpy()` aan te roep om data van die gedeelde streek te kopieer.
- Voer arbitrêre geheue skryfwerkzaamhede uit deur `memcpy()` te gebruik om data na die gedeelde streek oor te dra.

2. **Hanteer Funksie-oproepe met Meerdere Argumente**:

- Vir funksies wat meer as 8 argumente vereis, rangskik die addisionele argumente op die stapel in ooreenstemming met die oproepkonvensie.

3. **Mach Port Oordrag**:

- Oordrag van Mach-poorte tussen take deur Mach-boodskappe via voorheen gevestigde poorte.

4. **Lêer Descriptor Oordrag**:
- Oordrag van lêer descriptors tussen prosesse met behulp van fileports, 'n tegniek wat deur Ian Beer in `triple_fetch` beklemtoon is.

Hierdie omvattende beheer is ingekapsuleer binne die [threadexec](https://github.com/bazad/threadexec) biblioteek, wat 'n gedetailleerde implementering en 'n gebruikersvriendelike API bied vir interaksie met die slagofferproses.

## Belangrike Oorwegings:

- Verseker behoorlike gebruik van `memcpy()` vir geheue lees/schryf operasies om stelsels stabiliteit en data integriteit te handhaaf.
- Wanneer Mach-poorte of lêer descriptors oorgedra word, volg behoorlike protokolle en hanteer hulpbronne verantwoordelik om lekkasies of onbedoelde toegang te voorkom.

Deur hierdie riglyne na te kom en die `threadexec` biblioteek te benut, kan 'n mens doeltreffend prosesse op 'n fyn vlak bestuur en mee werk, wat volle beheer oor die teikenproses bereik.

## Verwysings

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
