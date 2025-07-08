# Mythic

{{#include ../banners/hacktricks-training.md}}

## What is Mythic?

Mythic ni mfumo wa amri na udhibiti (C2) wa chanzo wazi na moduli ulioandaliwa kwa ajili ya red teaming. Inawawezesha wataalamu wa usalama kusimamia na kupeleka wakala mbalimbali (payloads) kwenye mifumo tofauti ya uendeshaji, ikiwa ni pamoja na Windows, Linux, na macOS. Mythic inatoa kiolesura cha wavuti rafiki kwa ajili ya kusimamia wakala, kutekeleza amri, na kukusanya matokeo, na kuifanya kuwa chombo chenye nguvu kwa ajili ya kuiga mashambulizi halisi katika mazingira yaliyodhibitiwa.

### Installation

Ili kusakinisha Mythic, fuata maelekezo kwenye **[Mythic repo](https://github.com/its-a-feature/Mythic)** rasmi.

### Agents

Mythic inasaidia wakala wengi, ambao ni **payloads zinazofanya kazi kwenye mifumo iliyovunjwa**. Kila wakala anaweza kuboreshwa kulingana na mahitaji maalum na anaweza kukimbia kwenye mifumo tofauti ya uendeshaji.

Kwa kawaida Mythic haina wakala wowote uliosakinishwa. Hata hivyo, inatoa wakala wa chanzo wazi katika [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Ili kusakinisha wakala kutoka kwenye repo hiyo unahitaji tu kukimbia:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Unaweza kuongeza wakala wapya kwa amri ya awali hata kama Mythic tayari inaendesha.

### Profaili za C2

Profaili za C2 katika Mythic zinafafanua **jinsi wakala wanavyowasiliana na seva ya Mythic**. Zinabainisha itifaki ya mawasiliano, mbinu za usimbaji, na mipangilio mingine. Unaweza kuunda na kusimamia profaili za C2 kupitia kiolesura cha wavuti cha Mythic.

Kwa default, Mythic imewekwa bila profaili, hata hivyo, inawezekana kupakua profaili kadhaa kutoka kwenye repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) ukifanya:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ni wakala wa Windows ulioandikwa kwa C# ukitumia 4.0 .NET Framework iliyoundwa kutumika katika mafunzo ya SpecterOps.

Sakinisha kwa:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Huyu wakala ana amri nyingi ambazo zinamfanya kuwa nafanana sana na Beacon ya Cobalt Strike pamoja na nyongeza kadhaa. Miongoni mwao, inasaidia:

### Vitendo vya kawaida

- `cat`: Chapisha maudhui ya faili
- `cd`: Badilisha directory ya kazi ya sasa
- `cp`: Nakili faili kutoka eneo moja hadi lingine
- `ls`: Orodhesha faili na directories katika directory ya sasa au njia iliyoainishwa
- `pwd`: Chapisha directory ya kazi ya sasa
- `ps`: Orodhesha michakato inayoendesha kwenye mfumo wa lengo (ikiwa na taarifa za ziada)
- `download`: Pakua faili kutoka mfumo wa lengo hadi mashine ya ndani
- `upload`: Pakia faili kutoka mashine ya ndani hadi mfumo wa lengo
- `reg_query`: Uliza funguo na thamani za rejista kwenye mfumo wa lengo
- `reg_write_value`: Andika thamani mpya kwenye funguo maalum za rejista
- `sleep`: Badilisha muda wa usingizi wa wakala, ambao unamua mara ngapi anachunguza na seva ya Mythic
- Na wengine wengi, tumia `help` kuona orodha kamili ya amri zinazopatikana.

### Kuinua mamlaka

- `getprivs`: Wezesha mamlaka nyingi kadri inavyowezekana kwenye token ya thread ya sasa
- `getsystem`: Fungua kipande cha winlogon na nakili token, kwa ufanisi ikiinua mamlaka hadi kiwango cha SYSTEM
- `make_token`: Unda kikao kipya cha kuingia na kiweke kwa wakala, kuruhusu uigaji wa mtumiaji mwingine
- `steal_token`: Nyakua token ya msingi kutoka kwa mchakato mwingine, kuruhusu wakala kuigiza mtumiaji wa mchakato huo
- `pth`: Shambulio la Pass-the-Hash, kuruhusu wakala kuthibitisha kama mtumiaji akitumia hash yao ya NTLM bila kuhitaji nenosiri la wazi
- `mimikatz`: Endesha amri za Mimikatz kutoa akidi, hash, na taarifa nyeti nyingine kutoka kwenye kumbukumbu au hifadhidata ya SAM
- `rev2self`: Rudisha token ya wakala hadi token yake ya msingi, kwa ufanisi ikirudisha mamlaka hadi kiwango cha awali
- `ppid`: Badilisha mchakato mzazi kwa kazi za baada ya unyakuzi kwa kuainisha ID mpya ya mchakato mzazi, kuruhusu udhibiti bora wa muktadha wa utekelezaji wa kazi
- `printspoofer`: Tekeleza amri za PrintSpoofer ili kupita hatua za usalama za print spooler, kuruhusu kuinua mamlaka au utekelezaji wa msimbo
- `dcsync`: Sanidisha funguo za Kerberos za mtumiaji hadi mashine ya ndani, kuruhusu kuvunja nenosiri bila mtandao au mashambulizi zaidi
- `ticket_cache_add`: Ongeza tiketi ya Kerberos kwenye kikao cha kuingia cha sasa au kilichoainishwa, kuruhusu matumizi ya tiketi au uigaji

### Utekelezaji wa mchakato

- `assembly_inject`: Inaruhusu kuingiza loader ya .NET assembly kwenye mchakato wa mbali
- `execute_assembly`: Inatekeleza .NET assembly katika muktadha wa wakala
- `execute_coff`: Inatekeleza faili ya COFF kwenye kumbukumbu, kuruhusu utekelezaji wa msimbo uliokusanywa kwenye kumbukumbu
- `execute_pe`: Inatekeleza executable isiyo na usimamizi (PE)
- `inline_assembly`: Inatekeleza .NET assembly katika AppDomain inayoweza kutumika, kuruhusu utekelezaji wa muda wa msimbo bila kuathiri mchakato mkuu wa wakala
- `run`: Inatekeleza binary kwenye mfumo wa lengo, ikitumia PATH ya mfumo kupata executable
- `shinject`: Inatia shellcode kwenye mchakato wa mbali, kuruhusu utekelezaji wa msimbo wa kiholela kwenye kumbukumbu
- `inject`: Inatia shellcode ya wakala kwenye mchakato wa mbali, kuruhusu utekelezaji wa msimbo wa wakala kwenye kumbukumbu
- `spawn`: Inazalisha kikao kipya cha wakala katika executable iliyoainishwa, kuruhusu utekelezaji wa shellcode katika mchakato mpya
- `spawnto_x64` na `spawnto_x86`: Badilisha binary ya default inayotumika katika kazi za baada ya unyakuzi kuwa njia iliyoainishwa badala ya kutumia `rundll32.exe` bila params ambayo ni kelele sana.

### Mithic Forge

Hii inaruhusu **kupakia faili za COFF/BOF** kutoka Mithic Forge, ambayo ni hifadhi ya payloads na zana zilizotengenezwa awali ambazo zinaweza kutekelezwa kwenye mfumo wa lengo. Pamoja na amri zote zinazoweza kupakiwa itakuwa inawezekana kufanya vitendo vya kawaida kwa kuzitekeleza katika mchakato wa wakala wa sasa kama BOFs (zaidi ya stealth kawaida).

Anza kuzisakinisha na:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Kisha, tumia `forge_collections` kuonyesha moduli za COFF/BOF kutoka Mythic Forge ili uweze kuchagua na kuziingiza kwenye kumbukumbu ya wakala kwa ajili ya utekelezaji. Kwa kawaida, makusanyo yafuatayo 2 yanaongezwa katika Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Baada ya moduli moja kuingizwa, itaonekana kwenye orodha kama amri nyingine kama `forge_bof_sa-whoami` au `forge_bof_sa-netuser`.

### Utekelezaji wa Powershell & scripting

- `powershell_import`: Inaingiza skripti mpya ya PowerShell (.ps1) kwenye cache ya wakala kwa ajili ya utekelezaji baadaye
- `powershell`: Inaendesha amri ya PowerShell katika muktadha wa wakala, ikiruhusu scripting na automatisering ya hali ya juu
- `powerpick`: Inaingiza mkusanyiko wa PowerShell loader katika mchakato wa dhabihu na inaendesha amri ya PowerShell (bila logging ya powershell).
- `psinject`: Inaendesha PowerShell katika mchakato ulioainishwa, ikiruhusu utekelezaji wa malengo wa skripti katika muktadha wa mchakato mwingine
- `shell`: Inaendesha amri ya shell katika muktadha wa wakala, sawa na kuendesha amri katika cmd.exe

### Harakati za Lateral

- `jump_psexec`: Inatumia mbinu ya PsExec kuhamia kwa upande mwingine kwa kuanza kwa kunakili executable ya wakala wa Apollo (apollo.exe) na kuitekeleza.
- `jump_wmi`: Inatumia mbinu ya WMI kuhamia kwa upande mwingine kwa kuanza kwa kunakili executable ya wakala wa Apollo (apollo.exe) na kuitekeleza.
- `wmiexecute`: Inaendesha amri kwenye mfumo wa ndani au wa mbali ulioainishwa kwa kutumia WMI, ikiwa na akidi za hiari za kuiga.
- `net_dclist`: Inapata orodha ya wakala wa kikoa kwa kikoa kilichoainishwa, muhimu kwa kutambua malengo yanayoweza kuwa kwa harakati za lateral.
- `net_localgroup`: Inataja makundi ya ndani kwenye kompyuta iliyoainishwa, ikirudi kwa localhost ikiwa hakuna kompyuta iliyoainishwa.
- `net_localgroup_member`: Inapata uanachama wa kundi la ndani kwa kundi lililoainishwa kwenye kompyuta ya ndani au ya mbali, ikiruhusu kuhesabu watumiaji katika makundi maalum.
- `net_shares`: Inataja sehemu za mbali na upatikanaji wao kwenye kompyuta iliyoainishwa, muhimu kwa kutambua malengo yanayoweza kuwa kwa harakati za lateral.
- `socks`: Inaruhusu proxy inayokidhi SOCKS 5 kwenye mtandao wa lengo, ikiruhusu kupitisha trafiki kupitia mwenyeji aliyeathirika. Inafaa na zana kama proxychains.
- `rpfwd`: Inaanza kusikiliza kwenye bandari iliyoainishwa kwenye mwenyeji wa lengo na inasambaza trafiki kupitia Mythic hadi IP na bandari ya mbali, ikiruhusu ufikiaji wa mbali kwa huduma kwenye mtandao wa lengo.
- `listpipes`: Inataja mabomba yote yaliyo na majina kwenye mfumo wa ndani, ambayo yanaweza kuwa muhimu kwa harakati za lateral au kupandisha hadhi kwa kuingiliana na mitambo ya IPC.

### Amri Mbalimbali
- `help`: Inaonyesha taarifa za kina kuhusu amri maalum au taarifa za jumla kuhusu amri zote zinazopatikana katika wakala.
- `clear`: Inaashiria kazi kama 'zilizofutwa' ili zisiweze kuchukuliwa na wakala. Unaweza kuainisha `all` kufuta kazi zote au `task Num` kufuta kazi maalum.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon ni wakala wa Golang unaokusanywa kuwa **Linux na macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
### Hatua za kawaida

- `cat`: Chapisha maudhui ya faili
- `cd`: Badilisha directory ya kazi ya sasa
- `chmod`: Badilisha ruhusa za faili
- `config`: Angalia config ya sasa na taarifa za mwenyeji
- `cp`: Nakili faili kutoka eneo moja hadi lingine
- `curl`: Tekeleza ombi moja la wavuti na vichwa na mbinu za hiari
- `upload`: Pandisha faili kwenye lengo
- `download`: Pakua faili kutoka mfumo wa lengo hadi mashine ya ndani
- Na mengi zaidi

### Tafuta Taarifa Nyeti

- `triagedirectory`: Pata faili za kuvutia ndani ya directory kwenye mwenyeji, kama faili nyeti au akidi.
- `getenv`: Pata mabadiliko yote ya mazingira ya sasa.

### Hamia kwa upande

- `ssh`: SSH kwa mwenyeji ukitumia akidi zilizotengwa na fungua PTY bila kuzalisha ssh.
- `sshauth`: SSH kwa mwenyeji/mwenyeji waliotajwa ukitumia akidi zilizotengwa. Unaweza pia kutumia hii kutekeleza amri maalum kwenye wenyeji wa mbali kupitia SSH au kuitumia SCP faili.
- `link_tcp`: Unganisha na wakala mwingine kupitia TCP, kuruhusu mawasiliano ya moja kwa moja kati ya wakala.
- `link_webshell`: Unganisha na wakala ukitumia wasifu wa webshell P2P, kuruhusu ufikiaji wa mbali kwenye kiolesura cha wavuti cha wakala.
- `rpfwd`: Anza au Stop Reverse Port Forward, kuruhusu ufikiaji wa mbali kwa huduma kwenye mtandao wa lengo.
- `socks`: Anza au Stop SOCKS5 proxy kwenye mtandao wa lengo, kuruhusu tunneling ya trafiki kupitia mwenyeji aliyeathirika. Inafaa na zana kama proxychains.
- `portscan`: Chunguza mwenyeji/mwenyeji kwa bandari wazi, muhimu kwa kutambua malengo yanayoweza kuwa ya kuhamia au mashambulizi zaidi.

### Utendaji wa mchakato

- `shell`: Tekeleza amri moja ya shell kupitia /bin/sh, kuruhusu utekelezaji wa moja kwa moja wa amri kwenye mfumo wa lengo.
- `run`: Tekeleza amri kutoka diski na hoja, kuruhusu utekelezaji wa binaries au scripts kwenye mfumo wa lengo.
- `pty`: Fungua PTY ya mwingiliano, kuruhusu mwingiliano wa moja kwa moja na shell kwenye mfumo wa lengo.


{{#include ../banners/hacktricks-training.md}}
