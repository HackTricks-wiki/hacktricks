# Mifumo ya Uendeshaji Inayolenga Faragha

{{#include ../banners/hacktricks-training.md}}

Mifumo ya uendeshaji inayolenga faragha hupunguza makosa ya routing na persistence, lakini hakuna mfumo unaoweza kufidia tabia inayoweza kutambulisha utambulisho au hardware iliyoathirika.

## Chagua muundo wa isolation

| Mfumo | Unaofaa zaidi | Persistence | Utekelezaji wa mtandao | Hasara kuu |
|---|---|---|---|---|
| **Tor Browser kwenye OS inayotunzwa** | Kuvinjari wavuti bila kutambulika mara chache | Hali ya browser kwa kawaida huwa ya session | Traffic ya browser pekee | Apps zingine na host hubaki nje ya Tor |
| **Tails** | Sessions zinazobebeka, zisizohifadhi kumbukumbu, na zenye kusudi moja | Persistent Storage ya hiari yenye encryption | Traffic ya Internet hulazimishwa kupitia Tor | Reboots na usumbufu wa workflow; uaminifu wa firmware/hardware |
| **Whonix** | Applications zinazoendelea kutumika na zinazohitaji routing ya lazima kupitia Tor | VMs zinazoendelea kuhifadhi hali | Mgawanyiko wa Gateway/Workstation | Host/hypervisor na kuchanganya identities bado hubaki |
| **Qubes-Whonix** | Mgawanyiko imara wa compartments kwa users wa advanced | Kwa kila qube | Qubes maalum za network na Whonix | Mahitaji ya hardware na ugumu wa uendeshaji |

## Tails

Tails huwasha mfumo kwa kujitegemea kutoka removable media, hupitisha traffic ya Internet kupitia Tor, na imeundwa kuacha state ndogo ya local. Warnings zake zinaeleza kuwa haiwezi kulinda dhidi ya BIOS/firmware/hardware iliyoathirika, disclosures zinazotambulisha utambulisho, metadata ya files, au observer mwenye uwezo wa ku-correlate pande zote mbili.<sup>[[1]](#references)</sup>

### Workflow ya Tails yenye kusudi moja

1. Pakua Tails kutoka kwenye site rasmi ukitumia computer inayoaminika na iliyosasishwa, kisha fuata mchakato rasmi wa verification/install.
2. Tumia USB drive inayoungwa mkono kwa kuwasha Tails pekee; usiitumie pia kama drive ya jumla ya kuhamisha files.
3. Washa mfumo kwenye hardware unayoidhibiti kimwili. Live OS haiwezi kuondoa hardware keylogger au firmware hasidi.
4. Acha Persistent Storage ikiwa imezimwa isipokuwa workflow inaihitaji kweli. Ikiwezeshwa, hifadhi categories zinazohitajika pekee na utumie passphrase imara.
5. Unganisha kwenye network halali. Ikiwa captive portal haiwezi kuepukwa, tumia Tails' Unsafe Browser kwa portal hiyo pekee, usifichue identity isiyohitajika, ifunge mara moja, na uunganishe Tor kabla ya shughuli yoyote nyeti.<sup>[[2]](#references)</sup>
6. Configure Tor bridge ikiwa mwonekano wa moja kwa moja wa Tor au blocking ni muhimu.
7. Fanya **identity/purpose moja ya kimuktadha kwa kila session**. Tails inapendekeza ku-restart kati ya shughuli ambazo hazipaswi kuhusishwa.<sup>[[1]](#references)</sup>
8. Kagua na usafishe files kabla ya kuzichapisha. Usifungue documents active ulizopakua kwenye application inayoweza kukwepa context iliyokusudiwa.
9. Zima mfumo kikamilifu ukimaliza na uiweke USB ikiwa salama kimwili.

## Whonix

Whonix hutenganisha **Gateway** inayopitisha traffic kupitia Tor kutoka kwa **Workstation** ambayo applications zake haziwezi kujifunza moja kwa moja IP ya nje. Hii hupunguza kwa kiasi kikubwa makosa ya proxy/DNS, lakini host, hypervisor, tabia, na documents bado vinaweza kufichua identity. Whonix inaonya wazi dhidi ya kutumia workstation moja kwa identities nyingi au kuchanganya shughuli anonymous na zisizo anonymous.<sup>[[3]](#references)</sup>

### Workflow ya compartment

1. Thibitisha image ya Whonix na virtualization platform kutoka kwenye sources rasmi.
2. Fanya patch kwenye host, hypervisor, Gateway, na Workstation kabla ya matumizi.
3. Clone Workstation mpya kwa kila identity au engagement; usiwahi ku-clone VM baada ya state yenye taarifa za identity kuingizwa.
4. Weka personal accounts, host shared folders, clipboard synchronization, USB devices, na data ya muda/location nje ya Workstation.
5. Tumia snapshots kwa recovery, si kama mbadala wa backups au kutenganisha identities.
6. Thibitisha kuwa Workstation haiwezi kufikia Internet Gateway ikiwa imesimamishwa.
7. Kwa files zilizo hatarini sana, tumia disposable VM/qube na export result iliyosafishwa pekee.

## Qubes OS na Qubes-Whonix

Qubes hutekeleza security kupitia compartmentalization kwa kutumia qubes zinazotegemea Xen. Muundo wake huzuia compromise katika domain moja kufikia domains zingine moja kwa moja, lakini applications zilizo ndani ya **qube hiyo hiyo** hazijatenganishwa kutoka kwa kila mmoja.<sup>[[4]](#references)</sup> Disposable qubes hutoa state mpya kwa sites, files, na devices zisizoaminika.<sup>[[5]](#references)</sup>

Muundo wa vitendo:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Rules:

- Ipe kila qube kiwango kimoja cha uaminifu na madhumuni ya utambulisho.
- Hifadhi siri katika vault qube ya offline na utumie operations za wazi za kunakili/kusogeza files kati ya qubes.
- Fungua files na links zisizoombwa katika disposables.
- Pitisha qubes zilizokusudiwa pekee kupitia Whonix au qube maalumu ya VPN.
- Weka labels za windows kwa utofauti na usimamishe qubes zisizohusiana wakati wa kazi nyeti.
- Usidhani kuwa qubes mbili zinazuia correlation ikiwa zinashiriki accounts, maudhui, ratiba au malipo.

## Verification and maintenance

- Thibitisha signatures/checksums za installer kupitia instructions rasmi.
- Patch templates kwanza, kisha restart qubes/VMs zinazozitegemea.
- Thibitisha tabia ya network-deny, DNS, IPv6, saa, clipboard, shared directories na mgawo wa USB.
- Kagua Persistent Storage na VM snapshots kwa data ya zamani inayohusishwa na utambulisho.
- Hifadhi backups zilizosimbwa za seeds/keys offline na ujaribu restoration katika mazingira yaliyotengwa.
- Unda upya compartment baada ya kushukiwa kwa compromise; kubadilisha egress IP yake hakutoshi.

## References

- [1] [Tails — Maonyo: Tails ni salama lakini si uchawi](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Kuingia kwenye network kwa kutumia captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Vikwazo vya Whonix na Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Malengo ya muundo wa usalama](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Jinsi ya kutumia disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
