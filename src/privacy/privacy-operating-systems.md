# Operating Systems za Faragha

Operating systems zinazolenga faragha hupunguza makosa ya routing na persistence, lakini hakuna inayoweza kufidia tabia inayoweza kukutambulisha au hardware iliyoathirika.

## Chagua modeli ya isolation

| System | Inafaa zaidi kwa | Persistence | Utekelezaji wa mtandao | Tradeoff kuu |
|---|---|---|---|---|
| **Tor Browser kwenye OS inayodumishwa** | Kuvinjari web bila kutambulika mara kwa mara | Hali ya browser kwa kawaida huwekewa mipaka ya session | Traffic ya browser pekee | Apps nyingine na host hubaki nje ya Tor |
| **Tails** | Sessions zinazobebeka, za amnesic, na zenye madhumuni maalum | Persistent Storage ya hiari iliyosimbwa | Internet traffic inalazimishwa kupitia Tor | Usumbufu wa reboot/workflow; uaminifu wa firmware/hardware |
| **Whonix** | Applications zinazoendelea zinazohitaji routing ya lazima kupitia Tor | VMs zinazoendelea | Mgawanyiko wa Gateway/Workstation | Host/hypervisor na kuchanganya identities bado hubaki |
| **Qubes-Whonix** | Mgawanyiko thabiti wa compartments kwa users wa advanced | Kwa kila qube | Network qubes maalum na Whonix | Mahitaji ya hardware na ugumu wa uendeshaji |

## Tails

Tails hu-boot kwa kujitegemea kutoka removable media, huelekeza Internet traffic kupitia Tor, na imeundwa kuacha local state kidogo sana. Warnings zake zenyewe zinasisitiza kwamba haiwezi kulinda dhidi ya BIOS/firmware/hardware iliyoathirika, ufichuzi unaoweza kukutambulisha, file metadata, au observer mwenye uwezo wa ku-correlate ncha zote mbili.<sup>[[1]](#references)</sup>

### Workflow ya Tails yenye madhumuni maalum

1. Download Tails kutoka official site kwenye computer inayoaminika na iliyosasishwa, kisha fuata verification/install process rasmi.
2. Tumia USB drive inayoungwa mkono kwa ku-boot Tails pekee; usiitumie pia kama drive ya jumla ya kuhamisha files.
3. Boot kwenye hardware unayodhibiti kimwili. Live OS haiwezi kuzuia hardware keylogger au firmware hasidi.
4. Acha Persistent Storage ikiwa disabled isipokuwa workflow ihitaji kweli. Ikiwashwa, persist categories zinazohitajika pekee na tumia passphrase imara.
5. Unganisha kwenye network halali. Ikiwa captive portal haiwezi kuepukika, tumia Unsafe Browser ya Tails kwa portal hiyo pekee, usifichue identity isiyohitajika, ifunge mara moja, na uunganishe Tor kabla ya shughuli yoyote nyeti.<sup>[[2]](#references)</sup>
6. Configure Tor bridge ikiwa kuonekana au kuzuiwa kwa Tor moja kwa moja ni jambo muhimu.
7. Fanya **identity/purpose moja ya muktadha kwa kila session**. Tails inapendekeza ku-restart kati ya shughuli ambazo hazipaswi kuunganishwa.<sup>[[1]](#references)</sup>
8. Kagua na usafishe files kabla ya kuzichapisha. Usifungue active documents zilizopakuliwa kwenye application inayoweza kupita nje ya muktadha uliokusudiwa.
9. Shut down kikamilifu ukimaliza na uweke USB katika usalama wa kimwili.

## Whonix

Whonix hutenganisha **Gateway** inayofanya Tor-routing kutoka kwa **Workstation** ambayo applications zake haziwezi kujifunza moja kwa moja external IP. Hii hupunguza kwa kiwango cha maana makosa ya proxy/DNS, lakini host, hypervisor, tabia, na documents bado vinaweza kufichua identity. Whonix inaonya wazi dhidi ya kutumia workstation moja kwa identities nyingi au kuchanganya shughuli anonymous na zisizo anonymous.<sup>[[3]](#references)</sup>

### Workflow ya compartment

1. Verify Whonix image na virtualization platform kutoka official sources.
2. Patch host, hypervisor, Gateway, na Workstation kabla ya matumizi.
3. Clone Workstation mpya kwa kila identity au engagement; usiwahi ku-clone VM baada ya state yenye identity kuingizwa.
4. Weka personal accounts, host shared folders, clipboard synchronization, USB devices, na data ya time/location nje ya Workstation.
5. Tumia snapshots kwa recovery, si kama mbadala wa backups au identity separation.
6. Thibitisha kwamba Workstation haiwezi kufikia Internet wakati Gateway imesimamishwa.
7. Kwa files hatari zaidi, tumia disposable VM/qube na export result iliyosafishwa pekee.

## Qubes OS na Qubes-Whonix

Qubes hutekeleza security kupitia compartmentalization kwa kutumia qubes zinazoendeshwa na Xen. Muundo wake huzuia compromise katika domain moja kufikia nyingine moja kwa moja, lakini applications zilizo ndani ya **qube hiyo hiyo** hazijatenganishwa kutoka kwa nyingine.<sup>[[4]](#references)</sup> Disposable qubes hutoa state mpya kwa sites, files, na devices zisizoaminika.<sup>[[5]](#references)</sup>

Mpangilio wa vitendo:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
- Mpe kila qube kiwango kimoja cha uaminifu na madhumuni ya utambulisho.
- Hifadhi secrets kwenye offline vault qube na utumie shughuli zilizo wazi za kunakili/kusogeza files kati ya qubes.
- Fungua files na links ambazo hukuzitarajia kwenye disposables.
- Pitisha qubes zilizokusudiwa pekee kupitia Whonix au dedicated VPN qube.
- Weka labels tofauti kwenye windows na usitishe qubes zisizohusiana wakati wa kazi nyeti.
- Usidhani kuwa qubes mbili zinazuia correlation ikiwa zinashiriki accounts, content, ratiba, au malipo.

## Verification and maintenance

- Thibitisha signatures/checksums za installer kupitia instructions rasmi.
- Fanya patch kwenye templates kwanza, kisha restart qubes/VMs zinazoitegemea.
- Thibitisha tabia ya network-deny, DNS, IPv6, clock, clipboard, shared directories, na USB assignment.
- Kagua Persistent Storage na VM snapshots kwa data ya zamani yenye utambulisho.
- Hifadhi backups zilizosimbwa za seeds/keys nje ya mtandao na ujaribu restoration katika mazingira yaliyotengwa.
- Jenga upya compartment baada ya kushukiwa kwa compromise; kubadilisha egress IP yake hakutoshi.

## References

- [1] [Tails — Warnings: Tails ni salama lakini si uchawi](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Kuingia kwenye network kwa kutumia captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix na limitations za Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Malengo ya muundo wa usalama](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Jinsi ya kutumia disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
