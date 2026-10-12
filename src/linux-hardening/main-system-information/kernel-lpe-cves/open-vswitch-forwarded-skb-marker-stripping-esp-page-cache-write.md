# Open vSwitch: stroop merker van aangestuurde skb vir ESP-skrywe na page-cache

{{#include ../../../banners/hacktricks-training.md}}

’n Nuttige Linux-kern-uitbuitingspatroon is om **eienaarskapmetadata van ’n skb te stroop sonder om die vreemde fragmente daarvan te verwyder**, en dan daardie skb aan ’n verbruiker te stuur wat direk daarop skryf. In die Open vSwitch (OVS)-geval verwyder ’n mislukte userspace-upcall `SKBFL_SHARED_FRAG` van ’n steeds lewende `MSG_ZEROCOPY`-skb; ESP dekripteer daarna direk oor ’n page-cache-folio van ’n leesalleen-lêer. Dit maak ’n deterministiese plaaslike skrywe na die page-cache moontlik en is opgespoor as CVE-2026-90049, CVE-2026-89487 en CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Dit is ’n probleem in die Copy Fail/Dirty Frag-klas, eerder as klassieke geheuekorrupsie: geen race of adreslekkasie word vereis nie, die lêer hoef slegs leesbaar te wees, en die veranderde grepe bestaan in die page-cache, nie op skyf nie.<sup>[[2]](#references)[[3]](#references)</sup>

## Sekuriteitsinvariant: vreemde fragmente moet gemerk bly

`SKBFL_SHARED_FRAG` dui aan in-place-verbruikers dat ’n skb-fragment kan verwys na stoorspasie wat hulle nie privaat besit nie. Die ESP-fast path in `esp_input()` mag ’n nie-lineêre, ongeklone skb in-place dekripteer slegs wanneer `skb_has_shared_frag()` vals is; anders skep `skb_cow_data()` eers privaat stoorspasie. Hierdie kontrole aan die verbruikerskant is ná Dirty Frag bygevoeg.<sup>[[5]](#references)</sup>

Die invariant het dus twee onafhanklike dele:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. In-place-skrywers moet `SKBFL_SHARED_FRAG` nagaan en gedeelde data kopieer voordat hulle dit verander.
2. Elke kloon-, saamsmelt-, oordrag- of aanstuurpad moet die merker behou solank die vreemde bladsy aangeheg bly.

Fragnesia het die tweede reël oortree toe dit fragmentbeskrywers in `skb_try_coalesce()` verskuif het. Die OVS-pad verskil subtiel: dit dra glad nie die fragment oor nie; dit vee die merker **in-place op die oorspronklike skb uit en stuur dit dan verder aan**.<sup>[[2]](#references)[[4]](#references)</sup>

## OVS-bereikbaarheid sonder voorregte

OVS se kern-datapad word beheer deur generic-netlink-families soos `ovs_datapath`, `ovs_vport`, `ovs_flow` en `ovs_packet`. Die wysigingsbewerkings daarvan gebruik naamruimte-bewuste `GENL_UNS_ADMIN_PERM`, dus verkry ’n proses wat onder `unshare -Urn` loop die `CAP_NET_ADMIN` wat nodig is om ’n datapad te skep, ’n veth te koppel en flow-aksies binne sy eie netwerknaamruimte te installeer. Die oplos van die OVS-familie kan ook `openvswitch.ko` outomaties laai; host `CAP_SYS_MODULE`, `ovs-vsctl` en `ovs-vswitchd` word nie vir hierdie aanvalsoppervlak vereis nie.<sup>[[2]](#references)[[7]](#references)</sup>

Die belangrike onderskeid is tussen twee soorte upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- ’n **flow miss** stuur die pakkie na `ovs-vswitchd`; as die upcall misluk, word die pakkie gewoonlik weggegooi.
- ’n Eksplisiete `OVS_ACTION_ATTR_USERSPACE`-aksie stuur ’n geleende kopie na ’n gekose poort-ID, en voer dan latere aksies op die oorspronklike skb uit.

’n Aanvaller kan dus ’n flow installeer met die volgende vorm:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Geen listener besit die gekose port ID nie, wat die userspace action voorspelbaar laat misluk, terwyl die daaropvolgende `OUTPUT`-aksie die oorspronklike packet aan die lewe hou.<sup>[[1]](#references)[[2]](#references)</sup>

## Grondoorsaak: `skb_tx_error()` op ’n packet wat oorleef

Die kwesbare OVS-upcall-foutpad roep `skb_tx_error(skb)` aan. Dié helper is ontwerp vir ’n mislukte versending waarna die skb bevry word; dit voltooi zerocopy-boekhouding deur middel van `skb_zcopy_clear()`, waarvan die vlagmasker histories ook `SKBFL_SHARED_FRAG` verwyder het. OVS het die userspace-action-fout geïgnoreer en die aksielys verder uitgevoer, wat die helper se lewensduurkontrak verbreek het.<sup>[[1]](#references)[[2]](#references)</sup>

Die uitbuitbare toestandsoorgang is:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Dit werk slegs wanneer `skb_zcopy()` zerocopy-toestand vind. ’n Fragment wat net `SKBFL_SHARED_FRAG` dra, is onvoldoende; `MSG_ZEROCOPY` is nuttig omdat dit `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` skep en ook `SKBFL_DONT_ORPHAN` stel. Laasgenoemde veroorsaak dat `skb_orphan_frags()` die vervanging van die vreemde bladsye tydens die OVS-userspace-kopie oorslaan.<sup>[[2]](#references)[[3]](#references)</sup>

## Bou van die write primitive

Die end-tot-end-sneller het die volgende komponente.<sup>[[2]](#references)[[3]](#references)</sup>

1. Betree private gebruikers- en netwerknaamruimtes met `unshare -Urn`.
2. Karteer ’n leesbare teikenlêer met `PROT_READ | MAP_SHARED`.
3. Gebruik ’n afsonderlike sender-netns en ’n veth-paar; plaaslike loopback sou die geleende bladsye kopieer en die primitive vernietig.
4. Bou ’n OVS-datapath en die foutiewe `USERSPACE`-dan-`OUTPUT`-flow.
5. Installeer ’n transport-mode ESP-in-UDP XFRM-toestand met `rfc4106(gcm(aes))` en UDP-poort 4500.
6. Stuur een `MSG_ZEROCOPY`-datagram met ’n iovec wat soos volg gevorm is: `[ESP header | mapped file bytes | invalid ICV]`.

Die XFRM-toestand gebruik 20 grepe AES-128-GCM-sleutelmateriaal: 16 grepe AES-sleutel gevolg deur die vier-greep RFC 4106-sout. Vir ’n gekose agt-greep eksplisiete IV begin payload-vertroulikheid met die tellerblok `salt || IV || be32(2)`; tellerwaarde 1 masker eerder die verifikasieresultaat.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Sodra OVS die marker verwyder, gebruik ESP sy no-copy-pad en voer `plaintext = ciphertext XOR keystream` uit oor die lêergebaseerde fragment. Verifikasie word **ná** hierdie transformasie nagegaan, so ’n ongeldige ICV wat uit alle nulle bestaan, laat die pakkie met `-EBADMSG` misluk eers nadat die page-cache-grepe reeds verander het.<sup>[[2]](#references)</sup>

### GCM omskakel na gekose grepe

Vir die huidige greep `C` en gewenste greep `P` moet die eerste keystream-greep `C XOR P` wees. Met die AES-sleutel en salt vasgestel, deursoek ’n 16-bis-agtervoegsel van die eksplisiete IV en bereken vooraf een agtervoegsel vir elke moontlike eerste keystream-greep:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Die publieke implementering beperk ciphertext tot 32 grepe en skuif die lêerfragment een greep vir elke pakkie aan. Die gekose eerste greep oorskryf die vorige pakkie se eerste bykomende greep; `pread()` verfris `C` voor elke pakkie, identiese grepe word oorgeslaan, en die laaste pakkie word verkort sodat skrywe nie verby die aangevraagde reeks gaan nie. ’n Opsoektabel met 256 inskrywings verander die primitief dus in ’n greep-vir-greep page-cache-skrywing met gekose inhoud, teen ongeveer een pakkie per verskillende greep.<sup>[[2]](#references)[[3]](#references)</sup>

## Page-cache-skrywing na root

’n Praktiese teiken is ’n bestaande setuid-root-uitvoerbare lêer. Die PoC vervang die eerste 160 grepe met ’n volledige statiese ELF wat een `PT_LOAD` met ’n vaste adres en lees-/uitvoertoestemming bevat, geen `PT_INTERP` het nie, en kode bevat wat `setuid(0)` aanroep voordat dit `execve("/bin/sh", ...)` uitvoer. Dit vermy aannames oor die oorspronklike binêre lêer se toegangspunt, PIE-uitleg, dinamiese laaier of relokasies.<sup>[[2]](#references)[[3]](#references)</sup>

Die wysiging is sigbaar oor gebruikersnaamruimtes heen omdat die page cache nie naamruimtegebonde is nie. Die gewysigde folio word nie as dirty gemerk nie en word dus nie teruggeskryf nie; voer die teiken uit terwyl dit in die geheue is, en verwerp dan die tydelike korrupsie met `posix_fadvise(..., POSIX_FADV_DONTNEED)` sodat latere leesbewerkings die oorspronklike skyfinhoud herlaai.<sup>[[2]](#references)[[3]](#references)</sup>

## Blootstellingskontroles en versagting

Kontroleer eers die werklike verskafferkern. Relevante voorwaardes vir blootstelling is onbevoorregte gebruikersnaamruimtes, die beskikbaarheid of teenwoordigheid van OVS, en ’n beskikbare ESP-implementering.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Gradeer op na ’n kernel met die volledige herstelreeks; die finale herstel dek die recirculation-pad en vermy dat gedeelde `skb_shinfo()`-toestand verander word, en sluit ook ’n verwante strook in `skb_zerocopy()` af.<sup>[[1]](#references)[[2]](#references)</sup>

As OVS ongebruik word, voorkom alias- én naamgebaseerde laaiing met ’n modprobe `install`-reël eerder as om net op `blacklist` staat te maak. As die gasheer nie IPsec beëindig nie en ESP modulêr is, kan dieselfde beheer die dekripsie-teiken verwyder.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Hierdie reëls help nie wanneer ’n module reeds gelaai is of die funksie in die kernel ingebou is nie. Deur unprivileged user namespaces te deaktiveer, word die namespace-bron van die vermoë ook verwyder, maar dit kan browsers, Flatpak, Podman en ander sandboxing-/container-werkladings breek.<sup>[[2]](#references)</sup>

## Review lessons

Wanneer jy zero-copy-netwerkverkeer oudit, moet jy nie jou soektog beperk tot helpers wat fragmente kopieer of verskuif nie. Identifiseer ook error-/completion-helpers wat gegroepeerde vlae uitvee, en verifieer dan dat elke oproeper die gedokumenteerde skb-lifetime-kontrak nakom. ’n Page-ownership-bit wat saam met zerocopy-lifecycle-bits gegroepeer is, is sekuriteitsensitief, selfs wanneer die skoonmaak-kode nooit direk toegang tot ’n fragment verkry nie.<sup>[[1]](#references)[[2]](#references)</sup>

’n Robuuste oplossing moet alle roetes dek waardeur die skb kan voortbestaan—insluitend action continuation en recirculation—en moet rekening hou met clones wat `skb_shinfo()` deel. Aan die consumer-kant maak authentication failure nie plaintext-skrywings ongedaan wat reeds deur ’n in-place AEAD-transformasie uitgevoer is nie; daarom moet kontroles vir vreemde stoorspasie plaasvind voordat dekripsie begin.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev-regstellingsreeks: net: moenie zerocopy-fragmerkers van ’n aangestuurde skb stroop nie](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Open vSwitch se verwydering van aangestuurde skb-merkers maak deterministiese ESP-page-cache-LPE moontlik](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` proof of concept](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Linux-regstelling vir die oorspronklike Fragnesia-coalescing-pad (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux se ESP-kant se kontrole vir gedeelde fragmente (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Die gebruik van Galois/Counter Mode (GCM) in IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Open vSwitch-kerneldatapad-dokumentasie](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
