# Ukusanyaji wa Trafiki, Firewall, na Tathmini ya Egress

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata [wasikilizaji wa ndani na soketi za Unix](local-network-and-socket-triage.md), kagua ni violesura vipi vinavyobeba trafiki yao na ni sheria zipi za firewall au proxy zinazoathiri ufikikaji. Huduma inayopatikana kupitia loopback pekee inaweza kubeba vichwa vya HTTP nyeti hata kama haiwezi kufikiwa kutoka kwa host nyingine.

## Kagua ruhusa za kunasa trafiki na uchague kiolesura

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` inaweza kuwa na ruhusa za kunasa pakiti hata kama mtumiaji wa sasa hana ufikiaji wa sudo. Angalia uwezo halisi wa faili inayoweza kutekelezwa na ruhusa za kikundi. Nasa kwenye kiolesura, kwa muda na kwa kichujio vinavyotosha tu; data iliyonaswa inaweza kuwa na vitambulisho vya kuingia au taarifa za kibinafsi.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` huunda upya mitiririko ya TCP ya maandishi wazi; `tshark` inaweza kuchuja na kutoa sehemu kutoka kwenye capture. Kwa trafiki ya TLS, kuisimbua kunahitaji funguo za endpoint au client inayotumika iliyosanidiwa kwa `SSLKEYLOGFILE` kabla ya muunganisho. [Ukurasa wa uchunguzi wa mtandao wa ndani](local-network-and-socket-triage.md#tls-key-logging) unaonyesha utaratibu huo. Usichukulie capture iliyosimbwa kuwa maandishi wazi yanayosomeka.

Artifacts za tukio zilizohifadhiwa zinaweza kubadili tathmini hiyo. [Linux core dump ni taswira ya kumbukumbu ya mchakato](https://man7.org/linux/man-pages/man5/core.5.html), ambayo huenda ikahifadhi session key; ikiwa dump inayosomeka na packet capture zilitokana na mchakato na session ileile, mchambuzi anaweza kuweza kusimbua trafiki hiyo. Kwanza orodhesha njia na ruhusa za artifacts, kisha thibitisha kando utambulisho wa mchakato, muda wa capture, protocol, na format ya key. Trafiki iliyosimbuliwa au archive iliyorejeshwa ni kidokezo cha ufichuaji, si uthibitisho wa ufikiaji wa akaunti nyingine: sehemu yoyote ya SSH key iliyopatikana bado inahitaji kujengwa upya, kulinganishwa na public key inayolingana, na kukubaliwa na sera ya SSH ya akaunti hiyo. Epuka kuonyesha maudhui ya core au payload za capture kwenye matokeo mapana ya uorodheshaji.

## Tambua tabaka za firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` na `iptables` zinaweza kufikiwa kupitia wrappers za usambazaji kama UFW au firewalld. Soma sheria zinazotumika na usanidi uliohifadhiwa wa wrapper; sheria inayoonekana katika uwakilishi mmoja huenda ilitengenezwa na zana nyingine. Kagua interface, mwelekeo, chanzo, lengwa, protocol, port na hali ya muunganisho kabla ya kuhusisha huduma iliyozuiwa na sheria fulani. Tazama [ukaguzi wa sheria za nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) kwa mfano maalum.

## Jaribu egress na tabia ya proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Tenganisha hitilafu ya DNS na hitilafu za TCP, TLS au proxy. Jaribu lengwa na itifaki mahususi zinazohusika na tathmini; kufikiwa kupitia ICMP hakumaanishi kwamba TCP au UDP inaruhusiwa. Ikiwa proxy imesanidiwa, linganisha ombi lililokusudiwa kutumia proxy na ombi kwa lengwa hilo hilo chini ya sheria zinazotumika za `no_proxy`. Usambazaji wa port wa ndani unaweza pia kufanya huduma ya loopback ipatikane kutoka sehemu nyingine, kwa hivyo kagua wasikilizaji wanaotumika na SSH tunnels pale mtazamo wa firewall na ufichuaji unaoonekana vinapotofautiana.
{{#include ../../banners/hacktricks-training.md}}
