# Kukamata Trafiki, Firewall, na Uchunguzi wa Egress

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata [wasikilizaji wa ndani na soketi za Unix](local-network-and-socket-triage.md), kagua ni violesura vipi vinavyobeba trafiki yao na ni sheria zipi za firewall au proxy zinazoathiri ufikikaji. Huduma inayopatikana kupitia loopback pekee inaweza kubeba vichwa nyeti vya HTTP hata kama haipatikani kutoka kwa mashine nyingine.

## Kagua ruhusa za kunasa trafiki na uchague kiolesura

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` inaweza kuwa na uwezo wa kunasa pakiti hata kama mtumiaji wa sasa hana ufikiaji wa sudo. Kagua uwezo halisi wa faili inayotekelezeka na ruhusa za kikundi. Nasa kiolesura, muda na kichujio kidogo zaidi kinachofaa; data iliyonaswa inaweza kuwa na vitambulisho vya kuingia au taarifa binafsi.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` huunda upya mitiririko ya TCP yenye maandishi wazi; `tshark` inaweza kuchuja na kutoa sehemu mahususi kutoka kwenye capture. Kwa traffic ya TLS, kuisimbua kunahitaji funguo za endpoint au client inayotumika, iliyosanidiwa kutumia `SSLKEYLOGFILE` kabla ya muunganisho. [Ukurasa wa uchunguzi wa awali wa mtandao wa ndani](local-network-and-socket-triage.md#tls-key-logging) unaonyesha utaratibu huo. Usichukulie capture iliyosimbwa kuwa maandishi wazi yanayosomeka.

Artifacts za tukio zilizohifadhiwa zinaweza kubadilisha tathmini hiyo. [Core dump ya Linux ni taswira ya kumbukumbu ya mchakato](https://man7.org/linux/man-pages/man5/core.5.html), ambayo inaweza kuhifadhi session key; ikiwa dump inayosomeka na packet capture zilitokana na mchakato na session ileile, mchambuzi anaweza kuweza kusimbua traffic hiyo. Kwanza orodhesha njia za artifacts na ruhusa zake, kisha uthibitishe kando utambulisho wa mchakato, muda wa capture, protocol na umbizo la key. Traffic iliyosimbuliwa au archive iliyorejeshwa ni kidokezo cha ufichuzi, si uthibitisho wa ufikiaji wa akaunti nyingine: nyenzo yoyote ya sehemu ya SSH key bado inahitaji kuundwa upya, kulinganishwa na public key inayolingana, na kukubaliwa na sera ya SSH ya akaunti hiyo. Epuka kuonyesha maudhui ya core au payload za capture katika matokeo mapana ya kuorodhesha.

## Tambua tabaka za firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` na `iptables` zinaweza kupatikana kupitia wrapper za distro kama UFW au firewalld. Soma sheria zinazotumika na usanidi uliohifadhiwa wa wrapper; sheria inayoonekana katika uwakilishi mmoja huenda ilitengenezwa na zana nyingine. Kagua kiolesura, mwelekeo, chanzo, lengwa, itifaki, porti na hali ya muunganisho kabla ya kuhusisha huduma iliyozuiwa na sheria fulani. Tazama [ukaguzi wa sheria za nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) kwa mfano maalum.

## Pima trafiki ya kutoka na tabia ya proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Tenganisha hitilafu za DNS na hitilafu za TCP, TLS au proxy. Jaribu lengwa na itifaki mahususi inayohusika na tathmini; kufikika kupitia ICMP hakumaanishi kuwa TCP au UDP zimeruhusiwa. Ikiwa proxy imesanidiwa, linganisha ombi lililokusudiwa kupitia proxy na ombi kwa lengwa hilo hilo kwa kutumia sheria zinazotumika za `no_proxy`. Port forward ya ndani pia inaweza kufanya huduma ya loopback ipatikane kwingineko, kwa hiyo kagua wasikilizaji amilifu na SSH tunnels wakati mwonekano wa firewall na ufichuzi ulioonekana havilingani.
{{#include ../../banners/hacktricks-training.md}}
