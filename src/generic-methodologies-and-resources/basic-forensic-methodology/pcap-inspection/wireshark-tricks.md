# Njia za Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Boresha ujuzi wako wa Wireshark

### Mafunzo

Mafunzo yafuatayo ni mazuri kujifunza mbinu za msingi:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Taarifa zilizochambuliwa

**Taarifa za Wataalamu**

Kubofya kwenye _**Analyze** --> **Expert Information**_ utapata **muonekano** wa kile kinachotokea katika pakiti **zilizochambuliwa**:

![](<../../../images/image (256).png>)

**Anwani zilizotatuliwa**

Chini ya _**Statistics --> Resolved Addresses**_ unaweza kupata **taarifa** kadhaa ambazo zilitatuliwa na wireshark kama port/transport hadi protokali, MAC hadi mtengenezaji, n.k. Ni muhimu kujua kinachohusika katika mawasiliano.

![](<../../../images/image (893).png>)

**Hali ya Protokali**

Chini ya _**Statistics --> Protocol Hierarchy**_ unaweza kupata **protokali** **zilizohusika** katika mawasiliano na data kuhusu hizo.

![](<../../../images/image (586).png>)

**Mazungumzo**

Chini ya _**Statistics --> Conversations**_ unaweza kupata **muhtasari wa mazungumzo** katika mawasiliano na data kuhusu hizo.

![](<../../../images/image (453).png>)

**Mikondo**

Chini ya _**Statistics --> Endpoints**_ unaweza kupata **muhtasari wa mikondo** katika mawasiliano na data kuhusu kila mmoja wao.

![](<../../../images/image (896).png>)

**Taarifa za DNS**

Chini ya _**Statistics --> DNS**_ unaweza kupata takwimu kuhusu ombi la DNS lililotolewa.

![](<../../../images/image (1063).png>)

**Grafu ya I/O**

Chini ya _**Statistics --> I/O Graph**_ unaweza kupata **grafu ya mawasiliano.**

![](<../../../images/image (992).png>)

### Filters

Hapa unaweza kupata chujio za wireshark kulingana na protokali: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Chujio nyingine za kuvutia:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- Trafiki ya HTTP na HTTPS ya awali
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Trafiki ya HTTP na HTTPS ya awali + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Trafiki ya HTTP na HTTPS ya awali + TCP SYN + maombi ya DNS

### Tafuta

Ikiwa unataka **kutafuta** **maudhui** ndani ya **pakiti** za vikao bonyeza _CTRL+f_. Unaweza kuongeza tabaka mpya kwenye bar ya taarifa kuu (No., Wakati, Chanzo, n.k.) kwa kubonyeza kitufe cha kulia na kisha kuhariri safu.

### Maabara za bure za pcap

**Fanya mazoezi na changamoto za bure za:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Kutambua Domains

Unaweza kuongeza safu inayonyesha kichwa cha HTTP cha Host:

![](<../../../images/image (639).png>)

Na safu inayoongeza jina la Server kutoka kwa muunganisho wa HTTPS unaoanzisha (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Kutambua majina ya mwenyeji wa ndani

### Kutoka DHCP

Katika Wireshark ya sasa badala ya `bootp` unahitaji kutafuta `DHCP`

![](<../../../images/image (1013).png>)

### Kutoka NBNS

![](<../../../images/image (1003).png>)

## Kufichua TLS

### Kufichua trafiki ya https kwa kutumia funguo za kibinafsi za seva

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

Bonyeza _Edit_ na ongeza data zote za seva na funguo za kibinafsi (_IP, Port, Protokali, Faili ya funguo na nenosiri_)

### Kufichua trafiki ya https kwa kutumia funguo za kikao za symmetrick

Firefox na Chrome zina uwezo wa kurekodi funguo za kikao za TLS, ambazo zinaweza kutumika na Wireshark kufichua trafiki ya TLS. Hii inaruhusu uchambuzi wa kina wa mawasiliano salama. Maelezo zaidi juu ya jinsi ya kufanya ufichuzi huu yanaweza kupatikana katika mwongozo kwenye [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Ili kugundua hii tafuta ndani ya mazingira kwa variable `SSLKEYLOGFILE`

Faili ya funguo za pamoja itakuwa na muonekano huu:

![](<../../../images/image (820).png>)

Ili kuingiza hii katika wireshark nenda kwa \_edit > preference > protocol > ssl > na uingize katika (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## Mawasiliano ya ADB

Toa APK kutoka kwa mawasiliano ya ADB ambapo APK ilitumwa:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
{{#include ../../../banners/hacktricks-training.md}}
