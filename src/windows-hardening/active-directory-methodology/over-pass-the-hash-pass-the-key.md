# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

The **Overpass The Hash/Pass The Key (PTK)** attack is designed for environments where the traditional NTLM protocol is restricted, and Kerberos authentication takes precedence. This attack leverages the NTLM hash or AES keys of a user to solicit Kerberos tickets, enabling unauthorized access to resources within a network.

To execute this attack, the initial step involves acquiring the NTLM hash or password of the targeted user's account. Upon securing this information, a Ticket Granting Ticket (TGT) for the account can be obtained, allowing the attacker to access services or machines to which the user has permissions.

The process can be initiated with the following commands:

```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```

For scenarios necessitating AES256, the `-aesKey [AES key]` option can be utilized. Moreover, the acquired ticket might be employed with various tools, including smbexec.py or wmiexec.py, broadening the scope of the attack.

Encountered issues such as _PyAsn1Error_ or _KDC cannot find the name_ are typically resolved by updating the Impacket library or using the hostname instead of the IP address, ensuring compatibility with the Kerberos KDC.

An alternative command sequence using Rubeus.exe demonstrates another facet of this technique:

```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```

This method mirrors the **Pass the Key** approach, with a focus on commandeering and utilizing the ticket directly for authentication purposes. It's crucial to note that the initiation of a TGT request triggers event `4768: A Kerberos authentication ticket (TGT) was requested`, signifying an RC4-HMAC usage by default, though modern Windows systems prefer AES256.

To conform to operational security and use AES256, the following command can be applied:

```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```

## Stealthier version

> [!WARNING]
> Each logon session can only have one active TGT at a time so be careful.

1. Create a new logon sesison with **`make_token`** from Cobalt Strike.
2. Then, use Rubeus to generate a TGT for the new logon session without affecting the existing one.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)


{{#include ../../banners/hacktricks-training.md}}



