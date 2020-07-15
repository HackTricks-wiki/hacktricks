# WireShark tricks

## Decrypting TLS

### Decrypting https traffic with server private key

_edit&gt;preference&gt;protocol&gt;ssl&gt;_

![](../../.gitbook/assets/image%20%28263%29.png)

Press _Edit_ and add all the data of the server and the private key \(_IP, Port, Protocol, Key file and password_\)

### Decrypting https traffic with symmetric session keys

It turns out that Firefox and Chrome both support logging the symmetric session key used to encrypt TLS traffic to a file. You can then point Wireshark at said file and presto! decrypted TLS traffic. More in: [https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)  
To detect this search inside the environment for to variable `SSLKEYLOGFILE`

A file of shared keys will looks like this:

![](../../.gitbook/assets/image%20%2862%29.png)

To import this in wireshark go to _edit&gt;preference&gt;protocol&gt;ssl&gt;_ and import it in \(Pre\)-Master-Secret log filename:

![](../../.gitbook/assets/image%20%28191%29.png)



