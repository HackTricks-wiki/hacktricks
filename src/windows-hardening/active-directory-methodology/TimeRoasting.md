## TimeRoasting

timeRoasting, la causa principale è il meccanismo di autenticazione obsoleto lasciato da Microsoft nella sua estensione ai server NTP, noto come MS-SNTP. In questo meccanismo, i client possono utilizzare direttamente l'Identificatore Relativo (RID) di qualsiasi account computer, e il controller di dominio utilizzerà l'hash NTLM dell'account computer (generato da MD4) come chiave per generare il **Message Authentication Code (MAC)** del pacchetto di risposta.

Gli attaccanti possono sfruttare questo meccanismo per ottenere valori hash equivalenti di account computer arbitrari senza autenticazione. Chiaramente, possiamo utilizzare strumenti come Hashcat per il brute-forcing.

Il meccanismo specifico può essere visualizzato nella sezione 3.1.5.1 "Comportamento della Richiesta di Autenticazione" della [documentazione ufficiale di Windows per il protocollo MS-SNTP](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf).

Nel documento, la sezione 3.1.5.1 tratta del Comportamento della Richiesta di Autenticazione.
![](../../images/Pasted%20image%2020250709114508.png)
Si può vedere che quando l'elemento ADM ExtendedAuthenticatorSupported è impostato su `false`, il formato Markdown originale viene mantenuto.

>Citato nell'articolo originale：
>>Se l'elemento ADM ExtendedAuthenticatorSupported è falso, il client DEVE costruire un messaggio di Richiesta NTP Client. La lunghezza del messaggio di Richiesta NTP Client è di 68 byte. Il client imposta il campo Authenticator del messaggio di Richiesta NTP Client come descritto nella sezione 2.2.1, scrivendo i 31 bit meno significativi del valore RID nei 31 bit meno significativi del sotto-campo Key Identifier dell'autenticatore, e poi scrivendo il valore Key Selector nel bit più significativo del sotto-campo Key Identifier.

Nella sezione 4 Esempi di Protocollo punto 3

>Citato nell'articolo originale：
>>3. Dopo aver ricevuto la richiesta, il server verifica che la dimensione del messaggio ricevuto sia di 68 byte. Se non lo è, il server scarta la richiesta (se la dimensione del messaggio non è uguale a 48 byte) o la tratta come una richiesta non autenticata (se la dimensione del messaggio è di 48 byte). Supponendo che la dimensione del messaggio ricevuto sia di 68 byte, il server estrae il RID dal messaggio ricevuto. Il server lo utilizza per chiamare il metodo NetrLogonComputeServerDigest (come specificato nella sezione [MS-NRPC] 3.5.4.8.2) per calcolare i checksum crittografici e selezionare il checksum crittografico basato sul bit più significativo del sotto-campo Key Identifier dal messaggio ricevuto, come specificato nella sezione 3.2.5. Il server quindi invia una risposta al client, impostando il campo Key Identifier su 0 e il campo Crypto-Checksum sul checksum crittografico calcolato.

Secondo la descrizione nel documento ufficiale Microsoft sopra, gli utenti non hanno bisogno di alcuna autenticazione; devono solo compilare il RID per avviare una richiesta, e poi possono ottenere il checksum crittografico. Il checksum crittografico è spiegato nella sezione 3.2.5.1.1 del documento.

>Citato nell'articolo originale：
>>Il server recupera il RID dai 31 bit meno significativi del sotto-campo Key Identifier del campo Authenticator del messaggio di Richiesta NTP Client. Il server utilizza il metodo NetrLogonComputeServerDigest (come specificato nella sezione [MS-NRPC] 3.5.4.8.2) per calcolare i checksum crittografici con i seguenti parametri di input:
>>>![](../../images/Pasted%20image%2020250709115757.png)

Il checksum crittografico è calcolato utilizzando MD5, e il processo specifico può essere consultato nel contenuto del documento. Questo ci offre l'opportunità di eseguire un attacco di roasting.

## come attaccare

Citato in https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Script di Timeroasting di Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```

