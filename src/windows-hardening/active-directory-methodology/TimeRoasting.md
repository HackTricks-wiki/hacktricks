# TimeRoasting

{{#include /banners/hacktricks-training.md}}

timeRoasting, la principale cause est le mécanisme d'authentification obsolète laissé par Microsoft dans son extension aux serveurs NTP, connu sous le nom de MS-SNTP. Dans ce mécanisme, les clients peuvent utiliser directement l'Identifiant Relatif (RID) de n'importe quel compte d'ordinateur, et le contrôleur de domaine utilisera le hachage NTLM du compte d'ordinateur (généré par MD4) comme clé pour générer le **Message Authentication Code (MAC)** du paquet de réponse.

Les attaquants peuvent exploiter ce mécanisme pour obtenir des valeurs de hachage équivalentes de comptes d'ordinateur arbitraires sans authentification. Clairement, nous pouvons utiliser des outils comme Hashcat pour le brute-forcing.

Le mécanisme spécifique peut être consulté dans la section 3.1.5.1 "Comportement de la demande d'authentification" de la [documentation officielle de Windows pour le protocole MS-SNTP](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf).

Dans le document, la section 3.1.5.1 couvre le comportement de la demande d'authentification.
![](../../images/Pasted%20image%2020250709114508.png)
On peut voir que lorsque l'élément ADM ExtendedAuthenticatorSupported est défini sur `false`, le format Markdown d'origine est conservé.

> Cité dans l'article original :
>> Si l'élément ADM ExtendedAuthenticatorSupported est faux, le client DOIT construire un message de demande NTP Client. La longueur du message de demande NTP Client est de 68 octets. Le client définit le champ Authenticator du message de demande NTP Client comme décrit dans la section 2.2.1, en écrivant les 31 bits les moins significatifs de la valeur RID dans les 31 bits les moins significatifs du sous-champ Key Identifier de l'authentificateur, puis en écrivant la valeur Key Selector dans le bit le plus significatif du sous-champ Key Identifier.

Dans la section 4 Exemples de protocole point 3

> Cité dans l'article original :
>> 3. Après avoir reçu la demande, le serveur vérifie que la taille du message reçu est de 68 octets. Si ce n'est pas le cas, le serveur soit rejette la demande (si la taille du message n'est pas égale à 48 octets) soit la traite comme une demande non authentifiée (si la taille du message est de 48 octets). En supposant que la taille du message reçu est de 68 octets, le serveur extrait le RID du message reçu. Le serveur l'utilise pour appeler la méthode NetrLogonComputeServerDigest (comme spécifié dans la section 3.5.4.8.2 de [MS-NRPC]) pour calculer les crypto-checksums et sélectionner le crypto-checksum basé sur le bit le plus significatif du sous-champ Key Identifier du message reçu, comme spécifié dans la section 3.2.5. Le serveur envoie ensuite une réponse au client, en définissant le champ Key Identifier à 0 et le champ Crypto-Checksum au crypto-checksum calculé.

Selon la description dans le document officiel de Microsoft ci-dessus, les utilisateurs n'ont besoin d'aucune authentification ; ils doivent simplement remplir le RID pour initier une demande, puis ils peuvent obtenir le checksum cryptographique. Le checksum cryptographique est expliqué dans la section 3.2.5.1.1 du document.

> Cité dans l'article original :
>> Le serveur récupère le RID des 31 bits les moins significatifs du sous-champ Key Identifier du champ Authenticator du message de demande NTP Client. Le serveur utilise la méthode NetrLogonComputeServerDigest (comme spécifié dans la section 3.5.4.8.2 de [MS-NRPC]) pour calculer les crypto-checksums avec les paramètres d'entrée suivants :
>>>![](../../images/Pasted%20image%2020250709115757.png)

Le checksum cryptographique est calculé en utilisant MD5, et le processus spécifique peut être consulté dans le contenu du document. Cela nous donne l'opportunité d'effectuer une attaque de roasting.

## comment attaquer

Citation à https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts de Timeroasting par Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
{{#include /banners/hacktricks-training.md}}
