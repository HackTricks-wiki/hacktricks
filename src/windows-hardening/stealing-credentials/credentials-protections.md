# Protections des identifiants Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Le protocole [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introduit avec Windows XP, est conçu pour l'authentification via le protocole HTTP et est **activé par défaut sur Windows XP jusqu'à Windows 8.0 et sur Windows Server 2003 à Windows Server 2012**. Ce réglage par défaut entraîne le **stockage des mots de passe en clair dans LSASS** (Local Security Authority Subsystem Service). Un attaquant peut utiliser Mimikatz pour **extraire ces identifiants** en exécutant :
```bash
sekurlsa::wdigest
```
Pour **activer ou désactiver cette fonctionnalité**, les clés de registre _**UseLogonCredential**_ et _**Negotiate**_ situées dans _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ doivent être définies sur "1". Si ces clés sont **absentes ou définies sur "0"**, WDigest est **désactivé** :
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** et **Protected Process Light (PPL)** sont des **protections au niveau noyau de Windows** conçues pour empêcher l'accès non autorisé à des processus sensibles comme **LSASS**. Introduit dans **Windows Vista**, le **modèle PP** a été créé à l'origine pour l'application du **DRM** et ne permettait de protéger que des binaires signés avec un **certificat média spécial**. Un processus marqué **PP** ne peut être accédé que par d'autres processus **également PP** et ayant un **niveau de protection égal ou supérieur**, et encore, **seulement avec des droits d'accès limités** sauf autorisation explicite.

**PPL**, introduit dans **Windows 8.1**, est une version plus flexible de PP. Il permet des **cas d'utilisation plus larges** (p.ex. LSASS, Defender) en introduisant des **« niveaux de protection »** basés sur le champ EKU (Enhanced Key Usage) de la signature numérique. Le niveau de protection est stocké dans le champ `EPROCESS.Protection`, qui est une structure `PS_PROTECTION` contenant :
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (p.ex. `WinTcb`, `Lsa`, `Antimalware`, etc.)

Cette structure est empaquetée dans un seul octet et détermine **qui peut accéder à qui** :
- **Les signers de valeur plus élevée peuvent accéder aux signers de valeur plus faible**
- **Les PPL ne peuvent pas accéder aux PP**
- **Les processus non protégés ne peuvent accéder à aucun PPL/PP**

### Ce que vous devez savoir d'un point de vue offensif

- Quand **LSASS s'exécute en tant que PPL**, les tentatives de l'ouvrir via `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` depuis un contexte administrateur normal **échouent avec `0x5 (Access Denied)`**, même si `SeDebugPrivilege` est activé.
- Vous pouvez **vérifier le niveau de protection de LSASS** en utilisant des outils comme Process Hacker ou programmaticalement en lisant la valeur `EPROCESS.Protection`.
- LSASS aura typiquement `PsProtectedSignerLsa-Light` (`0x41`), qui ne peut être accédé **que par des processus signés avec un signer de niveau supérieur**, comme `WinTcb` (`0x61` ou `0x62`).
- PPL est une **restriction uniquement au niveau Userland** ; **le code côté kernel peut la contourner complètement**.
- Le fait que LSASS soit en PPL **n'empêche pas le credential dumping si vous pouvez exécuter du kernel shellcode** ou **tirer parti d'un processus fortement privilégié avec les accès appropriés**.
- **Activer ou désactiver PPL** nécessite un redémarrage ou des réglages Secure Boot/UEFI, ce qui peut rendre la configuration PPL persistante même après l'annulation des changements de registre.

### Create a PPL process at launch (documented API)

Windows expose une méthode documentée pour demander un niveau Protected Process Light pour un processus enfant lors de sa création en utilisant la extended startup attribute list. Cela ne contourne pas les exigences de signature — l'image cible doit être signée pour la classe de signer demandée.

Minimal flow in C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Notes et contraintes:
- Utiliser `STARTUPINFOEX` avec `InitializeProcThreadAttributeList` et `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, puis passer `EXTENDED_STARTUPINFO_PRESENT` à `CreateProcess*`.
- Le DWORD de protection peut être défini sur des constantes telles que `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, or `PROTECTION_LEVEL_LSA_LIGHT`.
- Le processus enfant ne démarre en tant que PPL que si son image est signée pour cette classe de signataire ; sinon la création du processus échoue, généralement avec `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Il ne s'agit pas d'un contournement — c'est une API prise en charge destinée aux images correctement signées. Utile pour durcir des outils ou valider des configurations protégées par PPL.

Example CLI using a minimal loader:
- Signataire Antimalware: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- Signataire LSA-light: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Options pour contourner les protections PPL :**

Si vous voulez dump LSASS malgré PPL, vous avez 3 options principales :
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)** to **remove LSASS’s protection flag**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** pour exécuter du code kernel personnalisé et désactiver la protection. Des outils comme **PPLKiller**, **gdrv-loader**, ou **kdmapper** rendent cela faisable.
3. **Steal an existing LSASS handle** depuis un autre processus qui l'a ouvert (ex., un processus AV), puis **le dupliquer** dans votre processus. Ceci est la base de la technique `pypykatz live lsa --method handledup`.
4. **Abuser d'un processus privilégié** qui vous permettra de charger du code arbitraire dans son espace d'adressage ou dans celui d'un autre processus privilégié, contournant ainsi les restrictions PPL. Vous pouvez consulter un exemple de ceci dans [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) or [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Vérifier l'état actuel de la protection LSA (PPL/PP) pour LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- Pour plus d'informations sur cette vérification [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, une fonctionnalité exclusive à **Windows 10 (Enterprise and Education editions)**, renforce la sécurité des identifiants machine en utilisant **Virtual Secure Mode (VSM)** et **Virtualization Based Security (VBS)**. Il exploite les extensions de virtualisation CPU pour isoler les processus clés dans un espace mémoire protégé, hors de portée du système d'exploitation principal. Cette isolation garantit que même le kernel ne peut accéder à la mémoire dans le VSM, protégeant ainsi efficacement les identifiants contre des attaques comme **pass-the-hash**. Le **Local Security Authority (LSA)** fonctionne dans cet environnement sécurisé en tant que trustlet, tandis que le processus **LSASS** dans l'OS principal agit uniquement comme un communicateur avec le LSA du VSM.

Par défaut, **Credential Guard** n'est pas actif et nécessite une activation manuelle au sein d'une organisation. Il est essentiel pour renforcer la sécurité contre des outils comme **Mimikatz**, qui se trouvent limités dans leur capacité à extraire les identifiants. Cependant, des vulnérabilités peuvent encore être exploitées par l'ajout de **Security Support Providers (SSP)** personnalisés pour capturer les identifiants en clair lors des tentatives de connexion.

Pour vérifier l'état d'activation de **Credential Guard**, la clé de registre _**LsaCfgFlags**_ sous _**HKLM\System\CurrentControlSet\Control\LSA**_ peut être inspectée. Une valeur de "**1**" indique une activation avec **UEFI lock**, "**2**" sans lock, et "**0**" signifie qu'il n'est pas activé. Cette vérification du registre, bien qu'étant un indicateur fort, n'est pas la seule étape pour activer Credential Guard. Des instructions détaillées et un script PowerShell pour activer cette fonctionnalité sont disponibles en ligne.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Pour une compréhension complète et des instructions sur l'activation de **Credential Guard** dans Windows 10 et son activation automatique dans les systèmes compatibles de **Windows 11 Enterprise and Education (version 22H2)**, consultez [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Des détails supplémentaires sur l'implémentation de custom SSPs pour la capture d'identifiants sont fournis dans [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** ont introduit plusieurs nouvelles fonctionnalités de sécurité, dont le _**Restricted Admin mode for RDP**_. Ce mode a été conçu pour renforcer la sécurité en atténuant les risques associés aux attaques [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Traditionnellement, lorsque vous vous connectez à un ordinateur distant via RDP, vos identifiants sont stockés sur la machine cible. Cela représente un risque de sécurité important, surtout lorsque vous utilisez des comptes avec des privilèges élevés. Toutefois, avec l'introduction du _**Restricted Admin mode**_, ce risque est fortement réduit.

Lorsque vous initiez une connexion RDP en utilisant la commande **mstsc.exe /RestrictedAdmin**, l'authentification auprès de l'ordinateur distant est effectuée sans stocker vos identifiants dessus. Cette approche garantit que, en cas d'infection par un malware ou si un utilisateur malveillant accède au serveur distant, vos identifiants ne sont pas compromis, car ils ne sont pas stockés sur le serveur.

Il est important de noter que dans le **Restricted Admin mode**, les tentatives d'accès aux ressources réseau depuis la session RDP n'utiliseront pas vos identifiants personnels ; c'est plutôt **l'identité de la machine** qui est utilisée.

Cette fonctionnalité représente une avancée importante pour sécuriser les connexions Remote Desktop et protéger les informations sensibles contre une exposition en cas de faille de sécurité.

![](../../images/RAM.png)

Pour plus d'informations détaillées, visitez [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows sécurise les **domain credentials** via la **Local Security Authority (LSA)**, en prenant en charge les processus de logon avec des protocoles de sécurité comme **Kerberos** et **NTLM**. Une caractéristique clé de Windows est sa capacité à mettre en cache les **dix dernières connexions de domaine** pour s'assurer que les utilisateurs peuvent toujours accéder à leurs ordinateurs même si le **domain controller est hors ligne** — très utile pour les utilisateurs de laptops souvent hors du réseau de l'entreprise.

Le nombre de connexions en cache est réglable via une **clé de registre** spécifique ou une **stratégie de groupe**. Pour afficher ou modifier ce paramètre, la commande suivante est utilisée :
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
L'accès à ces identifiants mis en cache est strictement contrôlé, seul le compte **SYSTEM** disposant des autorisations nécessaires pour les consulter. Les administrateurs qui doivent accéder à ces informations doivent le faire avec les privilèges de l'utilisateur SYSTEM. Les identifiants sont stockés à : `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** peut être utilisé pour extraire ces identifiants mis en cache en exécutant la commande `lsadump::cache`.

Pour plus de détails, la [source originale](http://juggernaut.wikidot.com/cached-credentials) fournit des informations complètes.

## Protected Users

L'appartenance au **groupe Protected Users** apporte plusieurs améliorations de sécurité pour les utilisateurs, garantissant un niveau de protection plus élevé contre le vol et l'abus d'identifiants :

- **Credential Delegation (CredSSP)** : Même si le paramètre de stratégie de groupe **Allow delegating default credentials** est activé, les identifiants en clair des Protected Users ne seront pas mis en cache.
- **Windows Digest** : À partir de **Windows 8.1 et Windows Server 2012 R2**, le système ne mettra pas en cache les identifiants en clair des Protected Users, indépendamment du statut de Windows Digest.
- **NTLM** : Le système ne mettra pas en cache les identifiants en clair des Protected Users ni les fonctions à sens unique NT (NTOWF).
- **Kerberos** : Pour les Protected Users, l'authentification Kerberos ne générera pas de clés **DES** ou **RC4**, et ne mettra pas en cache les identifiants en clair ni les clés à long terme au-delà de l'acquisition initiale du Ticket-Granting Ticket (TGT).
- **Offline Sign-In** : Les Protected Users n'auront pas de vérificateur mis en cache créé lors de la connexion ou du déverrouillage, ce qui signifie que la connexion hors ligne n'est pas prise en charge pour ces comptes.

Ces protections sont activées dès qu'un utilisateur membre du **groupe Protected Users** se connecte à l'appareil. Cela garantit que des mesures de sécurité critiques sont en place pour se prémunir contre diverses méthodes de compromission des identifiants.

Pour des informations plus détaillées, consultez la [documentation officielle](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
