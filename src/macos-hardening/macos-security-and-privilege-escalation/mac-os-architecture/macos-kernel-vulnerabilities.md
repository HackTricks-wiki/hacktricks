# Vulnérabilités du noyau macOS

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Dans ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) sont expliquées plusieurs vulnérabilités qui ont permis de compromettre le noyau en compromettant le logiciel de mise à jour.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024 : Vulnérabilités 0-day en exploitation (CVE-2024-23225 & CVE-2024-23296)

Apple a corrigé deux bugs de corruption de mémoire qui étaient activement exploités contre iOS et macOS en mars 2024 (corrigés dans macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Noyau**
• Écriture hors limites dans le sous-système de mémoire virtuelle XNU permettant à un processus non privilégié d'obtenir une lecture/écriture arbitraire dans l'espace d'adresses du noyau, contournant PAC/KTRR.
• Déclenché depuis l'espace utilisateur via un message XPC conçu qui déborde un tampon dans `libxpc`, puis pivote dans le noyau lorsque le message est analysé.
* **CVE-2024-23296 – RTKit**
• Corruption de mémoire dans le RTKit d'Apple Silicon (co-processeur en temps réel).
• Les chaînes d'exploitation observées utilisaient CVE-2024-23225 pour R/W du noyau et CVE-2024-23296 pour échapper au bac à sable du co-processeur sécurisé et désactiver PAC.

Détection du niveau de correctif :
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Si la mise à niveau n'est pas possible, atténuez en désactivant les services vulnérables :
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023 : MIG Type-Confusion – CVE-2023-41075

`mach_msg()` les requêtes envoyées à un client utilisateur IOKit non privilégié entraînent une **confusion de type** dans le code de liaison généré par MIG. Lorsque le message de réponse est réinterprété avec un descripteur hors ligne plus grand que celui qui a été initialement alloué, un attaquant peut réaliser un **écriture OOB** contrôlée dans les zones de tas du noyau et finalement
escalader vers `root`.

Esquisse primitive (Sonoma 14.0-14.1, Ventura 13.5-13.6) :
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Les exploits publics exploitent le bug en :
1. Pulvérisant les tampons `ipc_kmsg` avec des pointeurs de port actifs.
2. Écrasant `ip_kobject` d'un port pendu.
3. Sautant vers le shellcode mappé à une adresse forgée par PAC en utilisant `mprotect()`.

---

## 2024-2025 : Contournement de SIP via des Kexts tiers – CVE-2024-44243 (alias “Sigma”)

Des chercheurs en sécurité de Microsoft ont montré que le démon à privilèges élevés `storagekitd` peut être contraint de charger une **extension de noyau non signée** et ainsi désactiver complètement **System Integrity Protection (SIP)** sur macOS entièrement patché (avant 15.2). Le flux d'attaque est :

1. Abuser de l'attribution privée `com.apple.storagekitd.kernel-management` pour lancer un helper sous le contrôle de l'attaquant.
2. Le helper appelle `IOService::AddPersonalitiesFromKernelModule` avec un dictionnaire d'informations conçu pointant vers un bundle de kext malveillant.
3. Parce que les vérifications de confiance SIP sont effectuées *après* que le kext soit mis en scène par `storagekitd`, le code s'exécute en ring-0 avant validation et SIP peut être désactivé avec `csr_set_allow_all(1)`.

Conseils de détection :
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
La remédiation immédiate consiste à mettre à jour vers macOS Sequoia 15.2 ou une version ultérieure.

---

### Feuille de triche pour l'énumération rapide
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Fuzzer de messages Mach qui cible les sous-systèmes MIG (`github.com/preshing/luftrauser`).
* **oob-executor** – Générateur de primitives hors limites IPC utilisé dans la recherche CVE-2024-23225.
* **kmutil inspect** – Utilitaire Apple intégré (macOS 11+) pour analyser statiquement les kexts avant le chargement : `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “À propos du contenu de sécurité de macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyse de CVE-2024-44243, un contournement de la protection de l'intégrité du système macOS via des extensions de noyau.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
