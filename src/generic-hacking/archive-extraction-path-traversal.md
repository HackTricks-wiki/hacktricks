# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

De nombreux formats d'archive (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de porter son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier conçu contenant `..` ou un **chemin absolu** (par exemple `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur. Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **extraction de chemin d'archive**.

Les conséquences vont de l'écrasement de fichiers arbitraires à l'atteinte directe de **l'exécution de code à distance (RCE)** en déposant un payload dans un emplacement **auto-exécutable** tel que le dossier *Démarrage* de Windows.

## Root Cause

1. L'attaquant crée une archive où un ou plusieurs en-têtes de fichiers contiennent :
* Séquences de traversée relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin intégré au lieu de le nettoyer ou de forcer l'extraction sous le répertoire choisi.
3. Le fichier est écrit dans l'emplacement contrôlé par l'attaquant et exécuté/chargé la prochaine fois que le système ou l'utilisateur déclenche ce chemin.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows (y compris le CLI `rar` / `unrar`, la DLL et la source portable) n'a pas réussi à valider les noms de fichiers lors de l'extraction. Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
se retrouverait **en dehors** du répertoire de sortie sélectionné et à l'intérieur du dossier *Startup* de l'utilisateur. Après la connexion, Windows exécute automatiquement tout ce qui s'y trouve, offrant un RCE *persistant*.

### Création d'une archive PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options utilisées :
* `-ep`  – stocker les chemins de fichiers exactement comme donnés (ne pas élaguer le `./` initial).

Livrer `evil.rar` à la victime et lui demander de l'extraire avec une version vulnérable de WinRAR.

### Exploitation observée dans la nature

ESET a signalé des campagnes de spear-phishing RomCom (Storm-0978/UNC2596) qui ont joint des archives RAR abusant de CVE-2025-8088 pour déployer des portes dérobées personnalisées et faciliter des opérations de ransomware.

## Conseils de détection

* **Inspection statique** – Lister les entrées d'archive et signaler tout nom contenant `../`, `..\\`, *chemins absolus* (`C:`) ou encodages UTF-8/UTF-16 non canoniques.
* **Extraction en bac à sable** – Décompresser dans un répertoire jetable en utilisant un extracteur *sûr* (par exemple, `patool` de Python, 7-Zip ≥ dernière version, `bsdtar`) et vérifier que les chemins résultants restent à l'intérieur du répertoire.
* **Surveillance des points de terminaison** – Alerter sur les nouveaux exécutables écrits dans les emplacements `Startup`/`Run` peu après qu'une archive soit ouverte par WinRAR/7-Zip/etc.

## Atténuation et durcissement

1. **Mettre à jour l'extracteur** – WinRAR 7.13 implémente une bonne sanitation des chemins. Les utilisateurs doivent le télécharger manuellement car WinRAR n'a pas de mécanisme de mise à jour automatique.
2. Extraire des archives avec l'option **“Ignorer les chemins”** (WinRAR : *Extraire → "Ne pas extraire les chemins"*) lorsque cela est possible.
3. Ouvrir des archives non fiables **dans un bac à sable** ou une VM.
4. Mettre en œuvre une liste blanche d'applications et restreindre l'accès en écriture des utilisateurs aux répertoires d'auto-exécution.

## Cas supplémentaires affectés / historiques

* 2018 – Avis *Zip-Slip* massif par Snyk affectant de nombreuses bibliothèques Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 traversée similaire lors de la fusion `-ao`.
* Toute logique d'extraction personnalisée qui ne parvient pas à appeler `PathCanonicalize` / `realpath` avant l'écriture.

## Références

- [BleepingComputer – WinRAR zero-day exploité pour implanter des malwares lors de l'extraction d'archives](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Analyse de la vulnérabilité Zip Slip](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
