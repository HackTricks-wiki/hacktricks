# Conteneurs et espaces de noms

{{#include ../../banners/hacktricks-training.md}}

Un conteneur est un processus Linux exécuté avec une configuration d’isolation et de privilèges. Évaluez ensemble l’environnement d’exécution, les ressources de l’hôte montées, les capacités accordées et les paramètres des espaces de noms. La [présentation de la sécurité des conteneurs](container-security/README.md) explique ces couches et renvoie vers chaque contrôle.

- [Élévation de privilèges via Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) porte sur l’accès à l’interface de gestion de containerd.
- [Élévation de privilèges via RunC](runc-privilege-escalation.md) couvre les techniques d’élévation propres à cet environnement d’exécution.
- [Sécurité des conteneurs](container-security/README.md) explique les environnements d’exécution, les API exposées, les risques liés aux images, les montages sensibles, les conteneurs privilégiés, l’évaluation et les protections telles que les espaces de noms, seccomp et le contrôle d’accès obligatoire.
{{#include ../../banners/hacktricks-training.md}}
