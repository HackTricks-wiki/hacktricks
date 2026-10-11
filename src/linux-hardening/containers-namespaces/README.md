# Conteneurs et namespaces

{{#include ../../banners/hacktricks-training.md}}

Un conteneur est un processus Linux exécuté avec une configuration d’isolation et de privilèges. Évaluez ensemble le runtime, les ressources de l’hôte montées, les capabilities accordées et les paramètres des namespaces. La [présentation de la sécurité des conteneurs](container-security/README.md) explique ces couches et renvoie vers chaque mécanisme de contrôle.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) se concentre sur l’accès à l’interface de gestion de containerd.
- [RunC privilege escalation](runc-privilege-escalation.md) couvre les informations relatives à l’élévation de privilèges spécifique au runtime.
- [Sécurité des conteneurs](container-security/README.md) explique les runtimes, les API exposées, les risques liés aux images, les montages sensibles, les conteneurs privilégiés, l’évaluation et les protections telles que les namespaces, seccomp et le contrôle d’accès obligatoire.
{{#include ../../banners/hacktricks-training.md}}
