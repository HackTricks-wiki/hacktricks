# Systèmes d'exploitation axés sur la confidentialité

Les systèmes d'exploitation axés sur la confidentialité réduisent les erreurs de routage et de persistance, mais aucun ne peut compenser un comportement permettant l'identification ou un matériel compromis.

## Choisir le modèle d'isolation

| Système | Usage idéal | Persistance | Application du routage réseau | Principal compromis |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Navigation web anonyme occasionnelle | L'état du navigateur est normalement limité à la session | Trafic du navigateur uniquement | Les autres applications et l'hôte restent en dehors de Tor |
| **Tails** | Sessions portables, amnésiques et à usage unique | Persistent Storage chiffré facultatif | Le trafic Internet est forcé à passer par Tor | Redémarrages et friction opérationnelle ; confiance envers le firmware et le matériel |
| **Whonix** | Applications persistantes nécessitant un routage Tor forcé | VMs persistantes | Séparation Gateway/Workstation | L'hôte, l'hyperviseur et le mélange d'identités restent des risques |
| **Qubes-Whonix** | Séparation forte des compartiments pour utilisateurs avancés | Par qube | Qubes réseau dédiées et Whonix | Exigences matérielles et complexité opérationnelle |

## Tails

Tails démarre indépendamment depuis un support amovible, achemine le trafic Internet via Tor et est conçu pour laisser un minimum d'état local. Ses propres avertissements soulignent qu'il ne peut pas protéger contre un BIOS/firmware/matériel compromis, les divulgations permettant l'identification, les métadonnées des fichiers ou un observateur puissant corrélant les deux extrémités.<sup>[[1]](#references)</sup>

### Workflow Tails à usage unique

1. Téléchargez Tails depuis le site officiel sur un ordinateur fiable et à jour, puis suivez le processus officiel de vérification et d'installation.
2. Utilisez une clé USB prise en charge uniquement pour démarrer Tails ; ne l'utilisez pas également comme clé générale de transfert de fichiers.
3. Démarrez sur du matériel que vous contrôlez physiquement. Un système d'exploitation live ne peut pas neutraliser un keylogger matériel ou un firmware malveillant.
4. Laissez Persistent Storage désactivé, sauf si le workflow en a réellement besoin. S'il est activé, ne rendez persistantes que les catégories nécessaires et utilisez une phrase de passe robuste.
5. Connectez-vous à un réseau légal. Si un portail captif est inévitable, utilisez uniquement Unsafe Browser pour le portail, ne divulguez aucune identité superflue, fermez-le immédiatement et connectez-vous à Tor avant toute activité sensible.<sup>[[2]](#references)</sup>
6. Configurez un pont Tor si la visibilité directe de Tor ou son blocage pose problème.
7. Effectuez **une identité/un objectif contextuel par session**. Tails recommande de redémarrer entre les activités qui ne doivent pas être liées.<sup>[[1]](#references)</sup>
8. Inspectez et nettoyez les fichiers avant leur publication. N'ouvrez pas les documents actifs téléchargés dans une application susceptible de contourner le contexte prévu.
9. Éteignez complètement le système lorsque vous avez terminé et gardez la clé USB en lieu sûr.

## Whonix

Whonix sépare un **Gateway** assurant le routage Tor d'une **Workstation** dont les applications ne peuvent pas connaître directement l'adresse IP externe. Cela réduit sensiblement les erreurs de proxy/DNS, mais l'hôte, l'hyperviseur, le comportement et les documents peuvent toujours révéler l'identité. Whonix déconseille explicitement d'utiliser une même workstation pour plusieurs identités ou de combiner des activités anonymes et non anonymes.<sup>[[3]](#references)</sup>

### Workflow par compartiments

1. Vérifiez l'image Whonix et la plateforme de virtualisation depuis des sources officielles.
2. Appliquez les correctifs à l'hôte, à l'hyperviseur, au Gateway et à la Workstation avant toute utilisation.
3. Clonez une Workstation vierge pour chaque identité ou engagement ; ne clonez jamais une VM après l'introduction d'un état lié à une identité.
4. Gardez les comptes personnels, les dossiers partagés de l'hôte, la synchronisation du presse-papiers, les périphériques USB et les données temporelles/de localisation hors de la Workstation.
5. Utilisez les snapshots pour la récupération, et non comme substitut aux sauvegardes ou à la séparation des identités.
6. Vérifiez que la Workstation ne peut pas accéder à Internet lorsque le Gateway est arrêté.
7. Pour les fichiers particulièrement risqués, utilisez une VM/qube jetable et n'exportez qu'un résultat nettoyé.

## Qubes OS et Qubes-Whonix

Qubes met en œuvre la sécurité par compartimentation avec des qubes basées sur Xen. Sa conception limite la possibilité qu'une compromission dans un domaine atteigne automatiquement les autres, mais les applications à l'intérieur du **même** qube ne sont pas isolées les unes des autres.<sup>[[4]](#references)</sup> Les Disposable qubes fournissent un état vierge pour les sites, fichiers et périphériques non fiables.<sup>[[5]](#references)</sup>

Une disposition pratique :
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Règles :

- Attribuez à chaque qube un niveau de confiance et un objectif d’identité.
- Conservez les secrets dans un qube vault hors ligne et utilisez des opérations explicites de copie entre qubes/de fichiers.
- Ouvrez les fichiers et liens non sollicités dans des disposables.
- Faites passer uniquement les qubes concernés par Whonix ou un qube VPN dédié.
- Étiquetez distinctement les fenêtres et arrêtez les qubes sans rapport pendant les opérations sensibles.
- Ne supposez pas que deux qubes empêchent la corrélation s’ils partagent des comptes, du contenu, des horaires ou des paiements.

## Verification and maintenance

- Vérifiez les signatures/checksums des installateurs conformément aux instructions officielles.
- Appliquez d’abord les correctifs aux templates, puis redémarrez les qubes/VMs dépendants.
- Confirmez le comportement de refus réseau, le DNS, IPv6, l’horloge, le presse-papiers, les répertoires partagés et l’affectation USB.
- Examinez Persistent Storage et les snapshots de VM à la recherche d’anciennes données associées à une identité.
- Conservez des sauvegardes chiffrées hors ligne des seeds/clés et testez leur restauration dans un environnement isolé.
- Reconstruisez un compartiment après une compromission suspectée ; changer son adresse IP de sortie est insuffisant.

## References

- [1] [Tails — Avertissements : Tails est sûr, mais pas magique](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Se connecter à un réseau via un portail captif](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Limitations de Whonix et Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Objectifs de conception de la sécurité](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Comment utiliser les disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
