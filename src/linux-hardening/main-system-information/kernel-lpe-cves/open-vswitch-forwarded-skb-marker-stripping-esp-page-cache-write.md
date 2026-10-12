# Suppression du marqueur des skb transférés par Open vSwitch vers des écritures ESP dans le page cache

{{#include ../../../banners/hacktricks-training.md}}

Un schéma d’exploitation utile du noyau Linux consiste à **effacer les métadonnées de propriété d’un skb sans retirer ses fragments externes**, puis à acheminer ce skb vers un consommateur qui écrit sur place. Dans le cas d’Open vSwitch (OVS), l’échec d’un upcall vers l’espace utilisateur efface `SKBFL_SHARED_FRAG` d’un skb `MSG_ZEROCOPY` toujours actif ; ESP déchiffre ensuite directement dans le folio du page cache d’un fichier en lecture seule. Cela permet une écriture déterministe dans le page cache local et a été suivi sous les identifiants CVE-2026-90049, CVE-2026-89487 et CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Il s’agit d’un problème de type Copy Fail/Dirty Frag plutôt que d’une corruption mémoire classique : aucune course ni divulgation d’adresse n’est nécessaire, il suffit que le fichier soit lisible, et les octets modifiés se trouvent dans le page cache, pas sur le disque.<sup>[[2]](#references)[[3]](#references)</sup>

## Invariant de sécurité : les fragments externes doivent rester marqués

`SKBFL_SHARED_FRAG` indique aux consommateurs qui écrivent sur place qu’un fragment de skb peut référencer un stockage dont ils ne sont pas les propriétaires exclusifs. Le chemin rapide ESP dans `esp_input()` ne peut déchiffrer sur place un skb non linéaire et non cloné que si `skb_has_shared_frag()` renvoie false ; sinon, `skb_cow_data()` crée d’abord un stockage privé. Cette vérification côté consommateur a été ajoutée après Dirty Frag.<sup>[[5]](#references)</sup>

L’invariant comporte donc deux parties indépendantes :<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Les processus qui écrivent sur place doivent vérifier `SKBFL_SHARED_FRAG` et copier les données partagées avant de les modifier.
2. Chaque chemin de clonage, de coalescence, de transfert ou de forwarding doit préserver le marqueur tant que la page externe reste attachée.

Fragnesia a enfreint la deuxième règle lors du déplacement de descripteurs de fragments dans `skb_try_coalesce()`. Le chemin OVS est légèrement différent : il ne transfère pas du tout le fragment ; il efface le marqueur **sur place, dans le skb d’origine, puis continue de le transférer**.<sup>[[2]](#references)[[4]](#references)</sup>

## Accessibilité d’OVS sans privilèges

Le datapath du noyau OVS est contrôlé par des familles generic-netlink telles que `ovs_datapath`, `ovs_vport`, `ovs_flow` et `ovs_packet`. Ses opérations de modification utilisent `GENL_UNS_ADMIN_PERM`, qui tient compte des namespaces ; un processus exécuté sous `unshare -Urn` obtient donc le `CAP_NET_ADMIN` nécessaire pour créer un datapath, attacher un veth et installer des actions de flux dans son propre namespace réseau. La résolution de la famille OVS peut également charger automatiquement `openvswitch.ko` ; les privilèges `CAP_SYS_MODULE` sur l’hôte, `ovs-vsctl` et `ovs-vswitchd` ne sont pas requis pour cette surface d’attaque.<sup>[[2]](#references)[[7]](#references)</sup>

La distinction importante concerne deux types d’upcall :<sup>[[2]](#references)[[7]](#references)</sup>

- Un **flow miss** envoie le paquet à `ovs-vswitchd` ; si l’upcall échoue, le paquet est normalement supprimé.
- Une action explicite `OVS_ACTION_ATTR_USERSPACE` envoie une copie empruntée à un ID de port sélectionné, puis exécute les actions suivantes sur le skb d’origine.

Un attaquant peut donc installer un flux de la forme suivante :<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Aucun listener ne possède le port ID sélectionné, ce qui fait échouer prévisiblement l'action userspace, tandis que l'action `OUTPUT` suivante maintient le paquet d'origine en vie.<sup>[[1]](#references)[[2]](#references)</sup>

## Cause fondamentale : `skb_tx_error()` sur un paquet qui survit

Le chemin d'erreur vulnérable des upcalls OVS appelle `skb_tx_error(skb)`. Cet helper a été conçu pour un échec de transmission après lequel le skb est libéré ; il termine la comptabilisation zerocopy via `skb_zcopy_clear()`, dont le masque de flags supprimait historiquement aussi `SKBFL_SHARED_FRAG`. OVS ignorait l'erreur de l'action userspace et poursuivait sa liste d'actions, violant ainsi le contrat de durée de vie de l'helper.<sup>[[1]](#references)[[2]](#references)</sup>

La transition d'état exploitable est la suivante :<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Cela ne fonctionne que lorsque `skb_zcopy()` trouve un état zerocopy. Un fragment portant uniquement `SKBFL_SHARED_FRAG` ne suffit pas ; `MSG_ZEROCOPY` est utile, car il crée `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` et définit également `SKBFL_DONT_ORPHAN`. Ce dernier fait que `skb_orphan_frags()` ignore le remplacement des pages étrangères lors de la copie vers l’espace utilisateur d’OVS.<sup>[[2]](#references)[[3]](#references)</sup>

## Construction de la primitive d’écriture

Le déclencheur de bout en bout comporte les éléments suivants.<sup>[[2]](#references)[[3]](#references)</sup>

1. Entrer dans des espaces de noms utilisateur et réseau privés avec `unshare -Urn`.
2. Mapper un fichier cible en lecture avec `PROT_READ | MAP_SHARED`.
3. Utiliser un netns émetteur distinct et une paire veth ; la boucle locale copierait les pages empruntées et détruirait la primitive.
4. Construire un datapath OVS et le flux défaillant `USERSPACE`-puis-`OUTPUT`.
5. Installer un état XFRM ESP-in-UDP en mode transport à l’aide de `rfc4106(gcm(aes))` et du port UDP 4500.
6. Envoyer un datagramme `MSG_ZEROCOPY` avec un iovec structuré ainsi : `[ESP header | mapped file bytes | invalid ICV]`.

L’état XFRM utilise 20 octets de matériel de clé AES-128-GCM : 16 octets de clé AES suivis du sel RFC 4106 de quatre octets. Pour un IV explicite de huit octets choisi, le chiffrement du contenu commence avec le bloc compteur `salt || IV || be32(2)` ; la valeur de compteur 1 masque plutôt le résultat de l’authentification.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Une fois qu’OVS retire le marqueur, ESP emprunte son chemin no-copy et effectue `plaintext = ciphertext XOR keystream` sur le fragment adossé au fichier. L’authentification est vérifiée **après** cette transformation : un ICV invalide entièrement nul fait donc échouer le paquet avec `-EBADMSG` seulement après que les octets du page cache ont déjà été modifiés.<sup>[[2]](#references)</sup>

### Transformer GCM en octets choisis

Pour l’octet courant `C` et l’octet souhaité `P`, le premier octet du keystream du payload doit être `C XOR P`. Avec la clé AES et le sel fixés, balayez un suffixe de 16 bits de l’IV explicite et précalculez un suffixe pour chaque valeur possible du premier octet du keystream :<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

L’implémentation publique limite le texte chiffré à 32 octets et avance le fragment du fichier d’un octet pour chaque paquet. Le premier octet choisi écrase le premier octet collatéral du paquet précédent ; `pread()` actualise `C` avant chaque paquet, les octets identiques sont ignorés et le dernier paquet est raccourci afin que les écritures ne dépassent pas la plage demandée. Une table de correspondance de 256 entrées transforme ainsi cette primitive en une écriture dans le page cache, octet par octet, avec un contenu choisi, à raison d’environ un paquet par octet différent.<sup>[[2]](#references)[[3]](#references)</sup>

## Écriture dans le page cache pour obtenir root

Une cible pratique est un exécutable setuid-root existant. Le PoC remplace les 160 premiers octets par un ELF statique complet contenant un unique `PT_LOAD` à adresse fixe avec les droits lecture/exécution, aucun `PT_INTERP` et du code qui appelle `setuid(0)` avant `execve("/bin/sh", ...)`. Cela évite toute hypothèse sur le point d’entrée du binaire d’origine, la disposition PIE, le chargeur dynamique ou les relocalisations.<sup>[[2]](#references)[[3]](#references)</sup>

La modification est visible dans tous les user namespaces, car le page cache n’est pas cloisonné par namespace. Le folio modifié n’est pas marqué dirty et n’est donc pas réécrit sur le disque ; exécutez la cible tant qu’il est en mémoire, puis annulez la corruption temporaire avec `posix_fadvise(..., POSIX_FADV_DONTNEED)` afin que les lectures ultérieures rechargent le contenu d’origine depuis le disque.<sup>[[2]](#references)[[3]](#references)</sup>

## Vérifications d’exposition et mesures d’atténuation

Vérifiez d’abord le noyau du fournisseur concerné. Les principaux facteurs d’exposition sont les user namespaces non privilégiés, la disponibilité ou la présence d’OVS, ainsi que la disponibilité d’une implémentation ESP.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Mettre à niveau vers un noyau intégrant la série complète de correctifs ; la réparation finale couvre le chemin de recirculation et évite de modifier l’état partagé de `skb_shinfo()`, tout en corrigeant également un problème connexe dans `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Si OVS n’est pas utilisé, empêcher son chargement à la fois par alias et par nom à l’aide d’une règle `install` de modprobe, plutôt que de s’appuyer uniquement sur `blacklist`. Si l’hôte ne termine pas IPsec et qu’ESP est modulaire, le même contrôle peut supprimer le point de terminaison du déchiffrement.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Ces règles ne sont pas utiles lorsqu’un module est déjà chargé ou que la fonctionnalité est intégrée au kernel. Désactiver les user namespaces non privilégiés supprime également cette source de capacités de namespace, mais peut perturber les navigateurs, Flatpak, Podman et d’autres workloads de sandboxing ou de conteneurs.<sup>[[2]](#references)</sup>

## Leçons à retenir

Lors de l’audit du networking zero-copy, ne limitez pas la recherche aux helpers qui copient ou déplacent des fragments. Repérez également les helpers d’erreur et de complétion qui effacent des flags groupés, puis vérifiez que chaque appelant respecte le contrat documenté sur la durée de vie du skb. Un bit de propriété de page regroupé avec des bits du cycle de vie zerocopy est sensible du point de vue de la sécurité, même si le code qui l’efface n’accède jamais directement à un fragment.<sup>[[1]](#references)[[2]](#references)</sup>

Un correctif robuste doit couvrir toutes les voies par lesquelles le skb peut survivre, y compris la continuation d’action et la recirculation, et tenir compte des clones qui partagent `skb_shinfo()`. Côté consommateur, un échec d’authentification n’annule pas les écritures en clair déjà effectuées par une transformation AEAD sur place ; les vérifications du stockage externe doivent donc être faites avant le début du déchiffrement.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Série de correctifs netdev de Doyensec : net : ne pas supprimer les marqueurs de fragments zerocopy d’un skb transféré](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec : la suppression des marqueurs de skb transféré dans Open vSwitch permet une LPE déterministe via le page cache ESP](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Proof of concept `ovs-pagecache-write` de Doyensec](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Correctif Linux pour le chemin de coalescence Fragnesia original (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Vérification côté consommateur ESP de fragments partagés dans Linux (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106 : utilisation du mode Galois/Counter (GCM) dans ESP IPsec](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Documentation du datapath du kernel Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
