# Le protocole Modbus

## Introduction au protocole Modbus

Le protocole Modbus est un protocole largement utilisé dans l'automatisation industrielle et les systèmes de contrôle. Modbus permet la communication entre divers dispositifs tels que les contrôleurs logiques programmables (PLC), les capteurs, les actionneurs et d'autres dispositifs industriels. Comprendre le protocole Modbus est essentiel car c'est le protocole de communication le plus utilisé dans les ICS et présente une grande surface d'attaque potentielle pour l'écoute et même l'injection de commandes dans les PLC.

Ici, les concepts sont énoncés point par point, fournissant le contexte du protocole et sa nature de fonctionnement. Le plus grand défi en matière de sécurité des systèmes ICS est le coût de mise en œuvre et de mise à niveau. Ces protocoles et normes ont été conçus au début des années 80 et 90, et sont encore largement utilisés. Étant donné qu'une industrie dispose de nombreux dispositifs et connexions, la mise à niveau des dispositifs est très difficile, ce qui donne aux hackers un avantage pour traiter des protocoles obsolètes. Les attaques sur Modbus sont pratiquement inévitables, car il sera utilisé sans mise à niveau, son fonctionnement étant critique pour l'industrie.

## L'architecture Client-Serveur

Le protocole Modbus est généralement utilisé dans une architecture Client-Serveur où un dispositif maître (client) initie la communication avec un ou plusieurs dispositifs esclaves (serveurs). Cela est également appelé architecture Maître-Esclave, qui est largement utilisée en électronique et IoT avec SPI, I2C, etc.

## Versions Série et Ethernet

Le protocole Modbus est conçu pour la communication série ainsi que pour les communications Ethernet. La communication série est largement utilisée dans les systèmes hérités, tandis que les dispositifs modernes prennent en charge l'Ethernet, qui offre des débits de données élevés et est plus adapté aux réseaux industriels modernes.

## Représentation des données

Les données sont transmises dans le protocole Modbus sous forme ASCII ou binaire, bien que le format binaire soit utilisé en raison de sa compatibilité avec les anciens dispositifs.

## Codes de fonction

Le protocole ModBus fonctionne avec la transmission de codes de fonction spécifiques qui sont utilisés pour faire fonctionner les PLC et divers dispositifs de contrôle. Cette partie est importante à comprendre, car des attaques de répétition peuvent être effectuées en retransmettant des codes de fonction. Les dispositifs hérités ne prennent en charge aucune cryptographie pour la transmission des données et ont généralement de longs fils qui les connectent, ce qui entraîne une manipulation de ces fils et la capture/injection de données.

## Adressage de Modbus

Chaque dispositif du réseau a une adresse unique qui est essentielle pour la communication entre les dispositifs. Des protocoles comme Modbus RTU, Modbus TCP, etc. sont utilisés pour mettre en œuvre l'adressage et servent de couche de transport pour la transmission des données. Les données transférées sont au format du protocole Modbus, qui contient le message.

De plus, Modbus met également en œuvre des vérifications d'erreur pour garantir l'intégrité des données transmises. Mais surtout, Modbus est une norme ouverte et tout le monde peut l'implémenter dans ses dispositifs. Cela a permis à ce protocole de devenir une norme mondiale et il est largement répandu dans l'industrie de l'automatisation industrielle.

En raison de son utilisation à grande échelle et du manque de mises à niveau, attaquer Modbus offre un avantage significatif avec sa surface d'attaque. Les ICS dépendent fortement de la communication entre les dispositifs et toute attaque menée contre eux peut être dangereuse pour le fonctionnement des systèmes industriels. Des attaques telles que la répétition, l'injection de données, l'écoute et le leak, le déni de service, la falsification de données, etc. peuvent être menées si le moyen de transmission est identifié par l'attaquant.
