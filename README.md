# **NETWORK SNIFFER PROJECT - libpcap**

## Compilation et lancement 

Pour compiler le projet, taper la commande :
[_To compile the project, type:_]
```bash
make
```

ou [_or_]

```bash
make clean
```

La cible **clean** est disponible pour supprimer les fichiers temporaires.

Le projet doit être lancé de la façon suivante : [_To launch the project, type:_]
```bash 
sudo ./sniffer -i <interface> -o <fichier> -f <filtre> -v <verbosité>
```

où _interface_ est un entier correspondant à la numérotation des périphériques.

## Analyse des paquets
Pour l'analyse au niveau de la couche liaison, on part du principe que les données sont encapsulées dans une trame **ethernet**. 

## Niveau de rendu 
L'analyse poussée des paquets est implémentée pour **IPv4** et **ARP**/**RARP**. 
J'ai implémenté deux niveaux de verbose : 1 et 3 (le paramètre 2 donne en fait le niveau de verbose 3).
