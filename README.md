# **PROJET SNIFFER RÉSEAU - libpcap**

## Compilation et lancement 

Pour compiler le projet, taper la commande :
>**make** 

ou

>make **clean**

La cible **clean** est disponible pour supprimer les fichiers temporaires.

Le projet doit être lancé de la façon suivante :
> **sudo** ./sniffer **-i** _interface_ **-o** _fichier_
**-f** _filtre_ **-v** _verbosité_

où _interface_ est un entier correspondant à la numérotation des périphériques.

## Analyse des paquets
Pour l'analyse au niveau de la couche liaison, on part du principe que les données sont encapsulées dans une trame **ethernet**. 

## Niveau de rendu 
L'analyse poussée des paquets est implémentée pour **IPv4** et **ARP**/**RARP**. 
J'ai implémenté deux niveaux de verbose : 1 et 3 (le paramètre 2 donne en fait le niveau de verbose 3).

Je n'ai pas réussi à implémenter l'analyse offline des paquets à partir d'un fichier.