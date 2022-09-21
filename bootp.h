#ifndef BOOTP_H
#define BOOTP_H

#define HARWARE_ADDR_LEN 16
#define MACHINE_NAME_LEN 64
#define BOOTFILE_NAME_LEN 128

#include <stdlib.h>

struct bootp {
    u_int8_t opcode;   
    u_int8_t htype;                     // Type de matériel
    u_int8_t addrlen;                   // Longueur de l'adresse matérielle (6 pour ethernet)
    u_int8_t hops;                      // Nombre de sauts
    u_int32_t id;                       // Identificateur de transaction
    u_short nsec;                       // Nombre de secondes
    u_short unused; 
    u_int32_t ciaddr;                   // Adresse ip client
    u_int32_t yiaddr;                   // Votre adresse ip
    u_int32_t siaddr;                   // Adresse ip du serveur
    u_int32_t giaddr;                   // Adresse ip du gateway
    u_char ceaddr[HARWARE_ADDR_LEN];    // Adresse matérielle du client 
    u_char sname[MACHINE_NAME_LEN];     // Nom de machine du serveur
    u_char bootfile[BOOTFILE_NAME_LEN]; // Nom du fichier de boot
    u_char vendor[MACHINE_NAME_LEN];    // Information spécifiques du vendeur 
};

#endif