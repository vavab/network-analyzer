#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include "capture.h"


int getopt(int argc, char * const argv[], const char *optstring);

extern char *optarg;
extern int optind, opterr, optopt;
int verbose;

void sig_handler(int signo) 
{
    if(signo == SIGINT)
    {
        printf("\nCaught signal SIGINT, Quitting...\n");
        exit(EXIT_FAILURE);
    }
}

void print_dev(int number, pcap_if_t* dev)
{
    printf("%d - %s: %s\n", number, dev->name, dev->description);
}

int main(int argc, char *argv[])
{
    /* 
    GESTION DES ARGUMENTS DE LIGNE DE COMMANDE :
    -i <interface> : interface pour l’analyse live
    -o <fichier> : fichier d’entrée pour l’analyse offline
    -f <filtre> : filtre BPF (optionnel)
    -v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)
    */

    int i_flag = 0, o_flag = 0, f_flag = 0, v_flag = 0;
    char *v_value = (char*)malloc(sizeof(char*));
    char *i_value = (char*)malloc(sizeof(char*));
    char *o_value = (char*)malloc(sizeof(char*));
    char *f_value = (char*)malloc(sizeof(char*));

    int c;
    opterr = 0;


    while( (c = getopt(argc, argv, "i:o:f:v:")) != -1 )
    {
        switch(c)
        {
            case 'i':
                i_flag = 1;
                i_value = optarg;
                break;

            case 'o':
                o_flag = 1;
                o_value = optarg;
                break;

            case 'f':
                f_flag = 1;
                f_value = optarg;
                break;

            case 'v':
                v_flag = 1;
                v_value = optarg;
                verbose = atoi(v_value);
                break;

            case '?':
                if (optopt == 'i'|| optopt == 'o' || optopt == 'v')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                return 1;

            default:
                abort();
        }

    }
    
    
    if(f_flag == 0)
        free(f_value);
    
    // Gestion du Ctrl-C
    if(signal(SIGINT, sig_handler) == SIG_ERR)
    {
        printf("\nCan't catch SIGSTOP\n");
    }

    // INTERFACE

    // Analyse live
    if(i_flag == 1)
    {
    // Interface mentionnée dans l'option -i
        int dev_no = atoi(i_value);
        printf("You have chosen device: %d\n", dev_no);
    
    // Récupération de tous les périphériques
        char errbuf[PCAP_ERRBUF_SIZE+1];
        pcap_if_t *alldevs;
        
        if((pcap_findalldevs(&alldevs, errbuf)) == -1)
        {
            fprintf(stderr, "Unable to find devices: %s", errbuf);
            exit(2);
        }

    // Affichage des périphériques trouvés
        pcap_if_t *dev;
        int i;
        printf("\nWorking devices (<name>: <description>):\n");
        for(i=1, dev = alldevs ; dev ; dev = dev->next)
        {
            print_dev(i, dev);
            i++;
        }

    // On recherche le numéro d'interface parmi les périphériques
        for(i=1, dev = alldevs ; dev ; i++, dev = dev->next)
        {
            if(i==dev_no)
            {
                printf("\nDevice found:\n");
                print_dev(i, dev);
                printf("\n");
                break;
                
            }
        }

    // CAPTURE (ouverture)
        pcap_t *handle ;

    // On ouvre le périphérique avec un temps de lecture de 1 seconde
        if((handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf)) == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
            exit(3);
        }

    // Si un filtre a été précisé, on le met en place
        if(f_flag == 1)
        {
            bpf_u_int32 net = 0;
            struct bpf_program fp;

            // On prépare le filtre
            if(pcap_compile(handle, &fp, f_value, 0, net) == -1)
            {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", f_value, errbuf);
                exit(4);
            }

            // On applique le filtre
            if(pcap_setfilter(handle, &fp) == -1)
            {
                fprintf(stderr, "Couldn't install filter %s: %s\n", f_value, errbuf);
                exit(5);
            }
        }
        else{
            free(f_value);
        }

    // On commence la capture
        int loop;
        if(v_flag == 1)
        {
        switch(verbose)
        {
            case 1:
                if((loop = pcap_loop(handle, -1, got_packet1, NULL)) < 0)
                {
                    fprintf(stderr, "Error: %s\n", errbuf);
                }
                break;
            case 2:
                if((loop = pcap_loop(handle, -1, got_packet2, NULL)) < 0)
                {
                    fprintf(stderr, "Error: %s\n", errbuf);
                }
                break;
            case 3:
                if((loop = pcap_loop(handle, -1, got_packet3, NULL)) < 0)
                {
                    fprintf(stderr, "Error: %s\n", errbuf);
                }
                break;
        }
        }

        return 0;

    }

    // Analyse offline
    else if(o_flag == 1)
    {
        printf("File to extract from: %s\n", o_value);
    }

    




}