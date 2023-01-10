#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INIT_SIZE 8

typedef struct {
    uint8_t header_revision;
    uint8_t header_pad;
    uint16_t header_length;
    uint32_t present_flags;
    uint8_t flags;
    uint8_t data_rate;
    uint16_t channel_frequency;
    uint16_t channel_flags;
    int8_t antenna_signal;
    uint8_t antenna;
    uint16_t rx_flags;
} radiotap;

typedef struct {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t frag_seq;
} beaconframe;

typedef struct {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability;
} fixed;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t *ssid;
} ssid;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t supported_rates[8];
} supported_rates;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t current_channel;
} current_channel;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t DTIM_count;
    uint8_t DTIM_period;
    uint8_t bitmap_control;
    uint8_t partial_virtual_bitmap;
} traffic_indication_map;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint16_t country_code;
    uint8_t environment;
    uint8_t first_channel;
    uint8_t num_channels;
    uint8_t max_transmit_power;
} country_information;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t erp_information;
} erp_information;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t extended_supported_rates[4];
} extended_supported_rates;

typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint16_t rsn_version;
    uint32_t group_cipher_suite;
    uint16_t pairwise_cipher_suite_count;
    uint32_t pairwise_cipher_suite;
    uint16_t akm_suite_count;
    uint32_t akm_list;
    uint16_t rsn_capabilities;
} rsn_information;

typedef struct {
    radiotap radiotap;
    beaconframe beaconframe;
    fixed fixed;
    ssid ssid;
    supported_rates supported_rates;
    current_channel current_channel;
    traffic_indication_map traffic_indication_map;
    country_information country_information;
    erp_information erp_information;
    extended_supported_rates extended_supported_rates;
    rsn_information rsn_information;
    uint8_t *tag;
} IEEE80211;

typedef struct {
    IEEE80211 ieee80211;
    unsigned int beacon_count;
    unsigned int data_count;
} IEEEtable;

char* str(int size) {
	char* string = (char*)malloc(sizeof(char) * size);

	for (int i = 0; i < size; i++)
		string[i] = '\0';

	return string;
}

char** split(char *sentence, char separator) {
	char** tokens;
	int* lengths;
	int tokens_idx = 0;
	int token_idx = 0;
	int num_tokens = 1;

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator)
			(num_tokens)++;
	}

	lengths = (int*)malloc(sizeof(int) * (num_tokens));
	tokens = (char**)malloc(sizeof(char*) * (num_tokens));

	for (int i = 0; i < num_tokens; i++) {
		tokens[i] = str(INIT_SIZE);
		lengths[i] = INIT_SIZE;
	}

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator && strlen(tokens[tokens_idx]) != 0) {
			token_idx = 0;
			tokens_idx++;
		}
		else if (sentence[i] == separator && strlen(tokens[tokens_idx]) == 0){
			continue;
		}
		else {
			/* Memory reallocation, If  array is full. */

			if (strlen(tokens[tokens_idx]) == lengths[tokens_idx] - 1) {
				tokens[tokens_idx] = realloc(tokens[tokens_idx], (lengths[tokens_idx] * sizeof(char)) << 1);

				for (int j = lengths[tokens_idx]; j < lengths[tokens_idx] << 1; j++)
					tokens[tokens_idx][j] = '\0';

				lengths[tokens_idx] <<= 1;
			}

			tokens[tokens_idx][token_idx] = sentence[i];
			token_idx++;
		}
	}

	return tokens;
}


void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump wlan0\n");
}

int compareMac(uint8_t* mac1, uint8_t* mac2) {
    for(int i = 0; i < 6; i++) {
        if(mac1[i] != mac2[i]) return 0;
    }
    return 1;
}

int channel = 1;

void changeChannel(char *arg) {
    while(1) {
        char command[30];
        sprintf(command, "iwconfig %s channel %d", arg, channel);
        system(command);
        if(channel == 14) channel = 1;
        else channel++;
        usleep(50);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
		usage();
		return -1;
	}
    IEEEtable table[500];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, NULL);
    if (handle == NULL) {
        printf("failed to open %s\n", argv[1]);
        return -1;
    }
    int table_idx = 0;
    pthread_t thread;
    pthread_create(&thread, NULL, changeChannel, argv[1]);
    while(1) {
        system("clear");
        printf("channel: %d\n", channel);
        printf("BSSID              PWR  Beacons    #Data, #/s  CH   MB  ESSID\n");
        for(int i = 0; i < table_idx; i++) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x  %d%9d%9d%5d%4d", table[i].ieee80211.beaconframe.bssid[0], table[i].ieee80211.beaconframe.bssid[1], table[i].ieee80211.beaconframe.bssid[2], table[i].ieee80211.beaconframe.bssid[3], table[i].ieee80211.beaconframe.bssid[4], table[i].ieee80211.beaconframe.bssid[5], table[i].ieee80211.radiotap.antenna_signal, table[i].beacon_count, table[i].data_count, 0, table[i].ieee80211.current_channel.current_channel);
            int rate = table[i].ieee80211.extended_supported_rates.extended_supported_rates[sizeof(table[i].ieee80211.extended_supported_rates.extended_supported_rates)/sizeof(table[i].ieee80211.extended_supported_rates.extended_supported_rates[0]) - 1];
            printf("%5d  ", rate > 20 ? rate : table[i].ieee80211.supported_rates.supported_rates[sizeof(table[i].ieee80211.supported_rates.supported_rates)/sizeof(table[i].ieee80211.supported_rates.supported_rates[0]) - 1]);
            // if(table[i].ieee80211.rsn_information.tag_number == 0x30) {
            //     printf(" %08x ", table[i].ieee80211.rsn_information.akm_list);
            //     if(table[i].ieee80211.rsn_information.akm_list & 3 == 2)printf(" WPA2 PSK ");
            //     else printf(" WPA3 SAE ");
            // }
            // else if(table[i].ieee80211.rsn_information.tag_number == 221) {
            //     printf(" WPA ");
            // }
            // else {
            //     printf(" OPN ");
            // }
            for(int j = 0; j < table[i].ieee80211.ssid.tag_length; j++) {
                printf("%c", table[i].ieee80211.ssid.ssid[j]);
            }
            printf("\n");
        }
        
        struct pcap_pkthdr* header;
        const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
        
        if(packet[18] == 0x80) {
            radiotap* radiotap = (struct radiotap*)packet;
            packet += radiotap->header_length;
            beaconframe* beaconframe = (struct beaconframe*)packet;
            packet += sizeof(*beaconframe);
            fixed* fixed = (struct fixed*)packet;
            packet += sizeof(*fixed);
            ssid* ssid;
            ssid->tag_number = packet[0];
            ssid->tag_length = packet[1];
            ssid->ssid = (char*)malloc(sizeof(char) * (ssid->tag_length));
            for(int i = 0; i < ssid->tag_length; i++) {
                ssid->ssid[i] = packet[i + 2];
            }
            packet += ssid->tag_length + 2;
            supported_rates* supported_rates = (struct supported_rates*)packet;
            packet += supported_rates->tag_length + 2;
            //if(packet[0] == 0x03) packet += 3;
            current_channel* current_channel = (struct current_channel*)packet;
            packet += current_channel->tag_length + 2;;
            traffic_indication_map* traffic_indication_map = (struct traffic_indication_map*)packet;
            packet += traffic_indication_map->tag_length + 2;
            country_information* country_information = (struct country_information*)packet;
            packet += country_information->tag_length + 2;
            // if(packet[0] == 0x20) packet += 3;
            // if(packet[0] == 0x23) packet += 4;
            // if(packet[0] == 0xc3) packet += 5;
            // if(packet[0] == 0x46) packet += 7;
            // if(packet[0] == 0x33) packet += 12;
            // if(packet[0] == 0x23) packet += 4;
            // if(packet[0] == 0x3b) packet += 8;
            erp_information* erp_information = (struct erp_information*)packet;
            packet += erp_information->tag_length + 2;
            extended_supported_rates* extended_supported_rates = (struct extended_supported_rates*)packet;
            packet += extended_supported_rates->tag_length + 2;
            // if(packet[0] == 0x2d) packet += 28;
            // if(packet[0] == 0x3d) packet += 24;
            // if(packet[0] == 0xdd) packet += 28;
            rsn_information* rsn_information = (struct rsn_information*)packet;
            packet += rsn_information->tag_length + 2;
            uint8_t* tag = (uint8_t*)packet;
            int tag_length = 0;
            int tag_number = 0;
            int tag_idx = 0;
            int flag = 0;
            for(int i = 0; i < 500; i++) {
                if(compareMac(table[i].ieee80211.beaconframe.bssid, beaconframe->bssid)) {
                    table[i].beacon_count++;
                    table[i].ieee80211.radiotap.antenna_signal = radiotap->antenna_signal;
                    table[i].ieee80211.radiotap.data_rate = radiotap->data_rate;
                    flag = 1;
                    break;
                }
            }
            if(flag == 0) {
                table[table_idx].ieee80211.radiotap = *radiotap;
                table[table_idx].ieee80211.beaconframe = *beaconframe;
                table[table_idx].ieee80211.fixed = *fixed;
                table[table_idx].ieee80211.ssid = *ssid;
                table[table_idx].ieee80211.supported_rates = *supported_rates;
                table[table_idx].ieee80211.current_channel = *current_channel;
                table[table_idx].ieee80211.traffic_indication_map = *traffic_indication_map;
                table[table_idx].ieee80211.country_information = *country_information;
                table[table_idx].ieee80211.erp_information = *erp_information;
                table[table_idx].ieee80211.extended_supported_rates = *extended_supported_rates;
                table[table_idx].ieee80211.rsn_information = *rsn_information;
                table[table_idx].beacon_count = 1;
                table[table_idx].data_count = 0;
                table_idx++;
            }

        }
        else if(packet[18] == 0x08) {
            for(int i = 0; i < 500; i++) {
                packet += 28;
                uint8_t* macaddr = (uint8_t*)packet;
                if(compareMac(table[i].ieee80211.beaconframe.bssid, macaddr)) {
                    table[i].data_count++;
                    break;
                }
            }
        }
    }

    pcap_close(handle);
    return 0;
}
