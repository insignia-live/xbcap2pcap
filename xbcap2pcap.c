#include <stdio.h>
#include <stdint.h>

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} __attribute__((packed)) pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} __attribute__((packed)) pcaprec_hdr_t;

int main (int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: xbcap2pcap input output\n");
        return -1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        fprintf(stderr, "Could not open %s\n", argv[1]);
        return -1;
    }

    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        fprintf(stderr, "Could not open %s\n", argv[2]);
        fclose(in);
        return -1;
    }

    // PCAP file header
    pcap_hdr_t pcap_hdr;
    pcap_hdr.magic_number = 0xa1b2c3d4;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = 4096;
    pcap_hdr.network = 1;
    fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, out);


    uint8_t buffer[4096];
    while (1) {
        uint32_t length;
        uint32_t mstimestamp;
        long int offset = ftell(in);

        size_t read = fread(&length, 4, 1, in);
        if (read != 1) {
            printf("No more packets\n");
            break;
        }

        // Length includes header, the actual packets are 8 bytes shorter
        length -= 8;

        printf("packet size: 0x%x, offset: 0x%lx\n", length, offset+8);
        if (length > 4096) {
            fprintf(stderr, "Packet too large (%d), aborting\n", length);
            fclose(in);
            fclose(out);
            return -1;
        }

        // Timestamp in ms
        fread(&mstimestamp, 4, 1, in);
        // Read actual packet
        fread(buffer, length, 1, in);

        if (feof(in)) {
            fprintf(stderr, "Unexpected EOF\n");
            fclose(in);
            fclose(out);
            return -1;
        }

        pcaprec_hdr_t packet_header;
        packet_header.ts_sec = mstimestamp / 1000; // TODO: Set the timestamp to something useful
        packet_header.ts_usec = (mstimestamp % 1000) * 1000;
        packet_header.incl_len = length;
        packet_header.orig_len = length;
        fwrite(&packet_header, sizeof(packet_header), 1, out);
        fwrite(buffer, length, 1, out);
    }

    fclose(in);
    fclose(out);
    return 0;
}