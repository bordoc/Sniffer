#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <signal.h>

struct sockaddr_in source;
struct sockaddr saddr;
struct in_addr in;
typedef struct
{
    short result;
    long position;
}searchresult;
typedef struct
{
    unsigned long int ip;
    int packets;
}ipcount;

typedef struct
{
    pid_t pid;
    long records;
}parameters;


int close(int);
int fork();
pid_t setsid(void);

int start(void);
int stop(void);
int showIp(char*);
int setIface(char*);
searchresult searcforrecord(ipcount*, int, int);
long getamount(void);
void insert(ipcount*);
void sort(void);
void help(void);
void writeip(unsigned char*, int);




int sock_raw;
FILE *datafile;
long sizeoffile, databufsize;
ipcount* databuf;
parameters param;

int main(int argc, char* argv[])
{
    start();
    return 0;
}

int Daemon()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *packetbuffer = (unsigned char *)malloc(65536); //Its Big!

    datafile=fopen("log.bin","r+b");
    if(datafile==NULL) printf("Unable to create file.");
    fread(&param, sizeof(parameters), 1, datafile);
    fseek(datafile, 0, SEEK_SET);
    printf("Starting...\n");

    databufsize = getamount()+10000;
    databuf = (ipcount*)calloc(databufsize, sizeof(ipcount));
    fseek(datafile, sizeof(parameters), SEEK_SET);

    printf("%d - %d \n", param.pid, param.records);



    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    saddr_size = sizeof saddr;
    int j = 0;
    struct sockaddr_in tmp;
    struct iphdr* iphr;
    char* string;
    fseek (datafile, sizeof(parameters), SEEK_SET);
    while(j<100)
    {
        data_size = recvfrom(sock_raw , packetbuffer , 65536 , 0 , &saddr , &saddr_size);
        writeip(packetbuffer , data_size);
        iphr = (struct iphdr *)packetbuffer;
        tmp.sin_addr.s_addr = iphr->saddr;
        string = inet_ntoa(tmp.sin_addr);
        printf("processed - %s\n", string);
        j++;
    }
    close(sock_raw);
    fclose(datafile);
    printf("Finished");
    return 0;
}

int start()
{
    datafile=fopen("log.bin","r+b");
    if(datafile==NULL)
    {
        datafile = fopen("log.bin", "w+b");
    }
    fseek(datafile, 0, SEEK_END);
    param.records = (ftell (datafile) - sizeof(parameters))/ sizeof(ipcount);
    if (param.records < 0)
    {
        param.pid = 0;
        param.records = 0;
    }
    else
    {
        fread(&param, sizeof(parameters), 1, datafile);
    }
    printf("Old PID:%d, numbers: %d\n", (int)param.pid, param.records);

    if((param.pid=fork())<0)
    {
         printf("\ncan't fork");
         fclose(datafile);
         exit(1);
    }
    else if (param.pid!=0)
    {
        fseek (datafile, 0, SEEK_SET);
        fwrite(&param, sizeof(parameters), 1, datafile);
        printf("PID is: %d\n", (int)param.pid);
        fclose(datafile);
        exit(0);
    }
    fclose(datafile);
    setsid();
    Daemon();
    return 0;
}

void writeip(unsigned char* packetbuffer, int size)
{
    if(databufsize <= getamount())
    {
        databuf = realloc(databuf, sizeof(ipcount)*(databufsize + 1000));
    }
    struct iphdr *iphr = (struct iphdr*)packetbuffer;
    iphr = (struct iphdr *)packetbuffer;
    ipcount ip;
    ip.ip = iphr->saddr;
    ip.packets = 1;
    searchresult res = searcforrecord(&ip, 0, getamount());
    if(res.result)
    {
        fseek(datafile, sizeof(parameters)+sizeof(ip)*res.position, SEEK_SET);
        fread(&ip, sizeof(ip), 1, datafile);
        ip.packets += 1;
        fseek(datafile, -1, SEEK_CUR);
        fwrite(&ip, sizeof(ip), 1, datafile);
    }
    else
    {
        param.records++;
        insert(&ip);
        fseek(datafile, sizeof(parameters), SEEK_SET);
        fwrite(databuf, sizeof(ipcount), param.records, datafile);
    }
}

searchresult searcforrecord(ipcount* record, int begin, int end)
{
    searchresult result;
    while (begin <= end)
    {
        int mid = (begin + end) / 2;
        if (databuf[mid].ip < record->ip)
            begin = mid + 1;
        else if (databuf[mid].ip == record->ip)
        {
            result.position = mid;
            result.result = 1;
            return result;
            break;
        }
        else
            end = mid - 1;
    }
    result.position = 0;
    result.result = 0;
    rseturn result;
}

void insert(ipcount* ip)
{
    databuf[param.records-1]=*ip;
    sort();
}

void sort(void)
{
    int i = 0;
    while(databuf[i].ip < databuf[param.records-1].ip)
    {
        i++;
    }
    ipcount* tmpbuf = calloc(param.records - i, sizeof(ipcount));
    memcpy(tmpbuf, databuf, sizeof(ipcount)*(param.records - i));
    databuf[i] = tmpbuf[param.records - i];
    memcpy(databuf+1, tmpbuf, sizeof(ipcount)*(param.records - i-1));
    free(tmpbuf);
}

long getamount(void)
{
    fseek (datafile, 0, SEEK_END);
    long sizeoffile=ftell (datafile);
    fseek(datafile, 0, SEEK_SET);
    return ((sizeoffile - sizeof(parameters)) / sizeof(ipcount));
}

int stop()
{

}

int showIp(char* ip)
{

}

int setIface(char* iface)
{

}

void help()
{

}


