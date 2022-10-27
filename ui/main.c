#include <unistd.h>
#include <getopt.h>

#include "contact.h"
struct KernelResponse cmdAddRule();
struct KernelResponse cmdAddNATRule();
void help();

char rulename[MAXRuleNameLen+1], insert[MAXRuleNameLen+1], sip[25], sport[15], dip[25], dport[15], protocol[6], natip[25], natport[15], logs[6];
unsigned short sportMin,sportMax,dportMin,dportMax,natportMin,natportMax;
unsigned int dolog = 0, deny = NF_DROP, proto;

int main(int argc, char *argv[]) {
	struct KernelResponse rsp;
	rsp.code = ERROR_CODE_EXIT;//nothing happened is wrong

    int option_index = 0, opt=0;
    int mod = 0, option = 0;
    char *string = "";

    static struct option long_options[] = {
            {"mod",         required_argument, NULL, 1},
            {"default",     required_argument, NULL, 2},
            {"del",         required_argument, NULL, 3},
            {"add",         required_argument, NULL, 4},
            {"insert",      required_argument, NULL, 5},
            {"sip",         required_argument, NULL, 6},
            {"sport",       required_argument, NULL, 7},
            {"dip",         required_argument, NULL, 8},
            {"dport",       required_argument, NULL, 9},
            {"protocol",    required_argument, NULL, 10},

            {"deny",        no_argument,       NULL, 11},
            {"accept",      no_argument,       NULL, 12},
            {"log",         no_argument,       NULL, 13},
            {"natip",       required_argument, NULL, 14},
            {"natport",     required_argument, NULL, 15},

            {"logs",        optional_argument, NULL, 16},
            {"rules",       no_argument,       NULL, 17},
            {"nats",        no_argument,       NULL, 18},
            {"connections", no_argument,       NULL, 19},

            {"help", no_argument, NULL, 20},
            {NULL, 0,                          NULL, 0}};
    while ((opt = getopt_long_only(argc, argv, string, long_options, &option_index)) != -1) {
        switch (opt) {
            case 1:
                if (strcmp(optarg, "rule") == 0) {
                    mod = 1;
                } else if (strcmp(optarg, "nat") == 0) {
                    mod = 2;
                } else if (strcmp(optarg, "show") == 0) {
                    mod = 3;
                } else {
                    printf("error: invalid '-mod' argument\n");
                    exit(0);
                }
                break;
            case 2:
                if (strcmp(optarg, "drop") == 0) {
                    option = 1;
                } else if (strcmp(optarg, "accept") == 0) {
                    option = 2;
                } else {
                    printf("error: invalid '-default' argument\n");
                    exit(0);
                }
                break;
            case 3:
                option = 3;//del
                if(strlen(optarg)>MAXRuleNameLen){
                    printf("error: rule name too long\n");
                    exit(0);
                }
                strcpy(rulename,optarg);
                break;
            case 4:
                option = 4;//add
                if(strlen(optarg)>MAXRuleNameLen){
                    printf("error: rule name too long\n");
                    exit(0);
                }
                strcpy(rulename,optarg);
                break;
            case 5:
                if(strlen(optarg)>MAXRuleNameLen){
                    printf("error: insert rule name too long\n");
                    exit(0);
                }
                strcpy(insert,optarg);
                break;
            case 6:
                if(strlen(optarg)>18){
                    printf("error: invalid sip\n");
                    exit(0);
                }
                strcpy(sip,optarg);
                break;
            case 7:
                if(strcmp(optarg, "any") == 0) {
                    sportMin = 0,sportMax = 0xFFFFu;
                }else if(sscanf(optarg,"%hu-%hu",&sportMin,&sportMax)==2 && strlen(optarg)<=11){
                    if(sportMin > sportMax) {
                        unsigned short tmp = sportMin;
                        sportMin = sportMax;
                        sportMax = tmp;
                    }
                }else{
                    printf("error: invalid sport range\n");
                    exit(0);
                }
                strcpy(sport,optarg);
                break;
            case 8:
                if(strlen(optarg)>18){
                    printf("error: invalid dip\n");
                    exit(0);
                }
                strcpy(dip,optarg);
                break;
            case 9:
                if(strcmp(optarg, "any") == 0) {
                    dportMin = 0,dportMax = 0xFFFFu;
                }else if(sscanf(optarg,"%hu-%hu",&dportMin,&dportMax)==2 && strlen(optarg)<=11){
                    if(dportMin > dportMax) {
                        unsigned short tmp = dportMin;
                        dportMin = dportMax;
                        dportMax = tmp;
                    }
                }else{
                    printf("error: invalid dport range\n");
                    exit(0);
                }
                strcpy(dport,optarg);
                break;
            case 10:
                if(strcmp(optarg,"TCP")==0 || strcmp(optarg,"tcp")==0)
                    proto = IPPROTO_TCP;
                else if(strcmp(optarg,"UDP")==0 || strcmp(optarg,"udp")==0)
                    proto = IPPROTO_UDP;
                else if(strcmp(optarg,"ICMP")==0 || strcmp(optarg,"icmp")==0)
                    proto = IPPROTO_ICMP;
                else if(strcmp(optarg,"ANY")==0 || strcmp(optarg,"any")==0)
                    proto = IPPROTO_IP;
                else {
                    printf("error: invalid protocol\n");
                    exit(0);
                }
                strcpy(protocol,optarg);
                break;
            case 11://deny
                deny = 0;
                break;
            case 12://accept
                deny = 1;
                break;
            case 13:
                dolog = 1;
                break;
            case 14:
                if(strlen(optarg)>15){
                    printf("error: invalid natip\n");
                    exit(0);
                }
                strcpy(natip,optarg);
                break;
            case 15:
                if(strcmp(optarg, "any") == 0) {
                    natportMin = 0,natportMax = 0xFFFFu;
                }else if(sscanf(optarg,"%hu-%hu",&natportMin,&natportMax)==2 && strlen(optarg)<=11){
                    if(natportMin > natportMax) {
                        unsigned short tmp = natportMin;
                        natportMin = natportMax;
                        natportMax = tmp;
                    }
                }else{
                    printf("error: invalid nat port range\n");
                    exit(0);
                }
                strcpy(natport,optarg);
                break;
            case 16:
                option = 1;//logs
                if(optarg!=NULL){
                    strcpy(logs,optarg);
                }else{
                    strcpy(logs,"0");
                }
                break;
            case 17:
                option = 2;//rules
                break;
            case 18:
                option = 3;//nats
                break;
            case 19:
                option = 4;//connections
                break;
            case 20://help
                mod = 0;
            default:
                break;
        }
    }

    //implement
    switch (mod) {
        case 1://rule
            switch (option) {
                case 1://default drop
                    rsp = setDefaultAction(NF_DROP);
                    break;
                case 2://default accept
                    rsp = setDefaultAction(NF_ACCEPT);
                    break;
                case 3://del
                    rsp = delFilterRule(rulename);
                    break;
                case 4://add
                    rsp = cmdAddRule();
                    break;
                default:
                    printf("error: unknown action\n");
                    break;
            }
            break;
        case 2://nat
            switch (option) {
                case 3://del
                    if(strcmp(rulename,"0")==0) {
                        rsp = delNATRule(0);
                    }else{
                        unsigned int num = atoi(rulename);
                        if(num == 0){
                            printf("error: invalid -del argument, expecting a int number\n");
                        }else{
                            rsp = delNATRule(num);
                        }
                    }
                    break;
                case 4://add
                    if(strcmp(rulename, "nat")!=0 && strcmp(rulename, "NAT")!=0){
                        printf("error: invalid -add argument, expecting\"NAT/nat\"\n");
                    }else{
                        rsp = cmdAddNATRule();
                    }
                    break;
                default:
                    printf("error: unknown action\n");
                    exit(0);
                    break;
            }
            break;
        case 3://show
            switch (option) {
                case 1:{//logs
                    unsigned int num = atoi(logs);;
                    //num would be "0" if no argument ("logs" would be NULL) or "logs" isn't a num
                    rsp = getLogs(num);
                    break;
                }
                case 2://rules
                    rsp = getAllFilterRules();
                    break;
                case 3://nats
                    rsp = getAllNATRules();
                    break;
                case 4://connections
                    rsp = getAllConns();
                    break;
                default:
                    printf("error: unknown action\n");
                    exit(0);
                    break;
            }
            break;
        default://help
            help();
            break;
    }
    dealResponseAtCmd(rsp);
    return 0;
}

void help() {
	printf("-help:\n");
	printf("firewall -mod [command] <option> [option argument]\n");
	printf("command: rule <-default | -del | -add>\n");
	printf("         nat  <-del | -add> \n");
	printf("         show <-logs | -logs=[num] | -rules | -nats | -connections>\n");
	printf("option:  -del | -add | -insert | -sip | -sport | -dip | -dport\n");
	printf("         -protocol | -deny | -accept | -log | -natip | -natport\n");
	exit(0);
}

// 新增过滤规则时的用户交互
struct KernelResponse cmdAddRule() {
	printf("Excecution result:\n");
	return addFilterRule(insert,rulename,sip,dip,
		(((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
		(((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),proto,dolog,deny);
}

struct KernelResponse cmdAddNATRule() {
	printf("Excecution result:\n");
	return addNATRule(sip,natip,natportMin,natportMax);
}