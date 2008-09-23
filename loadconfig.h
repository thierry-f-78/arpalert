/*
 * type:
 *  0: char
 *  1: int
 *  2: boolean
 *
 * attrib:
 *  valeur du parametre dans le fichier de config
 *
 * valeur:
 *  valeur du parametre de type indefini
 */

#define TRUE        		1
#define FALSE       		0

#define CF_MACLIST  		0
#define CF_LOGFILE  		1
#define CF_ACTION   		2
#define CF_LOCKFILE 		3
#define CF_DAEMON   		4
#define CF_RELOAD   		5
#define CF_LOGLEVEL 		6
#define CF_TIMEOUT  		7
#define CF_MAXTH    		8
#define CF_BLACKLST 		9
#define CF_LEASES   		10
#define CF_IF	    		11
#define CF_ABUS     		12
#define CF_MAXENTRY 		13
#define CF_DMPWL    		14
#define CF_DMPBL    		15
#define CF_DMPAPP   		16
#define CF_TOOOLD   		17
#define CF_LOGALLOW 		18
#define CF_ALRALLOW 		19
#define CF_LOGDENY  		20
#define CF_ALRDENY  		21
#define CF_LOGNEW  		22
#define CF_ALRNEW		23
#define CF_ALRIP		24
#define CF_LOGIP		25
#define CF_AUTHFILE		26
#define CF_LOG_UNAUTH_RQ	27
#define CF_ALERT_UNAUTH_RQ	28
#define CF_LOG_ABUS		29
#define CF_ALERT_ABUS		30

#define NUM_PARAMS  		31

int flagdump;

typedef union {
	char	string[1024];
	int	integer;
} config_val;

typedef struct {
	int		type;
	char		attrib[512];
	config_val	valeur;
} config_cell;

config_cell config[NUM_PARAMS];
char config_file[2048];
char **margv;
int margc;

void config_load(void);
