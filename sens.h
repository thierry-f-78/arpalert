#include "data.h"

void sens_init(void);
void sens_free(void);
void sens_reload(void);
void sens_add(data_mac *, data_ip, u_int32_t);
int  sens_exist(data_mac *, data_ip);

