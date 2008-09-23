#include "data.h"

void sens_timeout_init(void);
void sens_timeout_add(data_mac *, data_ip);
int  sens_timeout_exist(data_mac *, data_ip);
void sens_timeout_clean(void);

