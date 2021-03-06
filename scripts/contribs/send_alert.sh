#!/bin/sh

#
# Arguments sent by ArpAlert are :
# 1 : MAC Address
# 2 : IP Address
# 3 : supp (used with unathrq alert)
# 4 : Type of alert (cf arpalert.conf)
#

# Intruder MAC address
intruder_MAC=$1

# Intruder IP address
intruder_IP=$2

# Extra parameter
intruder_Extra=$3

# Interface
intruder_Interface=$4

# Alert Type
intruder_AlertType=$5

# Vendor
if test ! -z "$6"; then
	intruder_Vendor="$6"
else
	intruder_Vendor="unknown mac vendor"
fi

# Mail recipient
mail_To="Jean Dupont <jdupond@domain.com>"

# Subject
mail_Subject="[Warning] Intrusion Detection [Warning]"

# Body and send mail
cat << EOF | mail -s "$mail_Subject" $mail_To
/!\ Intruder Detected /!\

Intrusion time stamp : $(date)

Intruder Ip Address : $intruder_IP
Intruder MAC Address : $intruder_MAC ($intruder_Vendor)
Intruder Extra info : $intruder_Extra
Intruder Interface : $intruder_Interface
Type of alert : $intruder_AlertType
EOF

