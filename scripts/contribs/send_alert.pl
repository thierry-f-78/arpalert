#!/usr/bin/perl -w

#
# This script is using Mail::Sendmail
# Web site : http://alma.ch/perl/Mail-Sendmail-FAQ.html
#
# Arguments sent by ArpAlert are :
# 1 : MAC Address
# 2 : IP Address
# 3 : supp (used with unathrq alert)
# 4 : Type of alert (cf arpalert.conf)
#

# Intruder MAC address
$intruder_MAC = $ARGV[0];

# Intruder IP address
$intruder_IP = $ARGV[1];

# Alert Type
$intruder_AlertType = $ARGV[3];

# Sender Email (should be update)
$mail{From} = 'Potential Intrusion <intrusion.detected@domain.com>';

# Separate multi receiver by coma (,) (should be update)
# $mail{To}   = 'Mail 1 <mail.one@domain.com>, Mail 2 <mail.two@domain.com>';
$mail{To}   = 'Jean Dupont <jdupond@domain.com>';

# SMTP server / IP or DNS name
$server = 'smtp.domain.com';


use Mail::Sendmail;

if ($server) {
	$mail{Smtp} = $server;
	print "Server set to: $server\n";
}

# Subject
$mail{Subject} = "[Warning] Intrusion Detection [Warning]";

# Body
$mail{Message} = "/!\\ Intruder Detected /!\\\n\n";
$mail{Message} .= "Intrusion time stamp : " . Mail::Sendmail::time_to_date() . "\n\n";
$mail{Message} .= "Intruder Ip Address : $intruder_IP\n";
$mail{Message} .= "Intruder MAC Address : $intruder_MAC\n";
$mail{Message} .= "Type of alert : $intruder_AlertType\n";

# Send Alert
if (sendmail %mail) {
	print "content of \$Mail::Sendmail::log:\n$Mail::Sendmail::log\n";
	if ($Mail::Sendmail::error) {
		print "content of \$Mail::Sendmail::error:\n$Mail::Sendmail::error\n";
	}
	print "ok 2\n";
}
else {
	print "\n!Error sending mail:\n$Mail::Sendmail::error\n";
	print "not ok 2\n";
}
