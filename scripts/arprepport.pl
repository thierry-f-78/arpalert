#!/usr/bin/perl -w
use strict;

my $mac = shift;
my $ip = shift;
system("echo \"$mac => $ip\" >> /tmp/ou.log");

