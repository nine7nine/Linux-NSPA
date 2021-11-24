#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0
my $total = 0;
foreach (@ARGV) {
    @stat = stat $_ or die "$_: $!";
    $total += $stat[7];
}
print "$total\n";
