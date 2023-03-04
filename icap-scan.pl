#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use List::Util qw(min max);
use Getopt::Std;
use Pod::Usage;

=head1 NAME

icap-scan.pl - Scan a file for viruses by submitting it to an ICAP server

=head1 SYNOPSIS

icap-scan.pl [options] icap://host[:port] filespec...

 Options:
   -h   help
   -p   use preview mode if available
   -v   verbose

 Exit codes:
   0    No virus found
   1    Virus found
   2    Invalid command line arguments
   111  Connection refused
   255  ICAP server error

=head1 DESCRIPTION

This script sends a file (or files) to an ICAP server for scanning. Directories are scanned recursively.
Files larger than $max_file_size are skipped.

=head1 AUTHOR

Written by Kent Oyer <kent@mxguardian.net>

=head1 COPYRIGHT AND LICENSE

 Copyright (c) 2023 MXGuardian LLC. All rights reserved.

 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance
 with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

=head1 SEE ALSO

https://www.mxguardian.net

=cut

# Initialize variables
my $max_chunk_size = 4096;
my $max_file_size = 50000000;

# DO NOT EDIT BELOW THIS LINE
my %opts;
getopts('hpv', \%opts) or pod2usage(2);
pod2usage(0) if $opts{h};
my $verbose = $opts{v};
my $use_preview = $opts{p};
my $preview_size = undef;

# extract host and port from URL on command line
my $url = shift; defined($url) && $url =~ m{^icap://([^/:]+)(?::(\d+))?} or pod2usage("Invalid URL");
my $icap_host = $1;
my $icap_port = $2 || 1344;

# Set up ICAP server connection
my $icap_socket = IO::Socket::INET->new(
    PeerAddr => $icap_host,
    PeerPort => $icap_port,
    Proto => 'tcp'
);
die "Can't connect to ICAP server $icap_host:$icap_port: $!\n" unless $icap_socket;

# Get OPTIONS from ICAP server
get_options();

my $rc = 0;
# scan all files on command line
while (my $filename = shift) {
    process($filename);
}

# Close the ICAP socket
close($icap_socket);

exit $rc;

#
# Subroutines
#

# Process files and directories recursively
sub process {
    my $filename = shift;
    if (-d $filename) {
        opendir(my $dir_handle, $filename) or die "Can't open directory $filename: $!\n";
        my @files = readdir($dir_handle);
        closedir($dir_handle);
        foreach my $file (@files) {
            next if $file eq '.' || $file eq '..';
            process("$filename/$file");
        }
    } elsif (-f $filename ) {
        # get file size
        my $size = -s $filename;
        if ( $size < $max_file_size ) {
            # scan file
            my $infected = scan_file($filename);
            $rc = 1 if $infected;
        } else {
            # skip file
            print "Skipping $filename (size $size exceeds limit of $max_file_size)\n";
        }
    } else {
        # skip non-files
        print "Skipping $filename (not a file or directory)\n";
    }
}

# Submit a single file to the ICAP server for scanning. Returns 1 if the file is infected, 0 otherwise.
sub scan_file {
    my $filename = shift;
    open(my $file_handle, '<', $filename) or die "Can't open file $filename: $!\n";

    # Send ICAP request
    my $response_headers = "HTTP/1.1 200 OK\r\n" .
        "content-disposition: attachment; filename=\"$filename\"\r\n" .
        "\r\n";
    my $encapsulated = sprintf("res-hdr=0, res-body=%d",length($response_headers));
    my $icap_request = "RESPMOD $url ICAP/1.0\r\n" .
        "Host: $icap_host\r\n" .
        "Allow: 204\r\n" .
        "Preview: $preview_size\r\n" .
        "Encapsulated: $encapsulated\r\n" .
        "\r\n";
    send_data($icap_request);
    send_data($response_headers);

    my $threat_info;
    my $icap_status;
    while ( !defined($icap_status) || $icap_status == 100 ) {
        if ( $use_preview && !defined($icap_status) ) {
            # Send file contents in chunks up to the preview size
            chunk_send($file_handle,$preview_size);
        } else {
            # Send the rest of the file
            chunk_send($file_handle);
        }

        # Receive ICAP status line (ignore blank lines left over from previous responses)
        my $icap_response;
        while ($icap_response = read_line()) {
            last unless $icap_response =~ /^[\r\n]/;
        }
        $icap_response =~ m{^ICAP/1.0 (\d+)} or die "Invalid ICAP response: $icap_response\n";
        $icap_status = $1;
        die "ICAP server returned error $icap_status\n" if $icap_status !~ /^[12]/;

        # Receive ICAP response headers
        while (my $line = read_line()) {
            last if $line =~ /^[\r\n]/;
            if ( $line =~ /^X-/ ) {
                $threat_info .= $line;
            }
        }

    }

    # Close the file
    close($file_handle);

    my $infected = 0;
    unless ( $icap_status == 204 ) {
        # Receive HTTP status line
        my $http_response = read_line();
        $http_response =~ m{^HTTP/1.1 (\d+)} or die "Invalid HTTP response\n";
        my $http_status = $1;

        # Receive HTTP response headers
        while (my $line = read_line()) {
            last if $line =~ /^[\r\n]/;
        }

        # Receive HTTP response body
        # todo: read data in chunks instead of line by line
        while (my $line = read_line()) {
            last if $line =~ /^[\r\n]/;
        }

        $infected = $http_status !~ /^2/;
    }

    if ( $infected ) {
        print "$filename is infected\n";
        print $threat_info;
    } else {
        print "$filename is OK\n";
    }

    return $infected;

}

sub send_data {
    my $data = shift;
    if ( $verbose ) {
        print ">> $_" foreach (split(/^/, $data));
    }
    $icap_socket->send($data);
}

sub chunk_send {
    my $file_handle = shift;
    my $max = shift;
    my $bytes_sent = 0;
    while (1) {
        my $fetch_bytes = defined($max) ? min( $max-$bytes_sent, $max_chunk_size ) : $max_chunk_size;
        if ( !$fetch_bytes ) {
            send_data("0\r\n\r\n");
            return;
        }
        my $bytes_read = read($file_handle, my $buffer, $fetch_bytes);
        if ( !$bytes_read ) {
            send_data("0; ieof\r\n\r\n");
            return;
        }
        my $chunk_header = sprintf("%x\r\n", length($buffer));
        my $chunk_footer = "\r\n";
        $icap_socket->send($chunk_header);
        $icap_socket->send($buffer);
        $icap_socket->send($chunk_footer);
        print ">> $chunk_header>> ...DATA...$chunk_footer" if $verbose;
        $bytes_sent += $bytes_read;
    }
}

sub read_line {
    my $line = <$icap_socket>;
    print "<< $line" if $verbose;
    return $line;
}

sub get_options {
    my $icap_request = "OPTIONS $url ICAP/1.0\r\n".
                       "Host: $icap_host\r\n".
                       "\r\n";
    send_data($icap_request);
    my $icap_response = <$icap_socket>;
    print ">> $icap_response";
    $icap_response =~ m{^ICAP/1.0 (\d+)} or die "Invalid ICAP response\n";
    my $icap_status = $1;
    die "ICAP server returned error $icap_status\n" if $icap_status !~ /^2/;
    # Receive ICAP response headers
    while (my $line = read_line()) {
        if ($line =~ /^Preview: (\d+)/) {
            $preview_size = $1;
            print "Set preview size to $preview_size\n" if $verbose;
        }
        last if $line =~ /^[\r\n]/;
    }
}
