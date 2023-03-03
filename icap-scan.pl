#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use Getopt::Std;
use Pod::Usage;

=head1 NAME

icap-scan.pl - Scan a file for viruses by submitting it to an ICAP server

=head1 SYNOPSIS

icap-scan.pl [options] icap://host[:port] filename

 Options:
   -h   help
   -d   debug
   -o   send the OPTIONS command to the ICAP server

 Exit codes:
   0    File is clean
   1    File is infected
   2    Invalid command line arguments
   111  Connection refused
   255  ICAP server error

=head1 DESCRIPTION

This script sends a file to an ICAP server for scanning. The response from the
ICAP server is printed to standard output.

=head1 AUTHOR

Written by Kent Oyer <kent@mxguardian.net>

=cut

my %opts;
getopts('dho', \%opts) or pod2usage(2);
pod2usage(0) if $opts{h};
my $debug = $opts{d};

# extract host and port from URL on command line
my $url = $ARGV[0]; defined($url) && $url =~ m{^icap://([^/:]+)(?::(\d+))?} or pod2usage("Invalid URL");
my $icap_host = $1;
my $icap_port = $2 || 1344;

# Set up ICAP server connection
my $icap_socket = IO::Socket::INET->new(
    PeerAddr => $icap_host,
    PeerPort => $icap_port,
    Proto => 'tcp'
);
die "Can't connect to ICAP server $icap_host:$icap_port: $!\n" unless $icap_socket;

# Send OPTIONS command if requested
send_options() if $opts{o};

# Open the file to be scanned
my $filename = $ARGV[1] or pod2usage("Filename is required");
die "File not found: $filename\n" unless -f $filename;
open(my $file_handle, '<', $filename) or die "Can't open file $filename: $!\n";

my $response_headers = "HTTP/1.1 200 OK\r\n" .
                       "\r\n";
#                       "content-disposition: attachment; filename=\"$filename\"\r\n" .
#                       "content-type: application/octet-stream\r\n" .

my $encapsulated = sprintf("res-hdr=0, res-body=%d",length($response_headers));

# Send ICAP request
my $icap_request = "RESPMOD $url ICAP/1.0\r\n" .
                   "Host: $icap_host\r\n" .
                   "Allow: 204\r\n" .
                   "Encapsulated: $encapsulated\r\n" .
                   "\r\n";

#                   "Transfer-Encoding: chunked\r\n" .
#                   "Preview: 1024\r\n" .
                   
send_data($icap_request);
send_data($response_headers);

# Send request body (file contents) in chunks
my $chunk_size = 4096;
while (my $chunk = read($file_handle, my $buffer, $chunk_size)) {
    my $chunk_header = sprintf("%x\r\n", length($buffer));
    my $chunk_footer = "\r\n";
    $icap_socket->send($chunk_header);
    $icap_socket->send($buffer);
    $icap_socket->send($chunk_footer);
    print "> $chunk_header> ...DATA...\r\n" if $debug;
}

# Send final chunk and trailer
send_data("0\r\n\r\n");

# Close the file
close($file_handle);

# Receive ICAP response
my $icap_response = <$icap_socket>;
print $icap_response;
$icap_response =~ m{^ICAP/1.0 (\d+)} or die "Invalid ICAP response\n";
my $icap_status = $1;
die "ICAP server returned error $icap_status\n" if $icap_status !~ /^2/;

# Receive ICAP response headers
while (my $line = <$icap_socket>) {
    print $line;
    last if $line =~ /^[\r\n]/;
}
exit(0) if $icap_status == 204; # No content

# Receive HTTP response headers
my $http_response = <$icap_socket>;
print $http_response;
$http_response =~ m{^HTTP/1.1 (\d+)} or die "Invalid HTTP response\n";
my $http_status = $1;

# Receive HTTP response body
while (my $line = <$icap_socket>) {
    print $line;
    last if $line =~ /^[\r\n]/;
}

while (my $line = <$icap_socket>) {
    print $line;
    last if $line =~ /^0[\r\n]/;
}

# Close the ICAP socket
close($icap_socket);

exit($http_status =~ /^2/ ? 0 : 1);

sub send_data {
    my $data = shift;
    if ( $debug ) {
        print "> $_" foreach (split(/^/, $data));
    }
    $icap_socket->send($data);
}

sub send_options {
    my $icap_request = "OPTIONS $url ICAP/1.0\r\n".
                       "Host: $icap_host\r\n".
                       "\r\n";
    send_data($icap_request);
    my $icap_response = <$icap_socket>;
    print $icap_response;
    $icap_response =~ m{^ICAP/1.0 (\d+)} or die "Invalid ICAP response\n";
    my $icap_status = $1;
    die "ICAP server returned error $icap_status\n" if $icap_status !~ /^2/;
    # Receive ICAP response headers
    while (my $line = <$icap_socket>) {
        print $line;
        last if $line =~ /^[\r\n]/;
    }
    exit(0);
}
