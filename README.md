# NAME

icap-scan.pl - Scan a file for viruses by submitting it to an ICAP server

# SYNOPSIS

icap-scan.pl \[options\] icap://host\[:port\] filename

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

# DESCRIPTION

This script sends a file to an ICAP server for scanning. The response from the
ICAP server is printed to standard output.

# AUTHOR

Written by Kent Oyer <kent@mxguardian.net>
