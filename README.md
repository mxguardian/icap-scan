# NAME

icap-scan.pl - Scan a file for viruses by submitting it to an ICAP server

# SYNOPSIS

icap-scan.pl \[options\] icap://host\[:port\] filespec...

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

# DESCRIPTION

This script sends a file (or files) to an ICAP server for scanning. Directories are scanned recursively.
Files larger than $max\_file\_size are skipped.

# AUTHOR

Written by Kent Oyer <kent@mxguardian.net>

# COPYRIGHT AND LICENSE

    Copyright (c) 2023 MXGuardian LLC. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance
    with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

# SEE ALSO

https://www.mxguardian.net
