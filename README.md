# Digest checksum tools
Tool name | Description
|:-- |:--
  md5sum    | Print or check MD5 checksums. 
  sha1sum   | Print or check SHA1 checksums.
  sha256sum | Print or check SHA256 checksums.
  sha384sum | Print or check SHA384 checksums.
  sha512sum | Print or check SHA512 checksums.

 Written in C++ for Windows platform. Functions are very similar with the tools in GNU coreutils. 
 All above tools share the same source code and only compile once and modify the .exe files' name to md5sum.exe, sha1sum.exe, sha256sum.exe etc.

https://github.com/fshb/digest-checksum-tools/

Copyright (c) 2019 Sun Hongbo (Felix)

# License
>Permission is hereby granted, free of charge, to any person obtaining a copy of this Software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify,  erge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

>***THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.***

# Usage
```
$> md5sum --help
Usage: md5sum [OPTION]... [FILE]...
Print or check MD5 checksums.

With no FILE, or when FILE is '-', read standard input.

  -b, --binary          read in binary mode (default)
  -c, --check           read MD5 sums from the FILEs and check them
      --tag             create a BSD-style checksum
  -t, --text            read in text mode

The following five options are useful only when verifying checksums:
      --ignore-missing  don't fail or report status for missing files
      --quiet           don't print OK for each successfully verified file
      --status          don't output anything, status code shows success
      --strict          exit non-zero for improperly formatted checksum lines
  -w, --warn            warn about improperly formatted checksum lines

      --help            display this help and exit
      --version         output version information and exit

The sums are computed as described in RFC 1321. 
When checking, the input should be a former output of this program. 
The default mode is to print a line with checksum, a space, a character 
indicating input mode ('*' for binary, ' ' for text or where binary is insignificant), 
and name for each FILE.
```
# Examples
```
$> md5sum -b file ed044a283dfc248c9fe14e1b4a012617 *file
$>_
```
```
$> md5sum -t file --tag
MD5 (file) = ed044a283dfc248c9fe14e1b4a012617
$>_
```
```
$> md5sum -b file > file.md5
$> md5sum -c file.md5
file: OK
$>_
```
```
$> md5sum -b file > file.md5
$> cat file.md5 | md5sum -c -
file: OK
$>_
```
