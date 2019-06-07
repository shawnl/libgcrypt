#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# (C) 2019 Shawn Landden
perl sha512-ppc8.pl linux64le sha512-ppc8.S
perl sha512-ppc8.pl linux64le sha256-ppc8.S
perl sha512-ppc8.pl linux64 sha512-ppc8be.S
perl sha512-ppc8.pl linux64 sha256-ppc8be.S
perl sha512-ppc8.pl linux32 sha512-ppc832.S
perl sha512-ppc8.pl linux32 sha256-ppc832.S
perl rijndael-ppc8.pl linux64le > rijndael-ppc8.S
perl rijndael-ppc8.pl linux64 > rijndael-ppc8be.S
perl rijndael-ppc8.pl linux32 > rijndael-ppc832.S
