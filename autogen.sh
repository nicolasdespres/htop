#!/bin/sh

aclocal -I m4
autoconf
autoheader
for LIBTOOLIZE in glibtoolize libtoolize
do
  type $LIBTOOLIZE 2>/dev/null >/dev/null && break
done
$LIBTOOLIZE --copy --force
automake --add-missing --copy
