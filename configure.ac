#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libklscte35], [1.0], [stoth@kernellabs.com])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99

AC_PROG_RANLIB
AC_PROG_LIBTOOL

if test `uname -s` = "Darwin"
then
CFLAGS+=" -I/usr/local/include"
LDFLAGS+=" -L/usr/local/lib"
fi

# We always build with -fPIC in case our static libraries end up
# being linked into a consumer's shared library
AC_MSG_CHECKING(whether fPIC compiler option is accepted)
SAVED_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fPIC -Werror"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [return 0;])],
    [AC_MSG_RESULT(yes)
     CFLAGS="$SAVED_CFLAGS -fPIC"],
    [AC_MSG_RESULT(no)
     CFLAGS="$SAVED_CFLAGS"])

# Determine whether to include support for libjson-c
AC_ARG_WITH([libjsonc],
  [AS_HELP_STRING([--with-libjsonc],
    [support handling JSON files @<:@default=check@:>@])],
  [],
  [with_libjsonc=check])
AS_CASE(["$with_libjsonc"],
  [yes], [PKG_CHECK_MODULES([libjsonc], [json-c], [HAVE_LIBJSONC=1])],
  [no], [HAVE_LIBJSONC=0],
  [PKG_CHECK_MODULES([libjsonc], [json-c], [HAVE_LIBJSONC=1], [HAVE_LIBJSONC=0])])
AM_CONDITIONAL([USE_LIBJSONC], [test "$with_libjsonc" != no -a "$HAVE_LIBJSONC" -eq 1])

# Determine whether to include support for libklvanc
AC_ARG_WITH([libklvanc],
  [AS_HELP_STRING([--with-libklvanc],
    [support conversion of SCTE-104 @<:@default=check@:>@])],
  [],
  [with_libklvanc=check])
AS_CASE(["$with_libklvanc"],
  [yes], [AC_CHECK_HEADERS([libklvanc/vanc.h],[HAVE_LIBKLVANC=1])],
  [no], [HAVE_LIBKLVANC=0],
  [AC_CHECK_HEADERS([libklvanc/vanc.h],[HAVE_LIBKLVANC=1],[HAVE_LIBKLVANC=0])])
AM_CONDITIONAL([USE_LIBKLVANC], [test "$with_libklvanc" != no -a "$HAVE_LIBKLVANC" -eq 1])
AM_COND_IF(USE_LIBKLVANC, AC_DEFINE(HAVE_LIBKLVANC, 1, [Include libklvanc support]))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strrchr])

AC_CONFIG_FILES([Makefile src/Makefile tools/Makefile])
AC_OUTPUT

# Add debug support
AC_ARG_ENABLE(debug,
  AS_HELP_STRING(
    [--enable-debug],
    [enable debugging, default: no]),
    [case "${enableval}" in
      yes) debug=true ;;
      no)  debug=false ;;
      *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
    esac],
    [debug=false])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")
AM_COND_IF(DEBUG,
    AC_DEFINE(DEBUG, 1, [Define to 0 if this is a release build]),
    AC_DEFINE(DEBUG, 0, [Define to 1 or higher if this is a debug build]))
