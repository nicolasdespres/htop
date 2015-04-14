/*
htop - darwin/Battery.c
Copyright (c) 2015, Nicolas Despres
Released under the GNU GPL, see the COPYING file
in the source distribution for its full text.

Based on freebsd/Battery.c
(C) 2014 Hisham H. Muhammad
Released under the GNU GPL, see the COPYING file
in the source distribution for its full text.
*/

#include "BatteryMeter.h"

void Battery_getData(double* level, ACPresence* isOnAC) {
   // TODO
   *level = -1;
   *isOnAC = AC_ERROR;
}
