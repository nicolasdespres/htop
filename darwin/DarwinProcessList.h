/* Do not edit this file. It was automatically generated. */

#ifndef HEADER_DarwinProcessList
#define HEADER_DarwinProcessList
/*
htop - DarwinProcessList.h
Copyright (c) 2015, Nicolas Despres
Released under the GNU GPL, see the COPYING file
in the source distribution for its full text.

Based on FreeBSDProcessList.h
(C) 2014 Hisham H. Muhammad
Released under the GNU GPL, see the COPYING file
in the source distribution for its full text.
*/


typedef struct CPUData_ {
   unsigned long long int totalTime;
   unsigned long long int totalPeriod;
} CPUData;

typedef struct DarwinProcessList_ {
   ProcessList super;

   CPUData* cpus;

} DarwinProcessList;


ProcessList* ProcessList_new(UsersTable* usersTable, Hashtable* pidWhiteList, uid_t userId);

void ProcessList_delete(ProcessList* this);

void ProcessList_goThroughEntries(ProcessList* this);

#endif
