/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.  *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * DS_Init.cpp
 *
 *  Created on: Oct 6, 2011
 *      Author: lok
 */

#include "DroidScope/DS_Init.h"
#include "DroidScope/DS_Common.h"
#include <stdlib.h>
/* ARTDS START */
#include <pthread.h>
#include "DroidScope/taintTracker/framework/framework_offsets.h"
#include "DroidScope/taintTracker/framework/framework_prop.h"
#include "DroidScope/taintTracker/jni/jnihook.h"
#include <unistd.h>
#include "DroidScope/taintTracker/nativejava.h"
#include "DroidScope/taintTracker/dex_offset.h"
#include "DECAF_shared/DroidScope/taintTracker/framework/framework_hooks.h"
#include "whitelist.h"
#include "jni/jnimethod.h"
#include "jni/libcmethod.h"
#include "../DECAF_linux_vmi.h"
#include "linuxAPI/Context.h"
/* ARTDS END */

/* ARTDS START */
void *myThreadFunc(void *arg){
	  printf("begin initFramework()\n");
    initFramework();
		printf("finish initFramework()\n");
    printf("begin init_apiprop()\n");
		init_apiprop();
		printf("finish init_apiprop()\n");
		printf("begin initDex()\n");
    initDex();
		printf("finish initDex()\n");
		printf("begin initNative()\n");
    initNative();
		printf("finish initNative()\n");
		printf("begin jnihook_init()\n");
    jnihook_init();
		printf("finish jnihook_init()\n");
		printf("begin libchook_init()\n");
    libchook_init();
		printf("finish libchook_init()\n");
		printf("begin libmhook_init()\n");
    libmhook_init();
		printf("finish libmhook_init()\n");

    printf("begin frameworkHooksInit()\n");
		frameworkHooksInit();
		printf("finish frameworkHooksInit()\n");
    printf("begin jnimethod_init()\n");
		jnimethod_init();
		printf("finish jnimethod_init()\n");
    printf("begin libcmethod_init()\n");
		libcmethod_init();
		printf("finish libcmethod_init()\n");
    init();

    return NULL;
}
/* ARTDS END */

void DS_init()
{
  DECAF_linux_vmi_init();
  context_init();
  atexit(DS_close);
    
  /* ARTDS START */
  pthread_t mythread;
  if (pthread_create(&mythread, NULL, myThreadFunc, NULL)){
      printf("DBG[]: error creating thread\n");
      abort();
  }
  /* ARTDS END */
}

void DS_close()
{

}
