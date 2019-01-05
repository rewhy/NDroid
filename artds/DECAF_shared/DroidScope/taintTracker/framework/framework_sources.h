/**
 * Created By Chenxiong Qian
 * date: 2014-12-3
 */
#ifndef __FRAMEWORK_SOURCES_H_
#define __FRAMEWORK_SOURCES_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "framework_hooks.h"
extern int global_count;
void frameworkSourceInit();
frameworkCallHooker hookSource(const char* methodName);

#ifdef __cplusplus
}
#endif

#endif
