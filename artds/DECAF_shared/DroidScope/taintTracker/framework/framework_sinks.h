/**
 * Created By Chenxiong Qian
 * date: 2014-12-3
 */
#ifndef __FRAMEWORK_SINKS_H_
#define __FRAMEWORK_SINKS_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "framework_hooks.h"

frameworkCallHooker hookSink(const char* methodName);
void frameworkSinkInit();
void dumpstring(CPUState* env,gva_t addr);

#ifdef __cplusplus
}
#endif

#endif
