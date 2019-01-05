/**
 * Created By Chenxiong Qian
 * date: 2014-12-2
 */
#ifndef __FRAMEWORK_HOOKS_H_
#define __FRAMEWORK_HOOKS_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cpu.h"
#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_shared/DroidScope/taintTracker/taint/TaintEngine.h"

typedef void (*frameworkCallHooker) (CPUState* env, int afterInvoking);
frameworkCallHooker hookFrameworkCall(const char* methodName);
void frameworkHooksInit();

uint32_t getPointerAddr(CPUState* env,gva_t addr); // added -- zhouhao

#ifdef __cplusplus
}
#endif

#endif
