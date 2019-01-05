#include "../framework/framework_offsets.h"
#include "../framework/framework_hooks.h"
#include "DECAF_shared/utils/OutputWrapper.h"
#include "DECAF_main.h"
#include <map>
#include <string.h>
#include "libcmethod.h"
#include "pointer.h"

using namespace std;

map<char const*,LibcHook> libchookmap;

extern "C" unsigned * taintvalue;

void sprintfhooker(CPUState* env,int afterInvoking)
{
     if (!afterInvoking) {
         int tValue=getRegTaint(2);
				 if (tValue) {
             insert_pointer(tValue,env->regs[0]);
             DECAF_printf("Taint value: %x\n",tValue);
             DECAF_printf("tainted !!!\n");
         }
    } 
}

void libcmethod_init()
{
    libchookmap.insert(std::pair<char const *, LibcHook>("sprintf",sprintfhooker));
}

LibcHook libchook(char *name){

    std::map<char const*,LibcHook>::iterator it;
    for (it=libchookmap.begin();it!=libchookmap.end();++it) {
        if(strcmp(it->first,name)==0){
            return it->second;
        }
    }
    return NULL;
}
