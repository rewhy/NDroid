#include "DECAF_shared/DECAF_types.h"
#include "jni/jnimethod.h"
#include "framework/framework_hooks.h"


#ifdef __cplusplus

#include <map>
using namespace std;

struct tls_taint{
    int taintRegs[16];
    int taintD[16];
    int taintS[32];

    gva_t retform_framework;
    frameworkCallHooker frameworkhooker;
    gva_t codeoffset;

    unsigned taintvalue;

    bool jniset;

    gva_t jni_offset;
    gva_t retfrom_jni;
    map<int,unsigned> argsindex;

    gva_t breakpoint;
    gva_t calltype;

    JNIHook jnihooker;
    gva_t calljava_offset;
    frameworkCallHooker javahooker;
    gva_t retvalue;
    map<int,unsigned> java_args;
};

extern "C"
{
#endif

struct tls_taint * find_map(gpid_t tid);
void insert_map(gva_t tid);
void clear_map();
#ifdef __cplusplus
}
#endif
