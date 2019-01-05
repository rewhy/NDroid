#include <tr1/unordered_map>
#include "register.h"

using namespace std::tr1;
unordered_map<unsigned int, struct tls_taint> tls_map;

void clear_map()
{
    unordered_map<unsigned int, struct tls_taint>::iterator it;
    for (it=tls_map.begin();it!=tls_map.end();++it) {
        (it->second).argsindex.clear();
        (it->second).java_args.clear();
    }
    tls_map.clear();
}

void insert_map(gva_t tid)
{
    struct tls_taint tls_t;

    tls_t.breakpoint=0;
    tls_t.calltype=0;
    tls_t.frameworkhooker=0;
    tls_t.jni_offset=0;
    tls_t.jnihooker=0;
    tls_t.jniset=false;
    tls_t.retform_framework=0;
    tls_t.retfrom_jni=0;
    tls_t.retvalue=0;
    tls_t.calljava_offset=0;
    tls_t.javahooker=0;
    tls_t.codeoffset=0;
    tls_t.taintvalue=0;

    memset(tls_t.taintD,0,sizeof(int)*16);
    memset(tls_t.taintRegs,0,sizeof(int)*16);
    memset(tls_t.taintS,0,sizeof(int)*32);
    tls_t.argsindex.clear();
    tls_t.java_args.clear();
    tls_map.insert(std::pair<unsigned int, struct tls_taint>(tid,tls_t));
}

struct tls_taint * find_map(gpid_t tid)
{
    unordered_map<unsigned int, struct tls_taint>::iterator it;
    it=tls_map.find(tid);
    if (it==tls_map.end()) {
        return NULL;
    }else{
        return &(it->second);
    }
}

