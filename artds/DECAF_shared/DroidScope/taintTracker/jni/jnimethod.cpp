#include "../framework/framework_offsets.h"
#include "../framework/framework_hooks.h"
#include "../framework/framework_sources.h" // added -- zhouhao
#include "DECAF_shared/utils/OutputWrapper.h"
#include "DECAF_main.h"
#include <map>
#include <string.h>
#include "jnimethod.h"
#include "../dex_offset.h"
#include "../nativejava.h"
#include "../object.h"
#include "../argstaint.h"
#include "pointer.h"

using namespace std;

extern "C" unsigned * taintvalue;
map<char const*,JNIHook> jnihookmap;

#define FRAMEWORK_START 0x703bf000 // modified -- zhouhao

#define OFFSET_APP_EXECUTABLE 0x00006000 // this value is read from the oatdump file of the detected application -- zhouhao

#define GENERAL_TAINT 0x00000001 // added -- zhouhao

extern "C" gva_t * calltype;
extern "C" gva_t * breakpoint;
extern "C" frameworkCallHooker * javahooker;
extern "C" gva_t * calljava_offset;
extern "C" gva_t dexStartAddr;
extern "C" gva_t moduleStartAddr; // zhouhao
extern "C" gpid_t pid_wanted;
extern "C" int isPCInDex(gpid_t pid, gva_t pc);
extern gva_t * codeoffset;

extern "C" void   printtls();

void getframeworkcall(CPUState* env,int afterInvoking){
    if (!afterInvoking) {
        unsigned addr = 0;
        DECAF_read_mem(env,env->regs[2]+40,&addr,4);
        addr=addr&0xfffffffe;
				DECAF_printf("addr = %x\n", addr); // zhouhao
        (*breakpoint)=addr;
        DECAF_printf("Called a java method through JNI API, still in so now!\n");
        if (isPCInDex(pid_wanted,addr)) {
            DECAF_printf("pc is in dex"); // zhouhao
						*calltype=1;
            // unsigned offset=addr - dexStartAddr - 4096; // zhouhao
						unsigned offset = addr - moduleStartAddr + OFFSET_APP_EXECUTABLE; // zhouhao
						DECAF_printf("CallIntMethod offset: %x", offset); // zhouhao
            *calljava_offset=offset;
            char *className = 0;
            char *methodName = 0;
            char *arguments=0;
            int isStatic=-1;
            int len=-1;
            int ret=-1;
            if (dex_query(offset,&className,&methodName,&isStatic,&ret,&len,&arguments)==0) //args record
            {
                if (isStatic) {
                    int total=0;   //before process, arguments numbers
                    for (int i=0;i<len;i++) {
                        int j=arguments[i]-48;
                        if (total==0) {
                            if (j==9) {
                                unsigned taint=find(env->regs[3]);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if(taint)   
                                {
                                    insert_java(i+1,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                        if (total>0) {
                            if (j==9) {
                                unsigned ref=0;
                                DECAF_read_mem(env,env->regs[13]+16+(total-1)*4,&ref,4);
                                unsigned taint=find(ref);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if(taint)   
                                {
                                    insert_java(i+1,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                    }
                } else {
                    int total=1;
                    unsigned taint=find(env->regs[1]);
                    if (taint) {
                        insert_java(1,taint);
                    }
                    for (int i=0;i<len;i++) {
                        int j = arguments[i] - 48;
                        if (total==1) {
                            if (j==9) {
                                taint=find(env->regs[3]);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_java(i+2,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                        if (total>1) {
                            if (j==9) {
                                unsigned ref=0;
                                DECAF_read_mem(env,env->regs[13]+16+(total-2)*4,&ref,4);
                                taint=find(ref);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_java(i+2,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                    }
										DECAF_printf("Taint value: %d\n", taint); // zhouhao
                }
            }
        } else {
            *calltype=0xffffffff;
            unsigned offset=addr - FRAMEWORK_START;
						DECAF_printf("offset = %x\n", offset); // zhouhao
            *calljava_offset=offset;
            char *className = 0;
            char *methodName = 0;
            int isStatic=-1;
            int ret=-1;
            int len=-1;
            char *arguments=0;
            if(framework_query(offset,&className,&methodName,&isStatic,&ret,&len,&arguments)==0) //args record
            {
                (*codeoffset)=offset;
                if (isStatic) {
                    int total=0;   //before process, arguments numbers
                    for (int i=0;i<len;i++) {
                        int j=arguments[i]-48;
                        if (total==0) {
                            if (j==9) {
                                unsigned taint=find(env->regs[3]);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if(taint)   
                                {
                                    insert_java(i+1,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                        if (total>0) {
                            if (j==9) {
                                unsigned ref=0;
                                DECAF_read_mem(env,env->regs[13]+16+(total-1)*4,&ref,4);
                                unsigned taint=find(ref);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if(taint)   
                                {
                                    insert_java(i+1,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                    }
                }else {
                    int total=1;
										unsigned taint=find(env->regs[1]);
                    if (taint) {
                        DECAF_printf("taint is true\n"); // zhouhao
												insert_java(1,taint);
                    }
                    for (int i=0;i<len;i++) {
                        int j = arguments[i] - 48;
                        if (total==1) {
                            if (j==9) {
                                taint=find(env->regs[3]);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_java(i+2,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                        if (total>1) {
                            if (j==9) {
                                unsigned ref=0;
                                DECAF_read_mem(env,env->regs[13]+16+(total-2)*4,&ref,4);
                                taint=find(ref);
                                DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_java(i+2,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
                            continue;
                        }
                    }
										DECAF_printf("Taint value: %d\n", taint); // zhouhao
                }
            }
        }
    } else {
        DECAF_printf("Java method called through JNI API is over,in so now!\n");

        if (*calltype==1) {
            char *className = 0;
            char *methodName = 0;
            char *arguments=0;
            int isStatic=-1;
            int len=-1;
            int ret=-1;
            dex_query(*calljava_offset,&className,&methodName,&isStatic,&ret,&len,&arguments);
						if (ret==9) {
                unsigned taint = find_java(0);
                DECAF_printf("ret Taint value: %d\n", taint); // zhouhao
								if (taint) {
                    insert(taint,env->regs[0]);
                }
            }
            clear_java();
        }

        if (*calltype==0xffffffff) {
            char *className = 0;
            char *methodName = 0;
            char *arguments=0;
            int isStatic=-1;
            int len=-1;
            int ret=-1;
            framework_query(*calljava_offset,&className,&methodName,&isStatic,&ret,&len,&arguments);
						if (ret==9) {
                unsigned taint = find_java(0);
                DECAF_printf("ret Taint value: %d\n", taint); // zhouhao
								if (taint) {
                    insert(taint,env->regs[0]);
                }
            }

						(*codeoffset)=0;
            clear_java();
        }
        
        *breakpoint=0;
        *calltype=0;
        *calljava_offset=0;
    }
}

void newutfstr(CPUState* env,int afterInvoking){
    if (!afterInvoking) {
				// start -- zhouhao
				(*taintvalue) = find_pointer(env->regs[1]);
				if (*taintvalue == 0) {
					  insert_pointer(GENERAL_TAINT << global_count, env->regs[1]);
						global_count++;
				}
				// end -- zhouhao
				(*taintvalue)=find_pointer(env->regs[1]);
				DECAF_printf("newutfstr taintvalue: %d, global_count = %d\n", (*taintvalue), global_count); // zhouhao
    }else{
        if (*taintvalue) {
            insert(*taintvalue,env->regs[0]);
            DECAF_printf("Taint value: %x\n",*taintvalue);
            DECAF_printf("tainted !!!\n");
            *taintvalue=0;
        }
    }
}

void jnimethod_init()
{
    jnihookmap.insert(std::pair<char const *, JNIHook>("JNI::CallIntMethod",getframeworkcall));
		jnihookmap.insert(std::pair<char const *, JNIHook>("JNI::NewStringUTF",newutfstr));
}

JNIHook jnihook(char *name){
    std::map<char const*,JNIHook>::iterator it;
    
    for (it=jnihookmap.begin();it!=jnihookmap.end();++it) {
        if(strcmp(it->first,name)==0){
            return it->second;
        }
    }
    return NULL;
}
