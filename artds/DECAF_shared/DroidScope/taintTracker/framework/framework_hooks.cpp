/**
 * Created By Chenxiong Qian
 * date: 2014-12-2
 */
#include "../object.h"
#include "framework_hooks.h"
#include "framework_offsets.h"
#include "DECAF_shared/utils/OutputWrapper.h"
#include "framework_sinks.h"
#include "framework_sources.h"
#include <map>
#include "framework_prop.h"

extern "C" gva_t * codeoffset;
extern "C" unsigned * taintvalue;

void generalFrameworkHooker (CPUState* env, int afterInvoking){
	  char *className = 0;
    char *methodName = 0;
    int isStatic=-1;
    int ret=-1;
    int len=-1;
    char *args=0;
    framework_query((*codeoffset),&className,&methodName,&isStatic,&ret,&len,&args);
    Args * argsmap=query_argsmap(methodName);

    if (!argsmap) {
        return;
    }

    if (!afterInvoking) {
        char *flag=NULL;
        if (isStatic) {
            int total=0;
            int i=0;
            flag=new char[len+1]; //flag records everyone's taint status ,from 0 (the return value)
            memset(flag,0,len+1);
            for (;i<len;i++) {  //i holds the arg sn, total holds the memory words' sum
                int j=args[i]-48;
                if (total==0) {
                    unsigned taint=0;
                    if (j==9) {
                        taint=find(env->regs[1]);
                        total++;
                    } else {   // j<=2
                        int l=0;   
                        for (;l<j;l++) {
                            taint|=getRegTaint(1+l);
                        }
                        total+=j;
                    }
                    if (taint) {
                        char* p=query_argseffect(argsmap,i+1);
                        if (p) {
                            (*taintvalue)|=taint;
                            flag[i+1]=1;
                            int k = 0;
                            for (;k<p[0];k++) {
                                flag[p[k+1]]=1;
                            }
                        }
                    }
                    continue;
                }
                if (total==1) {
                    unsigned taint=0;
                    if (j==9) {
                        taint=find(env->regs[2]);
                        total++;
                    } else {  // j<=2
                        int l=0;
                        for (;l<j;l++) {
                            taint|=getRegTaint(2+l);
                        }
                        total+=j;
                    }
                    if (taint) {
                        char* p=query_argseffect(argsmap,i+1);
                        if (p) {
                            (*taintvalue)|=taint;
                            flag[i+1]=1;
                            int k = 0;
                            for (;k<p[0];k++) {
                                flag[p[k+1]]=1;
                            }
                        }
                    }
                    continue;
                }
                if (total==2) {
                    unsigned taint=0;
                    if (j==9) {
                        taint=find(env->regs[3]);
                        total++;
                    } else { //j<=2
                        taint|=getRegTaint(3);
                        if (j==2) {
                            taint|=getTaint(env->regs[13]+16);
                        }
                        total += j;
                    }
                    if (taint) {
                        char* p=query_argseffect(argsmap,i+1);
                        if (p) {
                            (*taintvalue)|=taint;
                            flag[i+1]=1;
                            int k = 0;
                            for (;k<p[0];k++) {
                                flag[p[k+1]]=1;
                            }
                        }
                    }
                    continue;
                }
                if (total>2) {
                    unsigned taint=0;
                    if (j==9) {
                        unsigned ref=0;
                        DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                        taint=find(ref);
                        total++;
                    } else {
                        int l=0;
                        for (;l<4*j;l++) {
                            taint|=getTaint(env->regs[13] + 16 + (total-3)*4+l);
                        }
                        total+=j;
                    }
                    if (taint) {
                        char* p=query_argseffect(argsmap,i+1);
                        if (p) {
                            (*taintvalue)|=taint;
                            flag[i+1]=1;
                            int k = 0;
                            for (;k<p[0];k++) {
                                flag[p[k+1]]=1;
                            }
                        }
                    }
                    continue;
                }
            }

            DECAF_printf("%s taint bitmap:",methodName);
            for (int i=0;i<len+1;i++) {
                DECAF_printf(" %d",flag[i]);
            }
            DECAF_printf("\n");
            
        } else {
            int total=1;
            int i=0;
            flag=new char[len+2]; //flag records everyone's taint status ,from 0 (the return value)
            memset(flag,0,len+2);
            unsigned taint=find(env->regs[1]);
						// start -- zhouhao
						// a specific condition
						if (!taint
						&& (strcmp(methodName, "java.util.Iterator java.util.Collections$SynchronizedCollection.iterator()") == 0)) {
						    taint = find(getPointerAddr(env, env->regs[1]));
						}
						// dumpstring
						if (strcmp(methodName, "java.lang.Object android.content.ContextWrapper.getSystemService(java.lang.String)") == 0) {
							  dumpstring(env, env->regs[2]);
						}
						// end -- zhouhao
						DECAF_printf("addr=%d, taint=%d\n", env->regs[1], taint); // test -- zhouhao
            getPointerAddr(env, env->regs[1]); // test -- zhouhao
						if (taint) {
                char* p=query_argseffect(argsmap,1);
                if (p) {
                    (*taintvalue)|=taint;
                    flag[1]=1;
                    int k=0;
                    for (;k<p[0];k++) {
                        flag[p[k+1]]=1;
                    }
                }
            }

            for (; i < len; i++) {  //i holds the arg sn, total holds the words' sum
                int j=args[i]-48;
                if (total==1) {
                    taint=0;
                    if (j==9) {
                        taint=find(env->regs[2]);
                        total++;
                    } else {  //j<=2
                        int l=0;
                        for (;l<j;l++) {
                            taint|=getRegTaint(2+l);
                        }
                        total+=j;
                    }
                    if (taint) {
                        char* p=query_argseffect(argsmap,i+2);
                        if (p) {
                            (*taintvalue)|=taint;
                            flag[i+2]=1;
                            int k = 0;
                            for (;k<p[0];k++) {
                                flag[p[k+1]]=1;
                            }
                        }
                    }
                    continue;
                }
                if (total==2) {
                    taint=0;
                    if (j==9) {
                        taint=find(env->regs[3]);
                        total++;
                    } else {
                        taint|=getRegTaint(3);
                        if (j==2) {
                            taint|=getTaint(env->regs[13]+16);
                        }
                        total += j;
                    }
                    if (taint) {
                        char* p=query_argseffect(argsmap,i+2);
                        if (p) {
                            (*taintvalue)|=taint;
                            flag[i+2]=1;
                            int k = 0;
                            for (;k<p[0];k++) {
                                flag[p[k+1]]=1;
                            }
                        }
                    }
                    continue;
                }
                if (total>2) {
                    taint=0;
                    if (j==9) {
                        unsigned ref=0;
                        DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                        taint=find(ref);
                        total++;
                    } else {
                        int l=0;
                        for (;l<4*j;l++) {
                            taint|=getTaint(env->regs[13] + 16 + (total-3)*4+l);
                        }
                        total+=j;
                    }
                    if (taint) {
                        char* p=query_argseffect(argsmap,i+2);
                        if (p) {
                            (*taintvalue)|=taint;
                            flag[i+2]=1;
                            int k = 0;
                            for (;k<p[0];k++) {
                                flag[p[k+1]]=1;
                            }
                        }
                    }
                    continue;
                }
            }

						// start -- zhouhao
						// DECAF_printf("%d\n", strcmp(methodName, "boolean java.util.Collections$SynchronizedCollection.add(java.lang.Object)"));
						if(strcmp(methodName, "boolean java.util.Collections$SynchronizedCollection.add(java.lang.Object)") == 0) {
                int tmp_sum = 0;
								for(int tmp_index = 0; tmp_index < len + 2; tmp_index++) {
									  tmp_sum += flag[tmp_index];
								}
								if(tmp_sum > 0) {
									  flag[1] = 1;
								}
								// DECAF_printf("taint value: %d\n", *taintvalue);
						}
						// end -- zhouhao

            DECAF_printf("%s taint bitmap:",methodName);
            for (int i=0;i<len+2;i++) {
                DECAF_printf(" %d",flag[i]);
            }
            DECAF_printf("\n");
        }


        if (isStatic) {
            int total=0;
            int i=0;
            for (;i<len;i++) {
                int j=args[i]-48;
                if (total==0) {
                    if (j==9) {
                        if (flag[i+1]) {
                            insert((*taintvalue),env->regs[1]);
                        }
                        total++;
                    }else{
                        total+=j;
                    }
                    continue;
                }
                if (total==1) {
                    if (j==9) {
                        if (flag[i+1]) {
                            insert((*taintvalue),env->regs[2]);
                        }
                        total++;
                    }else{
                        total+=j;
                    }
                    continue;
                }
                if (total==2) {
                    if (j==9) {
                        if (flag[i+1]) {
                            insert((*taintvalue),env->regs[3]);
                        }
                        total++;
                    }else{
                        total+=j;
                    }
                    continue;
                }
                if (total>2) {
                    if (j==9) {
                        if (flag[i+1]) {
                            unsigned ref=0;
                            DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                            insert((*taintvalue),ref);
                        }
                        total++;
                    }else{
                        total+=j;
                    }
                    continue;
                }
            }
        }else{
            int total=1;
            int i=0;
            if (flag[1]) {
                insert((*taintvalue),env->regs[1]);
								DECAF_printf("insert taint value env->regs[1] = %d\n", *taintvalue); // test -- zhouhao
            }
						// start -- zhouhao
						// a specific condition
						if (flag[1] && strcmp(methodName, "boolean java.util.Collections$SynchronizedCollection.add(java.lang.Object)") == 0) {
							  insert((*taintvalue), getPointerAddr(env, env->regs[1]));
						}
						// end -- zhouhao
            for (;i<len;i++) {
                int j=args[i]-48;
                if (total==1) {
                    if (j==9) {
                        if (flag[i+2]) {
                            insert((*taintvalue),env->regs[2]);
                        }
                        total++;
                    }else{
                        total+=j;
                    }
                    continue;
                }
                if (total==2) {
                    if (j==9) {
                        if (flag[i+2]) {
                            insert((*taintvalue),env->regs[3]);
                        }
                        total++;
                    }else{
                        total+=j;
                    }
                    continue;
                }
                if (total>2) {
                    if (j==9) {
                        if (flag[i+2]) {
                            unsigned ref=0;
                            DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                            insert((*taintvalue),ref);
                        }
                        total++;
                    } else {
                        total+=j;
                    }
                    continue;
                }
            }
        }

        if (!flag[0]) {
            (*taintvalue)=0;
        }
        delete flag;
    }else{
        if (*taintvalue) {
            if (ret==9) {
                insert(*taintvalue,env->regs[0]);
								// DECAF_printf("ret from framework, Taint value : %d\n", *taintvalue); // zhouhao
            } else if (ret==1) {
                setRegTaint(0,*taintvalue);
								// DECAF_printf("ret from framework, Taint value : %d\n", *taintvalue); // zhouhao
            }else{
                setRegTaint(0,*taintvalue);
                setRegTaint(1,*taintvalue);
								// DECAF_printf("ret from framework, Taint value : %d\n", *taintvalue); // zhouhao
            }
        }
				else {
						// DECAF_printf("ret from framework, Taint value is 0\n"); // zhouhao
				}
        *taintvalue=0;
    }
}

frameworkCallHooker hookFrameworkCall(const char* methodName){

    frameworkCallHooker frameworkCH = NULL;

    frameworkCH = hookSource(methodName);
    if (frameworkCH != NULL){
        goto fin;
    }

    frameworkCH = hookSink(methodName);
    if (frameworkCH != NULL){
        goto fin;
    }

    frameworkCH = generalFrameworkHooker;

fin:
    return frameworkCH;
}

void frameworkHooksInit(){
    frameworkSourceInit();
    frameworkSinkInit();
}

// start -- zhouhao
uint32_t getPointerAddr(CPUState* env,gva_t addr)
{
		uint32_t pointer=0;
		DECAF_read_mem(env, addr, &pointer, sizeof(pointer));
		DECAF_printf("pointer addr = %lu\n", pointer);
		return pointer;
}
// end -- zhouhao
