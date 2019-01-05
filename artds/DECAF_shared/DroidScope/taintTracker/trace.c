#include "LinuxAPI.h" 
#include "linuxAPI/ProcessInfo.h"
#include "DECAF_shared/DECAF_callback.h"
#include "DECAF_shared/utils/SimpleCallback.h"
#include "DECAF_shared/utils/OutputWrapper.h"
#include "linuxAPI/Context.h"
#include "trace.h"
#include "DECAF_shared/DroidScope/taintTracker/disas/disas_arm.h"
#include "DECAF_shared/DroidScope/taintTracker/framework/framework_offsets.h"
#include "DECAF_shared/DroidScope/taintTracker/framework/framework_hooks.h"
#include "DECAF_shared/DroidScope/taintTracker/framework/framework_sources.h"
#include "../DS_Common.h"
#include "taint/TaintEngine.h"
#include "whitelist.h"
#include "jni/jnihook.h"
#include "jni/jnimethod.h"
#include "argstaint.h"
#include "dex_offset.h"
#include "nativejava.h"
#include "object.h"
#include "register.h"
#include "jni/libcmethod.h"
#include "jni/pointer.h"

#ifdef TARGET_ARM

#define suspicious_hard_code 0x000ba0d0 // zhouhao -- related to a specific method in libart.so
#define OFFSET_BOOT_QUICK_RESOLUTION_TRAMPOLINE 0x01abc048 // modified -- zhouhao (boot_oatdump.txt)
#define OFFSET_BOOT_QUICK_IMT_cONFLICT_TRAMPOLINE 0x01abc040 // added -- zhouhao (boot_oatdump.txt)

#define FRAMEWORK_START 0x703bf000 // modified -- zhouhao
#define FRAMEWORK_END 0x733321E0 // modified -- zhouhao

#define OFFSET_ART_QUICK_RESOLUTION_TRAMPOLINE_START 0x000A3CC0 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_RESOLUTION_TRAMPOLINE_END   0x000A3CDA // modified -- zhouhao  (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_START  0x000A2780 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_END  0x000A27A0 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_WITH_ACCESS_CHECK_START  0x000A27C0 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_WITH_ACCESS_CHECK_END  0x000A27E0 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_STATIC_TRAMPOLINE_WITH_ACCESS_CHECK_START  0x000A2800 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_STATIC_TRAMPOLINE_WITH_ACCESS_CHECK_END  0x000A2820 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_DIRECT_TRAMPOLINE_WITH_ACCESS_CHECK_START  0x000A2840 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_DIRECT_TRAMPOLINE_WITH_ACCESS_CHECK_END  0x000A2860 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_SUPER_TRAMPOLINE_WITH_ACCESS_CHECK_START  0x000A2880 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_SUPER_TRAMPOLINE_WITH_ACCESS_CHECK_END  0x000A28A0 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_VIRTUAL_TRAMPOLINE_WITH_ACCESS_CHECK_START  0x000A28C0 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_QUICK_INVOKE_VIRTUAL_TRAMPOLINE_WITH_ACCESS_CHECK_END  0x000A28E0 // modified -- zhouhao (libart_objdump.txt)
#define OFFSET_ART_JNI_DLSYM_LOOKUP_STUB_START 0x000A23D0 // modified -- zhouhao
#define OFFSET_ART_JNI_DLSYM_LOOKUP_STUB_END 0x000A23E2 // modified -- zhouhao

#define OFFSET_APP_EXECUTABLE 0x00006000 // this value is read from the oatdump file of the detected application -- zhouhao

static DECAF_Handle contextIBHandle;
static DECAF_Handle contextBEHandle;
static DECAF_Handle contextBBHandle;
static bool once = true;
static bool flag_fork = true;
static bool flag_flush = true;

target_ulong uid_wanted = 0xffffffff;
gpid_t pid_wanted = 0xffffffff;

gva_t LAST_INS_ADDR = 0;
gva_t LAST_CALL_ADDR = 0;

gva_t libArtStartAddress = 0;
gva_t libArtEndAddress = 0;

static gva_t cacheDexStartAddr = 0;
static gva_t cacheDexEndAddr = 0;

static gva_t curTID=-1;
static gva_t curTGID=-1;

gva_t dexStartAddr = 0;
gva_t dexEndAddr = 0;
gva_t moduleStartAddr = 0; // added -- zhouhao
gva_t moduleEndAddr = 0; // add -- zhouhao

extern gva_t * retfrom_framework;
extern frameworkCallHooker * frameworkhooker;
extern gva_t * codeoffset;

extern bool * jniset;

extern gva_t * jni_offset;
extern gva_t * retfrom_jni;
extern JNIHook * jnihooker;

extern gva_t * breakpoint;
extern gva_t * calltype;

extern gva_t * calljava_offset;
extern frameworkCallHooker * javahooker;
extern gva_t * retvalue;

extern unsigned * taintvalue;

void printtls()
{
    DECAF_printf("-------------------------------------------------------\n");
    DECAF_printf("Current thread: %d\n",curTID);
    DECAF_printf("jniset: %d\n",*jniset);
    DECAF_printf("jni_offset: %d\n",*jni_offset);
    DECAF_printf("retfrom_framework: %x\n",*retfrom_framework);
    DECAF_printf("retfrom_jni: %x\n",*retfrom_jni);
    DECAF_printf("breakpoint: %x\n",*breakpoint);
    DECAF_printf("jnihooker: %x\n",*jnihooker);
    DECAF_printf("frameworkhooker: %x\n",*frameworkhooker);
    DECAF_printf("taintvalue: %d\n",*taintvalue);
    DECAF_printf("codeoffset: %d\n",*codeoffset);
    DECAF_printf("calltype: %x\n",*calltype);
    DECAF_printf("retvalue: %x\n",*retvalue);
    DECAF_printf("javahooker: %x\n",*javahooker);
    DECAF_printf("calljava_offset: %d\n",*calljava_offset);
    DECAF_printf("-------------------------------------------------------\n");
}

void getDexStartAddr(gpid_t pid, gva_t pc){
    char moduleName[128];
    moduleName[0] = '\0';
    gva_t startAddr = -1;
    gva_t endAddr = -1;
    gva_t pc_even = pc & 0xfffffffe;
    getExecutableModuleInfo(pid, moduleName, 128, &startAddr, &endAddr, pc_even);
    moduleStartAddr = startAddr; // zhouhao
		moduleEndAddr = endAddr; // zhouhao
		// DECAF_printf("ModuleStartAddr: %x\tModuleEndAddr = %x\n", startAddr, endAddr); // zhouhao
		getModuleStartEndAddress(pid,&dexStartAddr,&dexEndAddr,moduleName);
		// DECAF_printf("DexStartAddr = %x\tDexEndAddr = %x\n", dexStartAddr, dexEndAddr); // zhouhao
}

int isPCInDex(gpid_t pid, gva_t pc){
    assert(pid > 0);
    if (pc >= 0xc0000000 || pc <= 0){
        return (0);
    }
#if 0
		/* annotated by zhouhao
    if (pc >= cacheDexStartAddr && pc <= cacheDexEndAddr){
        return (1);
    }
		*/
#else
    char moduleName[128];
    moduleName[0] = '\0';
    gva_t startAddr = -1;
    gva_t endAddr = -1;
    gva_t pc_even = pc & 0xfffffffe;
    getExecutableModuleInfo(pid, moduleName, 128, &startAddr, &endAddr, pc_even);

    if (moduleName[0] == '\0'){
        return (0);
    }
		
    int len = strlen(moduleName);
    char *dexSuffix = ".dex";
    if (len > 4 && strcmp((moduleName+len-4),dexSuffix) == 0){
        cacheDexStartAddr = startAddr;
        cacheDexEndAddr = endAddr;
				// DECAF_printf("isPCInDex(): DexName = %s, DexStartAddr = %x, DexEndAddr = %x\n", moduleName, cacheDexStartAddr, cacheDexEndAddr); // zhouhao
        return (1);
    }
#endif
    return (0);
}

bool isInJNI(gpid_t pid, gva_t pc)
{
    assert(pid > 0);

    if (pc >= 0xc0000000 || pc <= 0){
        return (0);
    }
    char moduleName[128];
    moduleName[0] = '\0';
    gva_t startAddr = -1;
    gva_t endAddr = -1;
    gva_t pc_even = pc & 0xfffffffe;
    getExecutableModuleInfo(pid, moduleName, 128, &startAddr, &endAddr, pc_even);

    if (moduleName[0] == '\0'){
        return (0);
    }

    int len = strlen(moduleName);
    char *soSuffix = ".so";
    if (len > 3 && (strcmp((moduleName+len-3), soSuffix) == 0) && (!isInList(moduleName))) {
			  // test -- zhouhao
				/*
				if(strcmp(moduleName, "/app/com.a-1/lib/arm/libhello-jni.so") == 0) {
            DECAF_printf("soLibraryName = %s, soStartAddr = %x, soEndAddr = %x, jniset = %d\n", moduleName, startAddr, endAddr, *jniset); // zhouhao
				}
				*/
				return 1;
    }

    return 0;
}

bool isInLib(gpid_t pid, gva_t pc, char * name,gva_t * startaddr){
    gva_t pc_even = pc & 0xfffffffe;
    gva_t startAddr = -1;
    gva_t endAddr = -1;
    getModuleStartEndAddress(pid,&startAddr,&endAddr,name);
    if (pc_even>=startAddr&&pc_even<=endAddr) {
        *startaddr=startAddr;
        return true;
    }
    return false;
}


int IBCondFunc (DECAF_callback_type_t cbType, gva_t curPC, gva_t nextPC)
{
    DEFENSIVE_CHECK1(cbType != DECAF_INSN_BEGIN_CB, 0);
    DEFENSIVE_CHECK1(pid_wanted == 0xffffffff, 0);

    gva_t cur_pc_even = curPC & 0xfffffffe;

    if(isBpHit(pid_wanted,cur_pc_even)){
        return 1;
    }
#if 0		
		if(cur_pc_even > libArtStartAddress && cur_pc_even < libArtEndAddress)
			DECAF_printf("IBCondFunc suspicious hard code: %x\t%d\n", (cur_pc_even-libArtStartAddress), (cur_pc_even-libArtStartAddress)); // zhouhao
#else
		if (libArtStartAddress!=0&&cur_pc_even==libArtStartAddress+suspicious_hard_code/*what does it mean? -- zhouhao*/) {
        return 1;
    }
#endif
    return (isPCInDex(pid_wanted, cur_pc_even) || isInJNI(pid_wanted, cur_pc_even));
}

void IBCallback(DECAF_Callback_Params* params)
{
	  // DECAF_printf("execute IBCallback() method ...\n"); // test -- zhouhao
		// DECAF_printf("jniset = %d\n", jniset); // test -- zhouhao

    DEFENSIVE_CHECK0(params == NULL);
    DEFENSIVE_CHECK0(pid_wanted == 0xffffffff);

    CPUState* env = params->ib.env;
    gva_t curPC = params->ib.cur_pc;
    gva_t cur_pc_even = curPC & 0xfffffffe;
   
    if (isThread(curTGID,curTID)) {
        if (cur_pc_even == LAST_INS_ADDR){
            return;
        }

        if(!setThread(curTID))
        {
						 return;
        }

        if (*jniset) {    // in callxxxmethods 
            if (cur_pc_even==(*breakpoint)) {
                DECAF_printf("Through JNI API called a java method from so, in java code now!\n");
                if (*calltype==1) {          //dex method   args update
                     char *className = 0;
                     char *methodName = 0;
                     char *arguments=0;
                     int isStatic=-1;
                     int len=-1;
                     int ret=-1;
                     if (dex_query(*calljava_offset,&className,&methodName,&isStatic,&ret,&len,&arguments)==0)
                     {
                         DECAF_printf("Java method in dex file \"%s\" is called!\n",methodName);
                         if (isStatic) {
                             int total=0;   //before process, arguments numbers
                             int i=0;
                             for (;i<len;i++) {
                                 int j=arguments[i]-48;
                                 if (total==0) {
                                     if (j==9) {
                                         unsigned taint=find_java(i+1);
                                         // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				 if(taint)
                                         {
                                             insert(taint,env->regs[1]);
                                         }
                                         total++;
                                     }else{
                                         total+=j;
                                     }
                                     continue;
                                 }

                                 if (total==1) {
                                     if (j==9) {
                                         unsigned taint=find_java(i+1);
																				 // DECAF_printf("Taint value: %d\n", taint); // zhouhao
                                         if (taint) {
                                             insert(taint,env->regs[2]);
                                         }
                                         total++;
                                     }else{
                                         total+=j;
                                     }
																		 continue;
                                 }
                                 if (total==2) {
                                     if (j==9) {
                                         unsigned taint=find_java(i+1);
                                         // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				 if (taint) {
                                             insert(taint,env->regs[3]);
                                         }
                                         total++;
                                     }else{
                                         total+=j;
                                     }
																		 continue;
                                 }
                                 if (total>2) {
                                     if (j==9) {
                                         unsigned taint=find_java(i+1);
                                         // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				 if (taint) {
                                             unsigned ref = 0;
                                             DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                                             insert(taint,ref);
                                         }
                                         total++;
                                     } else {
                                         total+=j;
                                     }
																		 continue;
                                 }
                             }
                         } else {
                             int total=1;
                             unsigned taint=find_java(1);
                             if (taint) {
                                 insert(taint,env->regs[1]);
                             }
                             int i=0;
                             for (;i<len;i++) {
                                 int j = arguments[i] - 48;
                                 if (total==1) {
                                     if (j==9) {
                                         taint=find_java(i+2);
                                         // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				 if (taint) {
                                             insert(taint,env->regs[2]);
                                         }
                                         total++;
                                     }else{
                                         total+=j;
                                     }
																		 continue;
                                 }
                                 if (total==2) {
                                     if (j==9) {
                                         taint=find_java(i+2);
                                         // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				 if (taint) {
                                             insert(taint,env->regs[3]);
                                         }
                                         total++;
                                     }else{
                                         total+=j;
                                     }
																		 continue;
                                 }
                                 if (total>2) {
                                     if (j==9) {
                                         taint=find_java(i+2); 
                                         // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				 if (taint) {
                                             unsigned ref=0;
                                             DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                                             insert(taint,ref);
                                         }
                                         total++;
                                     } else {
                                         total+=j;
                                     }
																		 continue;
                                 }
                             }
														 // DECAF_printf("Taint value: %d\n", taint); // zhouhao
                         }
                     }
                     goto dis;
                }
                if (*calltype==0xffffffff) { //framework api
                    char *className = 0;
                    char *methodName = 0;
                    char *arguments=0;
                    int isStatic=-1;
                    int len=-1;
                    int ret=-1;
                    if (framework_query(*calljava_offset,&className,&methodName,&isStatic,&ret,&len,&arguments)==0)
                    {
                        DECAF_printf("Java method of framework APIs \"%s\" is called!\n",methodName);
                        if (isStatic) {
                            int total=0;   //before process, arguments numbers
                            int i=0;
                            for (;i<len;i++) {
                                int j=arguments[i]-48;
                                if (total==0) {
                                    if (j==9) {
                                        unsigned taint=find_java(i+1);
                                        // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				if(taint)
                                        {
                                            insert(taint,env->regs[1]);
                                        }
                                        total++;
                                    }else{
                                        total+=j;
                                    }
																		continue;
                                }

                                if (total==1) {
                                    if (j==9) {
                                        unsigned taint=find_java(i+1);
                                        // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				if (taint) {
                                            insert(taint,env->regs[2]);
                                        }
                                        total++;
                                    }else{
                                        total+=j;
                                    }
																		continue;
                                }

                                if (total==2) {
                                    if (j==9) {
                                        unsigned taint=find_java(i+1);
                                        // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				if (taint) {
                                            insert(taint,env->regs[3]);
                                        }
                                        total++;
                                    }else{
                                        total+=j;
                                    }
																		continue;
                                }
                                if (total>2) {
                                    if (j==9) {
                                        unsigned taint=find_java(i+1);
                                        // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				if (taint) {
                                            unsigned ref = 0;
                                            DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                                            insert(taint,ref);
                                        }
                                        total++;
                                    } else {
                                        total+=j;
                                    }
																		continue;
                                }
                            }
                        } else {
                            int total=1;
                            unsigned taint=find_java(1);
                            if (taint) {
                                insert(taint,env->regs[1]);
														}
                            int i=0;
                            for (;i<len;i++) {
                                int j = arguments[i] - 48;
                                if (total==1) {
                                    if (j==9) {
                                        taint=find_java(i+2);
																				// DECAF_printf("Taint value: %d\n", taint); // zhouhao
                                        if (taint) {
                                            insert(taint,env->regs[2]);
                                        }
                                        total++;
                                    }else{
                                        total+=j;
                                    }
																		continue;
                                }
                                if (total==2) {
                                    if (j==9) {
                                        taint=find_java(i+2);
                                        // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				if (taint) {
                                            insert(taint,env->regs[3]);
                                        }
                                        total++;
                                    }else{
                                        total+=j;
                                    }
																		continue;
                                }
                                if (total>2) {
                                    if (j==9) {
                                        taint=find_java(i+2); 
                                        // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																				if (taint) {
                                            unsigned ref=0;
                                            DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                                            insert(taint,ref);
                                        }
                                        total++;
                                    } else {
                                        total+=j;
                                    }
																    continue;
                                }
                            }
														// DECAF_printf("Taint value: %d\n", taint); // zhouhao
                        }
                    }
                    (*javahooker)=hookFrameworkCall(methodName);
                    (*(*javahooker))(env,0);
										// (*(*javahooker))(env,1); // zhouhao
                    return;
                }
            }
        }

        if (*jniset) {
						if (cur_pc_even==libArtStartAddress+suspicious_hard_code) { 
								if (*calltype==0xffffffff&&(*javahooker!=0)) {
                    (*(*javahooker))(env,1);
                    char *className = 0;
                    char *methodName = 0;
                    char *arguments=0;
                    int isStatic=-1;
                    int len=-1;
                    int ret=-1;
                    framework_query(*calljava_offset,&className,&methodName,&isStatic,&ret,&len,&arguments);
                    DECAF_printf("Java method of frmaework API called through JNI API \"%s\" has returned!\n",methodName);

                    if (ret==9) {
                        unsigned taint=find(env->regs[0]);
                        // DECAF_printf("ret Taint value: %d\n", taint); // zhouhao
												if (taint) {
                            insert_java(0,taint);
                        }
										}

                    *javahooker=0;
                }

                if (*calltype==1) {
                    char *className = 0;
                    char *methodName = 0;
                    char *arguments=0;
                    int isStatic=-1;
                    int len=-1;
                    int ret=-1;
                    dex_query(*calljava_offset,&className,&methodName,&isStatic,&ret,&len,&arguments);
                    DECAF_printf("Java method in dex called through JNI API \"%s\" has returned!\n",methodName);
                    if (ret==9) {
                        unsigned taint=find(env->regs[0]);
												// DECAF_printf("ret Taint value: %d\n", taint); // zhouhao
                        if (taint) {
                            insert_java(0,taint);
                        }
										}

                }
                return;
            }
        }

        if ((!isPCInDex(pid_wanted, cur_pc_even))&&(!isInJNI(pid_wanted,cur_pc_even))){  
            return;
        }

        unsigned char insn[4] = { 0 };

				if (((*retfrom_framework) == cur_pc_even) && ((*frameworkhooker) != NULL)) {
            (*(*frameworkhooker))(env, 1);
            (*frameworkhooker) = 0;
            (*retfrom_framework) = 0;
            (*codeoffset)=0;
            goto dis;
        }

        if (*jniset==false&&isPCInDex(pid_wanted, cur_pc_even)) { //inital hooking before going into jni call

            if (once) {
                getDexStartAddr(pid_wanted, cur_pc_even);
                once=false;
            }

						gva_t offset = cur_pc_even - moduleStartAddr + OFFSET_APP_EXECUTABLE; // modified -- zhouhao
            // gva_t offset_test = cur_pc_even - dexStartAddr - 4096; // test -- zhouhao
						// DECAF_printf("cur_pc_even = %x\n", cur_pc_even); // test -- zhouhao
						// DECAF_printf("dex_startAddr = %x\tdex_offset = %x\n", dexStartAddr, offset); // test -- zhouhao
						// DECAF_printf("module_startAddr = %x\tmodule_offset = %x\n", moduleStartAddr, offset); // test -- zhouhao

            // start -- zhouhao
						/*
						if (!find_point(offset))
						{
							  char *className = 0;
								char *methodName = 0;
								char *arguments=0;
								int isStatic=-1;
								int len=-1;
								int ret=-1;
								native_query(offset, &className, &methodName, &isStatic, &ret, &len, &arguments);
								DECAF_printf("offset: %x, jni class name: %s, jni method name: %s\n", offset, className, methodName); // test -- zhouhao
						}
						*/
						// end -- zhouhao

            if (find_point(offset)) {
                DECAF_printf("Will go into JNI part,still in dex now!\n");
                *jniset=true;
                *jni_offset=offset;
                *retfrom_jni=env->regs[14] & 0xfffffffe;

                char *className = 0;
                char *methodName = 0;
                char *arguments=0;
                int isStatic=-1;
                int len=-1;
                int ret=-1;
                native_query(offset,&className,&methodName,&isStatic,&ret,&len,&arguments);
								DECAF_printf("jni class name: %s, jni method name: %s\n", className, methodName); // test -- zhouhao
								if (isStatic) {
                    int total=0;   //before process, arguments numbers
                    int i=0;
                    for (;i<len;i++) {
                        int j=arguments[i]-48;
                        if (total==0) {
                            if (j==9) {
                                unsigned taint=find(env->regs[1]);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if(taint)   
                                {
                                    insert_args(i+1,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total==1) {
                            if (j==9) {
                                unsigned taint=find(env->regs[2]);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if(taint)   
                                {
                                    insert_args(i+1,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total==2) {
                            if (j==9) {
                                unsigned taint=find(env->regs[3]);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if(taint)   
                                {
                                    insert_args(i+1,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total>2) {
                            if (j==9) {
                                unsigned ref=0;
                                DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                                unsigned taint=find(ref);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_args(i+1,taint);
                                }
                                total++;
                            } else {
                                total+=j;
                            }
														continue;
                        }
                    }
                } else {
                    int total=1;
                    unsigned taint=find(env->regs[1]);
										if (taint) {
                        insert_args(1,taint);
                    }
                    int i=0;
                    for (;i<len;i++) {
                        int j = arguments[i] - 48;
                        if (total==1) {
                            if (j==9) {
                                taint=find(env->regs[2]);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_args(i+2,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total==2) {
                            if (j==9) {
                                taint=find(env->regs[3]);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_args(i+2,taint);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total>2) {
                            if (j==9) {
                                unsigned ref=0;
                                DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                                taint=find(ref);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert_args(i+2,taint);
                                    total++;
                                }
                            }else{
                                total+=j;
                            }
														continue;
                        }
                    }
										// DECAF_printf("Taint value: %d\n", taint); // zhouhao
                }
                goto dis;
            }
        }


        if (*jniset) {     //  totally finish jni call
            if((*retfrom_jni)==cur_pc_even)
            {
                DECAF_printf("JNI part is totally finished!\n");
                *retfrom_jni=0;
                *jniset=false;
                char *className = 0;
                char *methodName = 0;
                char *arguments=0;
                int isStatic=-1;
                int len=-1;
                int ret=-1;
                native_query(*jni_offset,&className,&methodName,&isStatic,&ret,&len,&arguments);
								DECAF_printf("jni class name: %s, jni method name: %s\n", className, methodName); // test -- zhouhao
                *jni_offset=0;

                if (ret==9) {
                    unsigned taint = find_args(0);
										// DECAF_printf("ret Taint value: %d\n", taint); // zhouhao
                    if (taint) {
                        insert(taint,env->regs[0]);
                    }
								}
                clear_args();
                goto dis;
            }
        }

        if (*jniset) {  //after a JNI API call
            if (cur_pc_even==(*retvalue)&&(*jnihooker)!=0) {
                DECAF_printf("A JNI API call is over!\n");
                (*(*jnihooker))(env,1);  //also can process ret value update in jnihooker
                (*retvalue)=0;
                (*jnihooker)=0;
                goto dis;
            }
        }



    dis:DECAF_read_mem(env, cur_pc_even, &insn, 4);
        if(env->thumb == 1){
            DumpThumb(insn, cur_pc_even, env);
        }else{
            DumpArm(insn, cur_pc_even, env);
        }
        LAST_INS_ADDR = cur_pc_even;
    }
    return;
}


int BlockEndCondFunc (DECAF_callback_type_t cbType, gva_t curPC, gva_t nextPC)
{
    DEFENSIVE_CHECK1(cbType != DECAF_BLOCK_END_CB, 0);
    DEFENSIVE_CHECK1(pid_wanted == 0xffffffff, 0);
    gva_t cur_pc_even = curPC & 0xfffffffe;

    if (libArtStartAddress!=0&&
        (cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_RESOLUTION_TRAMPOLINE_END ||
         cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_DIRECT_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
         cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_END ||
         cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
         cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_STATIC_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
         cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_SUPER_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
         cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_VIRTUAL_TRAMPOLINE_WITH_ACCESS_CHECK_END||
         cur_pc_even == libArtStartAddress + OFFSET_ART_JNI_DLSYM_LOOKUP_STUB_END)){
				// DECAF_printf("cur_pc_even in libArtStartAddress\n"); // zhouhao
        return (1);
    }

    if (isPCInDex(pid_wanted, cur_pc_even)||isInJNI(pid_wanted,cur_pc_even)){
				return (1);
    }

    if (cur_pc_even == DO_FORK_END_ADDR) {
				return (1);
    }

    return (0);
}



void BlockEndCallback(DECAF_Callback_Params* params)
{
    // DECAF_printf("execute BlockEndCallback() method ...\n"); // test -- zhouhao

    DEFENSIVE_CHECK0(params == NULL);
    DEFENSIVE_CHECK0(pid_wanted == 0xffffffff);
    DEFENSIVE_CHECK0(pid_wanted != curTGID); // Zhouhao
		
    CPUState* env = params->be.env;
    gva_t curPC = params->be.cur_pc;
    gva_t cur_pc_even = curPC & 0xfffffffe;
    gva_t nextPC = params->be.next_pc;
    gva_t next_pc_even = nextPC & 0xfffffffe;

		// DECAF_printf("BEnd: cur_pc_even = %x, next_pc_even = %x\n, ", cur_pc_even, next_pc_even); // zhouhao

		if (cur_pc_even == DO_FORK_END_ADDR ) {
				updateThreadByPID(env,pid_wanted);
        updateTaintRegs(pid_wanted);
        return;
    }

#if 1 // zhouhao
			// DECAF_printf("BEnd: cur_pc_even = %x, next_pc_even = %x\n, ", cur_pc_even, next_pc_even); // zhouhao
			// DECAF_printf("next_pc_even is in FrameWork = %d, isThread = %d\n", next_pc_even>=FRAMEWORK_START && next_pc_even<=FRAMEWORK_END, isThread(curTGID,curTID)); // zhouhao
			// DECAF_printf("curTGID = %d, curTID = %d\n", curTGID, curTID); // zhouhao
#endif

		if (isThread(curTGID,curTID)) {

        if(!setThread(curTID))
        {
					// DECAF_printf("setThread() failure, currTID=%d\n", curTID); // zhouhao
					return;
        }
				
        if (flag_flush) {
            if (libArtStartAddress == 0) {
                getModuleStartEndAddress(curTGID, &libArtStartAddress, &libArtEndAddress, "/lib/libart.so");
								// DECAF_printf("libArtStartAddress = %x\n", libArtStartAddress); // zhouhao
								// DECAF_printf("libArtEndAddress = %x\n", libArtEndAddress); // zhouhao
                if (libArtStartAddress != 0){
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_RESOLUTION_TRAMPOLINE_START);
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_START);
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_DIRECT_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_STATIC_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_SUPER_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_VIRTUAL_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                    DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_JNI_DLSYM_LOOKUP_STUB_START);
                    flag_flush=false;
                }
            }else{
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_RESOLUTION_TRAMPOLINE_START);
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_START);
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_DIRECT_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_STATIC_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_SUPER_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_QUICK_INVOKE_VIRTUAL_TRAMPOLINE_WITH_ACCESS_CHECK_START);
                DECAF_flushTranslationPage_env(env, libArtStartAddress + OFFSET_ART_JNI_DLSYM_LOOKUP_STUB_START);
                flag_flush=false;
            }
        }

				if (isPCInDex(pid_wanted,cur_pc_even) && next_pc_even>=FRAMEWORK_START && next_pc_even<=FRAMEWORK_END
						&& next_pc_even != (FRAMEWORK_START + OFFSET_BOOT_QUICK_RESOLUTION_TRAMPOLINE)
						&& next_pc_even != (FRAMEWORK_START + OFFSET_BOOT_QUICK_IMT_cONFLICT_TRAMPOLINE/*added -- zhouhao*/))
				{
            gva_t offset = next_pc_even - FRAMEWORK_START;            
						DECAF_printf("offset = %x\n", offset); // zhouhao
						char *className = 0;
            char *methodName = 0;
            char *arguments=0;
            int isStatic=-1;
            int len=-1;
            int ret=-1;
            if(framework_query(offset,&className,&methodName,&isStatic,&ret,&len,&arguments)==0){
                DECAF_printf("current TID:%d\n",curTID);
                DECAF_printf("Framework API :%s  is called!\n",methodName);
                (*frameworkhooker) = hookFrameworkCall(methodName);
                (*codeoffset)=offset;
                (*(*frameworkhooker))(env, 0);
                (*retfrom_framework) = env->regs[14]&0xfffffffe;
            }
            return;
        }

        if (isPCInDex(pid_wanted,cur_pc_even)
				&& (next_pc_even == (FRAMEWORK_START + OFFSET_BOOT_QUICK_RESOLUTION_TRAMPOLINE)
					 || next_pc_even == (FRAMEWORK_START + OFFSET_BOOT_QUICK_IMT_cONFLICT_TRAMPOLINE)/*added -- zhouhao*/
					 || (libArtStartAddress!=0
						  &&
						  (next_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_DIRECT_TRAMPOLINE_WITH_ACCESS_CHECK_START ||
               next_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_START ||
               next_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_WITH_ACCESS_CHECK_START ||
               next_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_STATIC_TRAMPOLINE_WITH_ACCESS_CHECK_START ||
               next_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_SUPER_TRAMPOLINE_WITH_ACCESS_CHECK_START ||
               next_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_VIRTUAL_TRAMPOLINE_WITH_ACCESS_CHECK_START)))) {
            (*retfrom_framework) = env->regs[14]&0xfffffffe;
            return;
        }

        if (libArtStartAddress!=0&&(cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_RESOLUTION_TRAMPOLINE_END ||
            cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_DIRECT_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
            cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_END ||
            cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_INTERFACE_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
            cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_STATIC_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
            cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_SUPER_TRAMPOLINE_WITH_ACCESS_CHECK_END ||
            cur_pc_even == libArtStartAddress + OFFSET_ART_QUICK_INVOKE_VIRTUAL_TRAMPOLINE_WITH_ACCESS_CHECK_END)&&
            next_pc_even>FRAMEWORK_START&&next_pc_even<FRAMEWORK_END){
            if ((*retfrom_framework) == (env->regs[14] & 0xfffffffe)){
                gva_t offset = next_pc_even - FRAMEWORK_START;
								DECAF_printf("offset = %x\n", offset); // -- zhouhao
                char *className = 0;
                char *methodName = 0;
                char *arguments=0;
                int isStatic=-1;
                int len=-1;
                int ret=-1;
                if(framework_query(offset,&className,&methodName,&isStatic,&ret,&len,&arguments)==0){
                    DECAF_printf("current TID:%d\n",curTID);
                    DECAF_printf("Framework API :%s  is called!\n",methodName);
                    (*frameworkhooker) = hookFrameworkCall(methodName);
                    (*codeoffset)=offset;
                    (*(*frameworkhooker))(env, 0);
                }
            }
            return;
        }
    

        if (*jniset) {  //will go into so native methods
            if ((isPCInDex(pid_wanted,cur_pc_even)&&isInJNI(pid_wanted,next_pc_even))||(cur_pc_even == libArtStartAddress + OFFSET_ART_JNI_DLSYM_LOOKUP_STUB_END&&isInJNI(pid_wanted,next_pc_even)))
            {
                DECAF_printf("JNI part will go into so file!\n");
                char *className = 0;
                char *methodName = 0;
                char *arguments=0;
                int isStatic=-1;
                int len=-1;
                int ret=-1;
                native_query((*jni_offset),&className,&methodName,&isStatic,&ret,&len,&arguments);
                DECAF_printf("jni class name: %s, jni method name: %s\n", className, methodName); // test -- zhouhao
								if (isStatic) {
                    int total=0;  
                    int i=0; 
                    for (;i<len;i++) {
                        int j=arguments[i]-48;
                        if (total==0) {
                            if (j==9) {
                                unsigned taint=find_args(i+1);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert(taint,env->regs[2]);
                                }
                                total++;
                            } else {
                                total+=j;
                            }
														continue;
                        }
                        if (total==1) {
                            if (j==9) {
                                unsigned taint=find_args(i+1);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert(taint,env->regs[3]);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total>1) {
                            if (j==9) {
                                unsigned taint=find_args(i+1);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    unsigned ref=0;
                                    DECAF_read_mem(env,env->regs[13]+16+(total-2)*4,&ref,4);
                                    insert(taint,ref);
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
                    unsigned taint=find_args(1);
										if (taint) {
                        insert(taint,env->regs[1]);
                    }
                    int i = 0;
                    for (; i < len; i++) {
                        int j = arguments[i] - 48;
                        if (total==1) {
                            if (j==9) {
                                taint=find_args(i+2);
																// DECAF_printf("Taint value: %d\n", taint); // zhouhao
                                if (taint) {
                                    insert(taint,env->regs[2]);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total==2) {
                            if (j==9) {
                                taint=find_args(i+2);
                                // DECAF_printf("Taint value: %d\n", taint); // zhouhao
																if (taint) {
                                    insert(taint,env->regs[3]);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                        if (total>2) {
                            if (j==9) {
                                taint=find_args(i+2);
																// DECAF_printf("Taint value: %d\n", taint); // zhouhao
                                if (taint) {
                                    unsigned ref = 0;
                                    DECAF_read_mem(env,env->regs[13]+16+(total-3)*4,&ref,4);
                                    insert(taint,ref);
                                }
                                total++;
                            }else{
                                total+=j;
                            }
														continue;
                        }
                    }
										// DECAF_printf("Taint value: %d\n", taint); // zhouhao
                }
                return;
            }
        }

        if (*jniset) {   //return from jni call, still in so
            if (isInJNI(pid_wanted,cur_pc_even)&&isPCInDex(pid_wanted,next_pc_even)) {
                DECAF_printf("JNI part still in so, but will be over!\n");
                char *className = 0;
                char *methodName = 0;
                char *arguments=0;
                int isStatic=-1;
                int len=-1;
                int ret=-1;
                native_query((*jni_offset),&className,&methodName,&isStatic,&ret,&len,&arguments);
								DECAF_printf("jni class name: %s, jni method name: %s, offset = %x\n", className, methodName, *jni_offset); // test -- zhouhao
                if (ret==9) {
                    unsigned taint=find(env->regs[0]);
                    // DECAF_printf("ret Taint value: %d\n", taint); // zhouhao
										if (taint) {
                        insert_args(0,taint);
                    }
								}
                return;
            }
        }

        if (*jniset) {  //so call other methods
            gva_t startaddr=0;
            if (isInJNI(pid_wanted,cur_pc_even)&&isInLib(pid_wanted,next_pc_even,"/lib/libart.so",&startaddr)) { //JNI APIs
                int offset=next_pc_even-startaddr;
                char *name=findjni(offset);
                if (name) {
                    DECAF_printf("JNI API : \"%s\"  is called!\n",name);
                    *jnihooker=jnihook(name);
                    if (*jnihooker) {
                        *retvalue=env->regs[14] & 0xfffffffe;
                        (*(*jnihooker))(env,0);
                        if (*calltype) { //CallXXMethod  series , calltype set in jnihooker
                            DECAF_flushTranslationPage_env(env, *breakpoint);
                            DECAF_flushTranslationPage_env(env,libArtStartAddress+suspicious_hard_code);
                        }
                    }
                }
                return;
            }

            if (isInLib(pid_wanted,next_pc_even,"/lib/libc.so",&startaddr)) {
                DECAF_printf("Go into libc!!!\n");
                int offset=next_pc_even-startaddr;
								// DECAF_printf("libc offset: %x\n", offset); //zhouhao
                char *name=findlibc(offset);
                if (name) {
                    DECAF_printf("Libc API : \"%s\" !\n",name);
                    LibcHook libchooker=libchook(name);
                    if (libchooker) {
                        (*libchooker)(env,0);
                    }
                }
                return;
            }

            if (isInLib(pid_wanted,next_pc_even,"/lib/libm.so",&startaddr)) {
                DECAF_printf("Go into libm!!!\n");
                int offset=next_pc_even-startaddr;
                char *name=findlibm(offset);
                if (name) {
                    DECAF_printf("Libm API : \"%s\" !\n",name);
                }
                return;
            }
        }
    }
    return;
}

int BBCondFunc (DECAF_callback_type_t cbType, gva_t curPC, gva_t nextPC)
{
  DEFENSIVE_CHECK1(cbType != DECAF_BLOCK_BEGIN_CB, 0);

  if (curPC == SWITCH_TO || curPC == DO_FORK_ADDR)
  {
    return (1);
  }

  return (0);
}

void BBCallBack(DECAF_Callback_Params* params)
{
    // DECAF_printf("execute BBCallBack() method ...\n"); // test -- zhouhao
	
	  DEFENSIVE_CHECK0(params == NULL);
    DEFENSIVE_CHECK0(pid_wanted == 0xffffffff);
    static gva_t taskAddr = INV_ADDR;
		TranslationBlock* tb = NULL;
    CPUState* env = NULL;

    env = params->bb.env;
    tb = params->bb.tb;

    if (NULL == tb)
    {
        return;
    }

    if (tb->pc == SWITCH_TO) {
				DECAF_read_mem(env,(env->regs[1]+12),&taskAddr,sizeof(taskAddr));
        curTID = DECAF_get_pid(env, taskAddr);
        curTGID = DECAF_get_tgid(env,taskAddr);
				DECAF_read_mem(env,(env->regs[2]+12),&taskAddr,sizeof(taskAddr));
        curTID = DECAF_get_pid(env, taskAddr);
        curTGID = DECAF_get_tgid(env,taskAddr);
    }
    
    if (tb->pc == DO_FORK_ADDR && flag_fork) {
				flag_fork=false;
        DECAF_flushTranslationPage_env(env, DO_FORK_END_ADDR);
    }

}

void wait_uid(Monitor* mon, target_ulong uid)
{
    if(uid_wanted != 0xffffffff)
    {
        DECAF_fprintf(NULL, "Tracing has been started!Please stop first!\n");
        return;
    }
    uid_wanted = uid;
    return;
}

void start_tracing_pid(target_ulong pid){
    if (pid_wanted!=0xffffffff) {
        return;
    }
    DECAF_printf("Starts tracing process with pid<%d>\n", pid);
    pid_wanted = pid;
    contextIBHandle = DECAF_register_callback(DECAF_INSN_BEGIN_CB, &IBCallback, &IBCondFunc);
		// contextIBHandle = DECAF_register_callback(DECAF_INSN_BEGIN_CB, &IBCallback, NULL);
		contextBEHandle = DECAF_register_callback(DECAF_BLOCK_END_CB, &BlockEndCallback, &BlockEndCondFunc);
		// contextBEHandle = DECAF_register_callback(DECAF_BLOCK_END_CB, &BlockEndCallback, NULL);
    contextBBHandle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, &BBCallBack, &BBCondFunc);
    //contextBBHandle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, &BBCallBack, NULL);
}

void stop_trace(Monitor *mon)
{
    removeProcess(pid_wanted);
    uid_wanted = 0xffffffff;
    pid_wanted = 0xffffffff;
    if (contextIBHandle != DECAF_NULL_HANDLE) {
        DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, contextIBHandle);
        contextIBHandle = DECAF_NULL_HANDLE;
    }
    if (contextBEHandle != DECAF_NULL_HANDLE) {
        DECAF_unregister_callback(DECAF_BLOCK_END_CB, contextBEHandle);
        contextBEHandle = DECAF_NULL_HANDLE;
    }
    if (contextBBHandle != DECAF_NULL_HANDLE)
    {
        DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, contextBBHandle);
        contextBBHandle = DECAF_NULL_HANDLE;
    }
    clear_map();
    clear_taintmap();
    clear_refmap();
    clear_pmap();
    setp2tls0();
    global_count=0;
    cacheDexStartAddr=cacheDexEndAddr=0;
    libArtStartAddress=libArtEndAddress=0;
    dexStartAddr=dexEndAddr=0;
    curTID=curTGID=-1;
    once=true;
    flag_flush=true;
    flag_fork=true;
    return;
}

#endif
