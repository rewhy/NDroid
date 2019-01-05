/**
 * Created By Chenxiong Qian
 * date: 2014-12-3
 */

#include "framework_sinks.h"
#include <map>
#include "DECAF_shared/utils/OutputWrapper.h"
#include "../object.h"
#include <locale.h>
#include <stdlib.h>

using namespace std;

#define GENERAL_TAINT 0x00000001

void dumpstring(CPUState* env,gva_t addr)
{
        setlocale(LC_ALL, "");
        gva_t array=0;
        DECAF_read_mem(env,(addr+8),&array,sizeof(array));
        gva_t count=0;
        DECAF_read_mem(env,(addr+12),&count,sizeof(count));
        gva_t offset=0;
        DECAF_read_mem(env,(addr+20),&offset,sizeof(offset));


        wchar_t * chars=new wchar_t[count+1];
        memset(chars,0,sizeof(wchar_t)*(count+1));
        for (int i=0;i<count;i++) {
            DECAF_read_mem(env, (array + 12 + offset+i*2), chars+i, sizeof(uint16_t));
        }    

        char* str=new char[count*4];
        wcstombs(str, chars, count*4);
 
        DECAF_printf("String value: %s\n",str);
        delete chars;
        delete str;

}

void sendTextMessageHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking){
        gva_t addr;
        DECAF_read_mem(env,env->regs[13] + 16,&addr,sizeof(addr));
				int count=0;
        if((count=find(addr))){
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
        dumpstring(env,env->regs[2]);
        dumpstring(env,addr); 
    }
}

void writeHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
        int count=0;
        if ((count=find(env->regs[2]))) {
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
    }
}

// start -- zhouhao
void writerHooker(CPUState* env, int afterInvoking) {
	  DECAF_printf("addr: %d\n", env->regs[2]); 
    if (!afterInvoking) {
			  int count = 0;
				if ((count = find(env->regs[2]))) {
					  DECAF_printf("Taint value: %x\n", count);
						for (int i = 0; i < 32; i++) {
							  if (count & (GENERAL_TAINT << i)) {
									  DECAF_printf("Taint source No.%d is gotten!\n", i);
								}
						}
				}
				dumpstring(env, env->regs[2]);
		}
}
// end -- zhouhao

// start -- zhouhao
void editorPutStringHooker(CPUState* env, int afterInvoking) {
    if (!afterInvoking) {
			  int count = 0;
        if ((count=find(env->regs[3]))) {
					  DECAF_printf("Taint value: %x\n",count);
					  for (int i=0;i<32;i++) {
						    if (count&(GENERAL_TAINT<<i)) {
						        DECAF_printf("Taint source No.%d is gotten!\n", i);
						    }
						}
				}
				dumpstring(env,env->regs[2]);
				dumpstring(env,env->regs[3]);
		}
}
// end -- zhouhao

void logHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
        int count=0;
        if ((count=find(env->regs[2]))) {
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
        dumpstring(env,env->regs[2]);
    }
}

void resHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
        int count=0;
        if ((count=find(env->regs[3]))) {
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
    }
}

void startHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
        int count=0;
        if ((count=find(env->regs[2]))) {
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
    }
}

void connectHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
        int count=0;
        if ((count=find(env->regs[1]))) {
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
    }
}

extern "C" unsigned * taintvalue;

void divideHooker(CPUState* env, int afterInvoking)
{
    if (!afterInvoking) {
        int count=0;
        if ((count=find(env->regs[2]))) {
            *taintvalue=count;
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
        dumpstring(env,env->regs[2]);
    }else{
        if (*taintvalue) {
            insert(*taintvalue, env->regs[0]);
            *taintvalue=0;
        }
    }
}

void messageHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
        int count=0;
        if ((count=find(env->regs[2]))) {
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
            dumpstring(env,env->regs[2]);
        }
        

        count=0;
        gva_t addr;
        DECAF_read_mem(env,env->regs[13] + 16,&addr,sizeof(addr));
        if ((count=find(addr))) {
            DECAF_printf("Taint value: %x\n",count);
            for (int i=0;i<32;i++) {
                if (count&(GENERAL_TAINT<<i)) {
                    DECAF_printf("Taint source No.%d is gotten!\n", i);
                }
            }
        }
    }
}

void execHooker(CPUState* env, int afterInvoking)
{
    if (!afterInvoking) {

        dumpstring(env,env->regs[2]);
    }
}

void fileinitHooker(CPUState* env, int afterInvoking)
{
    if (!afterInvoking) {
        dumpstring(env,env->regs[2]);
    }
}

void assetsHooker(CPUState* env, int afterInvoking)
{
    if (!afterInvoking) {
        dumpstring(env,env->regs[2]);
    }
}

void intentHooker(CPUState* env, int afterInvoking)
{
    if (!afterInvoking) {
        dumpstring(env,env->regs[2]);
    }
}

void uriHooker(CPUState* env, int afterInvoking)
{
    if (!afterInvoking) {
        dumpstring(env,env->regs[1]);
    }
}

void setintentHooker(CPUState* env, int afterInvoking)
{
    if (!afterInvoking) {
        dumpstring(env,env->regs[3]);
    }
}


struct cmp_str
{
    bool operator()(char const *a, char const *b)
    {
        return strcmp(a, b) < 0;
    }
};

std::map<char const*, frameworkCallHooker, cmp_str> sinkMethodHookerMap;

void frameworkSinkInit(){
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void android.telephony.SmsManager.sendTextMessage(java.lang.String, java.lang.String, java.lang.String, android.app.PendingIntent, android.app.PendingIntent)", 
                                                                           sendTextMessageHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void java.io.OutputStream.write(byte[])", 
                                                                           writeHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("int android.util.Log.i(java.lang.String, java.lang.String)",
                                                                           logHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("int android.util.Log.v(java.lang.String, java.lang.String)",
                                                                           logHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("int android.util.Log.d(java.lang.String, java.lang.String)",
                                                                           logHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void android.app.Activity.setResult(int, android.content.Intent)",
                                                                           resHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void android.app.Activity.startActivity(android.content.Intent)",
                                                                           startHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void com.android.okhttp.internal.http.HttpURLConnectionImpl.connect()",
                                                                           connectHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.util.ArrayList android.telephony.SmsManager.divideMessage(java.lang.String)",
                                                                           divideHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void android.telephony.SmsManager.sendMultipartTextMessage(java.lang.String, java.lang.String, java.util.ArrayList, java.util.ArrayList, java.util.ArrayList)",
                                                                           messageHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.lang.Process java.lang.Runtime.exec(java.lang.String)",
                                                                           execHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void java.io.File.<init>(java.lang.String)",
                                                                           fileinitHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.io.InputStream android.content.res.AssetManager.open(java.lang.String)",
                                                                           assetsHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void android.content.Intent.<init>(java.lang.String)",
                                                                           intentHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("android.content.Intent android.content.Intent.setDataAndType(android.net.Uri, java.lang.String)",
                                                                           setintentHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("android.net.Uri android.net.Uri.parse(java.lang.String)",
                                                                           uriHooker));
    sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("void java.io.Writer.write(java.lang.String)",
					                                                                 writerHooker)); // added -- zhouhao
		sinkMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putString(java.lang.String, java.lang.String)",
				                                                                   editorPutStringHooker)); // added -- zhouhao
}

frameworkCallHooker hookSink(const char* methodName){
    std::map<char const*, frameworkCallHooker>::iterator it;
    it = sinkMethodHookerMap.find(methodName);
    if (it != sinkMethodHookerMap.end()){
        DECAF_printf("This is sink!\n");
        return it->second;
    }
    return NULL;
}
