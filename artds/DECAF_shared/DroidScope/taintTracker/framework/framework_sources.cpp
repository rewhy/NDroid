/**
 * Created By Chenxiong Qian
 * date: 2014-12-3
 */
#include "framework_sources.h"
#include <map>
#include "DECAF_shared/utils/OutputWrapper.h"
#include <locale.h>
#include <stdlib.h>
#include "../object.h"

#define GENERAL_TAINT 0x00000001

int global_count=0;

using namespace std;

// this method is a copy of the "dumpstring" method in framework_sinks.cpp -- zhouhao
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
// zhouhao


void fileHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
    }else{
        if (global_count>=32) {
            return;
        }
        insert(GENERAL_TAINT << global_count, env->regs[0]);
        DECAF_printf("Taint value: %x\n",GENERAL_TAINT<<global_count);
        DECAF_printf("Taint source No.%d\n",global_count);
        global_count++;
    }
}


void getidHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
    }else{
        if (global_count>=32) {
            return;
        }
        insert(GENERAL_TAINT<<global_count,env->regs[0]);
        DECAF_printf("Taint value: %x\n",GENERAL_TAINT<<global_count);
        DECAF_printf("Taint source No.%d\n",global_count);
        dumpstring(env,env->regs[0]); // added -- zhouhao
				global_count++;
    }
}

void getLine1NumberHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
    }else{
        if (global_count>=32) {
            return;
        }
        insert(GENERAL_TAINT<<global_count,env->regs[0]);
        DECAF_printf("Taint value: %x\n",GENERAL_TAINT<<global_count);
        DECAF_printf("Taint source No.%d\n",global_count);
        global_count++;
    }
}

void tostrHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
    }else{
        if (global_count>=32) {
            return;
        }
        insert(GENERAL_TAINT<<global_count,env->regs[0]);
        DECAF_printf("Taint value: %x\n",GENERAL_TAINT<<global_count);
        DECAF_printf("Taint source No.%d\n",global_count);
        global_count++;
    }
}

void gettextHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
    }else{
        if (global_count>=32) {
            return;
        }
        insert(GENERAL_TAINT<<global_count,env->regs[0]);
        DECAF_printf("Taint value: %x\n",GENERAL_TAINT<<global_count);
        DECAF_printf("Taint source No.%d\n",global_count);
        global_count++;
    }
}

void gpsHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
    }else{
        if (global_count>=32) {
            return;
        }

        setRegTaint(0,GENERAL_TAINT<<global_count);
        setRegTaint(1,GENERAL_TAINT<<global_count);
        DECAF_printf("Taint value: %x\n",GENERAL_TAINT<<global_count);
        DECAF_printf("Taint source No.%d\n",global_count);
        global_count++;
    }
}


void gHooker(CPUState* env, int afterInvoking){
    if (!afterInvoking) {
    }else{
        if (global_count>=32) {
            return;
        }

        insert(GENERAL_TAINT<<global_count,env->regs[0]);
        DECAF_printf("Taint value: %x\n",GENERAL_TAINT<<global_count);
        DECAF_printf("Taint source No.%d\n",global_count);
        global_count++;
    }
}



struct cmp_str
{
    bool operator()(char const *a, char const *b)
    {
        return strcmp(a, b) < 0;
    }
};

std::map<char const*, frameworkCallHooker, cmp_str> sourceMethodHookerMap;

void frameworkSourceInit(){
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.lang.String android.telephony.TelephonyManager.getDeviceId()",
					                                                                   getidHooker));  
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.lang.String android.telephony.TelephonyManager.getLine1Number()",
					                                                                   getLine1NumberHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.io.FileInputStream android.content.ContextWrapper.openFileInput(java.lang.String)",
					                                                                   fileHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.lang.String android.view.View.toString()",
					                                                                   tostrHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("android.text.Editable android.widget.EditText.getText()",
					                                                                   gettextHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("double android.location.Location.getLatitude()",
					                                                                   gpsHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("double android.location.Location.getLongitude()",
					                                                                   gpsHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.lang.String android.telephony.TelephonyManager.getSimSerialNumber()",
					                                                                   getidHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("java.lang.String android.telephony.TelephonyManager.getSubscriberId()",
					                                                                   getidHooker));
    sourceMethodHookerMap.insert(std::pair<char const*, frameworkCallHooker>("android.database.Cursor android.content.ContentResolver.query(android.net.Uri, java.lang.String[], java.lang.String, java.lang.String[], java.lang.String)",
					                                                                   gHooker));
}

frameworkCallHooker hookSource(const char* methodName){
    std::map<char const*, frameworkCallHooker>::iterator it;
    it = sourceMethodHookerMap.find(methodName);
    if (it != sourceMethodHookerMap.end()){
        DECAF_printf("This is source!\n");
        return it->second;
    }
    return NULL;
}
