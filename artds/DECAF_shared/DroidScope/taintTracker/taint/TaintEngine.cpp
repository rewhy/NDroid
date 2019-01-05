/**
 * author: Chenxiong (R0r5ch4ch) Qian
 * date: 2013-4-3
 */

#include "TaintEngine.h"
#include <tr1/unordered_map>
#include <assert.h>
#include "DECAF_shared/utils/OutputWrapper.h"
#include "DECAF_shared/DroidScope/taintTracker/disas/disas_arm.h"
#include "../register.h"
#include "jni/jnimethod.h"
#include "framework/framework_hooks.h"

using namespace std::tr1;

typedef unordered_map<int, int> taint_map;
typedef unordered_map<int, int>::const_iterator const_taint_iterator;
typedef unordered_map<int, int>::iterator taint_iterator;
typedef std::pair<int, int> taint_pair;

static taint_map taintMap;

extern "C"
{

bool * jniset=0;
gva_t * jni_offset=0;
gva_t * retfrom_framework=0;
gva_t * retfrom_jni=0;
gva_t * breakpoint=0;
JNIHook * jnihooker=0;
frameworkCallHooker * frameworkhooker=0;
unsigned * taintvalue=0;
gva_t * codeoffset=0;
gva_t * calltype=0;
gva_t * retvalue=0;
map<int,unsigned> * argsindex=0;
map<int,unsigned> * java_args=0;
frameworkCallHooker * javahooker=0;
gva_t * calljava_offset=0;
int *taintRegs=NULL;
int *taintD=NULL;
int *taintS=NULL;

}

void setp2tls0()
{
    jniset=0;
    jni_offset=0;
    retfrom_framework=0;
    retfrom_jni=0;
    breakpoint=0;
    jnihooker=0;
    frameworkhooker=0;
    codeoffset=0;
    taintvalue=0;
    calltype=0;
    retvalue=0;
    argsindex=0;
    java_args=0;
    javahooker=0;
    calljava_offset=0;
    taintRegs=NULL;
    taintD=NULL;
    taintS=NULL;
}

void clear_taintmap()
{
    taintMap.clear();
}


// #define LOG_TAINT_PROPAGATION 1

#define DEFENSIVE_CHECK_TAINT(_tValue) \
	if (_tValue == 0) return (-1);

#define DEFENSIVE_CHECK_TAINT_NO_RET(_tValue) \
	if (_tValue == 0) return;

bool setThread(gpid_t tid)
{
    tls_taint *tmp=find_map(tid);
    if (tmp==NULL) {
        setp2tls0();
        return false;
    }else{

#ifdef LOG_TAINT_PROPAGATION
        DECAF_printf("______regs addr :%p\n",tmp);
#endif
        taintRegs=tmp->taintRegs;
        taintD=tmp->taintD;
        taintS=tmp->taintS;

        retfrom_framework=&tmp->retform_framework;
        frameworkhooker=&tmp->frameworkhooker;
        codeoffset=&tmp->codeoffset;
        taintvalue=&tmp->taintvalue;

        jniset=&tmp->jniset;

        jni_offset=&tmp->jni_offset;
        retfrom_jni=&tmp->retfrom_jni;
        jnihooker=&tmp->jnihooker;
        argsindex=&tmp->argsindex;

        breakpoint=&tmp->breakpoint;
        calltype=&tmp->calltype;

        calljava_offset=&tmp->calljava_offset;
        javahooker=&tmp->javahooker;
        retvalue=&tmp->retvalue;
        java_args=&tmp->java_args;

        return true;
    }
}

int addTaint(int addr, int tValue){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint mem[%x] |= %x \n", addr, tValue);
#endif

	DEFENSIVE_CHECK_TAINT(tValue);
	taint_iterator it = taintMap.find(addr);
	if(it != taintMap.end()){
		it->second |= tValue;
		return (1);
	}else{
		taint_pair newTaint (addr, tValue);
		taintMap.insert(newTaint);
		return (0);
	}
}

void addBlockTaint(int startAddr, int endAddr, int tValue){
	DEFENSIVE_CHECK_TAINT_NO_RET(tValue);
	assert(startAddr <= endAddr);
	int addr;
	for(addr = startAddr; addr <= endAddr; addr++){
		addTaint(addr, tValue);
	}
}

int setTaint(int addr, int tValue){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint mem[%x] = %x \n", addr, tValue);
#endif

	DEFENSIVE_CHECK_TAINT(tValue);
	taint_iterator it = taintMap.find(addr);	
	if(it != taintMap.end()){
		it->second = tValue;
		return (1);
	}else{
		taint_pair newTaint (addr, tValue);
		taintMap.insert(newTaint);
		return (0);
	}
}

int clearTaint(int addr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" clear taint mem[%x] \n", addr);
#endif

	taint_iterator it = taintMap.find(addr);
	if(it != taintMap.end()){
		taintMap.erase(it);
		return (1);
	}else{
		return (0);
	}
}

void clearBlockTaint(int startAddr, int endAddr){
	int addr;
	assert(startAddr <= endAddr);
	for(addr = startAddr; addr <= endAddr; addr++){
		clearTaint(addr);
	}
}

void addTaintToReg(int regIdx, int tValue){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint reg[%d] |= %x \n", regIdx, tValue);
#endif
	DEFENSIVE_CHECK_TAINT_NO_RET(tValue);
	if((regIdx >= 0) && (regIdx <= 15)){
		taintRegs[regIdx] |= tValue;
	}
}

void setRegTaint(int regIdx, int tValue){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint reg[%d] = %x \n", regIdx, tValue);
#endif
	DEFENSIVE_CHECK_TAINT_NO_RET(tValue);
	if((regIdx >= 0) && (regIdx <= 15)){
		taintRegs[regIdx] = tValue;
	}
}

void clearRegTaint(int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" clear taint reg[%d] \n", regIdx);
#endif
	if((regIdx >= 0) && (regIdx <= 15)){
		taintRegs[regIdx] = 0;
	}
}

int getTaint(int addr){
	taint_iterator it = taintMap.find(addr);
	if(it != taintMap.end()){
		return it->second;
	}else{
		return (0);
	}
}

int getRegTaint(int regIdx){
	if((regIdx >= 0) && (regIdx <= 15)){
		return taintRegs[regIdx];
	}
	return (0);
}


int addMemToMem(int destAddr, int srcAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint: mem[%x] --> mem[%x] \n", srcAddr, destAddr);
#endif
	int tValue = getTaint(srcAddr);
	if(tValue != 0){
		addTaint(destAddr, tValue);
		return (1);
	}else{
		return (0);
	}
}

int setMemToMem(int destAddr, int srcAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: mem[%x] --> mem[%x] \n", srcAddr, destAddr);
#endif
	int tValue = getTaint(srcAddr);
	if(tValue != 0){
		setTaint(destAddr, tValue);
		return (1);
	}else{
                clearTaint(destAddr);
		return (0);
	}
}

int addMemToReg(int regIdx, int srcAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint: mem[%x] --> r[%d] \n", srcAddr, regIdx);
#endif
	int tValue = getTaint(srcAddr);
	if(tValue != 0){
		addTaintToReg(regIdx, tValue);
		return (1);
	}else{
		return (0);
	}
}

int setMemToReg(int regIdx, int srcAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: mem[%x] --> r[%d] \n", srcAddr, regIdx);
#endif
	int tValue = getTaint(srcAddr);
	if(tValue != 0){
		setRegTaint(regIdx, tValue);
		return (1);
	}else{
                clearRegTaint(regIdx);
		return (0);
	}
}

int addRegToMem(int destAddr, int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint: r[%d] --> mem[%x] \n", regIdx, destAddr);
#endif
	int tValue = getRegTaint(regIdx);
	if(tValue != 0){
		addTaint(destAddr, tValue);
		return (1);
	}else{
		return (0);
	}
}

int setRegToMem(int destAddr, int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: r[%d] --> mem[%x] \n", regIdx, destAddr);
#endif
	int tValue = getRegTaint(regIdx);
	if(tValue != 0){
		setTaint(destAddr, tValue);
		return (1);
	}else{
                clearTaint(destAddr);
		return (0);
	}
}

void addRegToReg(int destReg, int srcReg){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint: r[%d] --> r[%d] \n", srcReg, destReg);
#endif
	int tValue = getRegTaint(srcReg);
	if(tValue != 0){
		addTaintToReg(destReg, tValue);
	}
}

void setRegToReg(int destReg, int srcReg){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: r[%d] --> r[%d] \n", srcReg, destReg);
#endif
	int tValue = getRegTaint(srcReg);
	if(tValue != 0){
		setRegTaint(destReg, tValue);
	}else{
                clearRegTaint(destReg);
        }
}


int setMem4ToReg(int regIdx, int startAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: mem4[%x] --> r[%d] \n", startAddr, regIdx);
#endif
	int addr;
	int tValue = 0;
	for(addr = startAddr; addr < startAddr + 4; addr++){
		tValue |= getTaint(addr);
	}
	if(tValue != 0){
		setRegTaint(regIdx, tValue);
		return (1);
	}else{
                clearRegTaint(regIdx);
		return (0);
	}
}

int addMem4ToReg(int regIdx, int startAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint: mem4[%x] --> r[%d] \n", startAddr, regIdx);
#endif
	int addr;
	int tValue = 0;
	for(addr = startAddr; addr < startAddr + 4; addr++){
		tValue |= getTaint(addr);
	}
	if(tValue != 0){
		addTaintToReg(regIdx, tValue);
		return (1);
	}else{
		return (0);
	}
}

int setMem2ToReg(int regIdx, int startAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: mem2[%x] --> r[%d] \n", startAddr, regIdx);
#endif
	int addr;
	int tValue = 0;
	for(addr = startAddr; addr < startAddr + 2; addr++){
		tValue |= getTaint(addr);
	}
	if(tValue != 0){
		setRegTaint(regIdx, tValue);
		return (1);
	}else{
                clearRegTaint(regIdx);
		return (0);
	}
}

void setRegToMem4(int startAddr, int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: reg[%d] --> mem4[%x] \n", regIdx, startAddr);
#endif
	if((regIdx >= 0) && (regIdx <= 15)){
		int tValue = getRegTaint(regIdx);
		if(tValue != 0){
			int addr;
			for(addr = startAddr; addr < startAddr + 4; addr++){
				setTaint(addr, tValue);
			}
		}else{
                        int addr;
                        for(addr = startAddr; addr < startAddr + 4; addr++){
				clearTaint(addr);
			}
                }

	}
}

void addRegToMem4(int startAddr, int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" add taint: reg[%d] --> mem4[%x] \n", regIdx, startAddr);
#endif
	if((regIdx >= 0) && (regIdx <= 15)){
		int tValue = getRegTaint(regIdx);
		if(tValue != 0){
			int addr;
			for(addr = startAddr; addr < startAddr + 4; addr++){
				addTaint(addr, tValue);
			}
		}
	}
}

void setRegToMem2(int startAddr, int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: reg[%d] --> mem2[%x] \n", regIdx, startAddr);
#endif
	if((regIdx >= 0) && (regIdx <= 15)){
		int tValue = getRegTaint(regIdx);
		if(tValue != 0){
			int addr;
			for(addr = startAddr; addr < startAddr + 2; addr++){
				setTaint(addr, tValue);
			}
		}else{
                        int addr;
			for(addr = startAddr; addr < startAddr + 2; addr++){
				clearTaint(addr);
			}
                }
	}
}

void setDTaint(int DIdx, int tValue){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint D[%d] = %x \n", DIdx, tValue);
#endif
	DEFENSIVE_CHECK_TAINT_NO_RET(tValue);
	if((DIdx >= 0) && (DIdx <= 15)){
		taintD[DIdx] = tValue;
	}
}

int getDTaint(int DIdx){
	if((DIdx >= 0) && (DIdx <= 15)){
		return taintD[DIdx];
	}
	return (0);
}

void clearDTaint(int DIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" clear taint D[%d] \n", DIdx);
#endif
	if((DIdx >= 0) && (DIdx <= 15)){
		taintD[DIdx] = 0;
	}
}

int setMem8ToD(int DIdx, int startAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: mem8[%x] --> D[%d] \n", startAddr, DIdx);
#endif

        int addr;
	int tValue = 0;
	for(addr = startAddr; addr < startAddr + 8; addr++){
		tValue |= getTaint(addr);
	}
	if(tValue != 0){
		setDTaint(DIdx, tValue);
		return (1);
	}else{
                clearDTaint(DIdx);
		return (0);
	}
}

void setDToMem8(int startAddr, int DIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: D[%d] --> mem8[%x] \n", DIdx, startAddr);
#endif
	if((DIdx >= 0) && (DIdx <= 15)){
		int tValue = getDTaint(DIdx);
		if(tValue != 0){
			int addr;
			for(addr = startAddr; addr < startAddr + 8; addr++){
				setTaint(addr, tValue);
			}
		}else{
                        int addr;
                        for(addr = startAddr; addr < startAddr + 8; addr++){
				clearTaint(addr);
			}
                }

	}
}

void setDToReg(int regIdx, int DIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: D[%d] --> r[%d] \n", DIdx, regIdx);
#endif
	int tValue = getDTaint(DIdx);
	if(tValue != 0){
		setRegTaint(regIdx, tValue);
	}else{
                clearRegTaint(regIdx);
        }
}

void setRegToD(int DIdx,int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: r[%d] --> D[%d] \n", regIdx, DIdx);
#endif
	int tValue = getRegTaint(regIdx);
	if(tValue != 0){
		setDTaint(DIdx, tValue);
	}else{
                clearDTaint(DIdx);
        }
}

void setDToD(int destD, int srcD){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: D[%d] --> D[%d] \n", srcD, destD);
#endif
        int tValue = getDTaint(srcD);
        if(tValue != 0){
		setDTaint(destD, tValue);
	}else{
                clearDTaint(destD);
        }
}

void setDToS(int S, int D){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: D[%d] --> S[%d] \n", D, S);
#endif
        int tValue = getDTaint(D);
        if(tValue != 0){
		setSTaint(S, tValue);
	}else{
                clearSTaint(S);
        }
}

void setSTaint(int SIdx, int tValue){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint S[%d] = %x \n", SIdx, tValue);
#endif
	DEFENSIVE_CHECK_TAINT_NO_RET(tValue);
	if((SIdx >= 0) && (SIdx <= 31)){
		taintS[SIdx] = tValue;
	}
}

int getSTaint(int SIdx){
	if((SIdx >= 0) && (SIdx <= 31)){
		return taintS[SIdx];
	}
	return (0);
}

void clearSTaint(int SIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" clear taint S[%d] \n", SIdx);
#endif
	if((SIdx >= 0) && (SIdx <= 31)){
		taintS[SIdx] = 0;
	}
}

int setMem4ToS(int SIdx, int startAddr){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: mem4[%x] --> S[%d] \n", startAddr, SIdx);
#endif

        int addr;
	int tValue = 0;
	for(addr = startAddr; addr < startAddr + 4; addr++){
		tValue |= getTaint(addr);
	}
	if(tValue != 0){
		setSTaint(SIdx, tValue);
		return (1);
	}else{
                clearSTaint(SIdx);
		return (0);
	}
}

void setSToMem4(int startAddr, int SIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: S[%d] --> mem4[%x] \n", SIdx, startAddr);
#endif
	if((SIdx >= 0) && (SIdx <= 31)){
		int tValue = getSTaint(SIdx);
		if(tValue != 0){
			int addr;
			for(addr = startAddr; addr < startAddr + 4; addr++){
				setTaint(addr, tValue);
			}
		}else{
                        int addr;
                        for(addr = startAddr; addr < startAddr + 8; addr++){
				clearTaint(addr);
			}
                }
	}
}

void setSToReg(int regIdx, int SIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: S[%d] --> r[%d] \n", SIdx, regIdx);
#endif
	int tValue = getSTaint(SIdx);
	if(tValue != 0){
		setRegTaint(regIdx, tValue);
	}else{
                clearRegTaint(regIdx);
        }
}

void setRegToS(int SIdx,int regIdx){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: r[%d] --> S[%d] \n", regIdx, SIdx);
#endif
	int tValue = getRegTaint(regIdx);
	if(tValue != 0){
		setSTaint(SIdx, tValue);
	}else{
                clearSTaint(SIdx);
        }
}

void setSToS(int destS, int srcS){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: S[%d] --> S[%d] \n", srcS, destS);
#endif
        int tValue = getSTaint(srcS);
        if(tValue != 0){
		setSTaint(destS, tValue);
	}else{
                clearSTaint(destS);
        }
}

void setSToD(int D, int S){
#ifdef LOG_TAINT_PROPAGATION
	DECAF_printf(" set taint: S[%d] --> D[%d] \n", S, D);
#endif
        int tValue = getSTaint(S);
        if(tValue != 0){
		setDTaint(D, tValue);
	}else{
                clearDTaint(D);
        }
}
