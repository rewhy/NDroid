/**
 * author: Chenxiong (R0r5ch4ch) Qian
 * date: 2013-4-3
 *
 * APIs for taint add, change, clear
 */

#ifndef __NDROID_TAINT_ENGINE_
#define __NDROID_TAINT_ENGINE_

#ifdef __cplusplus
extern "C" {
#endif

#include "DECAF_shared/DECAF_types.h"
        void setp2tls0();
        void clear_taintmap();

        bool setThread(gpid_t tid);
	int addTaint(int addr, int tValue);
	void addBlockTaint(int startAddr, int endAddr, int tValue);
	int setTaint(int addr, int tValue);
	int clearTaint(int addr);
	void clearBlockTaint(int startAddr, int endAddr);
	void addTaintToReg(int regIdx, int tValue);
	void setRegTaint(int regIdx, int tValue);
	void clearRegTaint(int regIdx);
	int getTaint(int addr);
	int getRegTaint(int regIdx);

	int addMemToMem(int destAddr, int srcAddr);
	int setMemToMem(int destAddr, int srcAddr);
	int addMemToReg(int regIdx, int srcAddr);
	int setMemToReg(int regIdx, int srcAddr);
	int addRegToMem(int destAddr, int regIdx);
	int setRegToMem(int destAddr, int regIdx);
	void addRegToReg(int destReg, int srcReg);
	void setRegToReg(int destReg, int srcReg);

	int setMem4ToReg(int regIdx, int startAddr);
	int addMem4ToReg(int regIdx, int startAddr);
	int setMem2ToReg(int regIdx, int startAddr);
	void setRegToMem4(int startAddr, int regIdx);
	void addRegToMem4(int startAddr, int regIdx);
	void setRegToMem2(int startAddr, int regIdx);

        void setDTaint(int DIdx, int tValue);
        int getDTaint(int DIdx);
        void clearDTaint(int DIdx);
        int setMem8ToD(int DIdx, int startAddr);
        void setDToMem8(int startAddr, int DIdx);
        void setDToReg(int regIdx, int DIdx);
        void setRegToD(int DIdx,int regIdx);
        void setDToD(int destD, int srcD);
        void setDToS(int S, int D);


        void setSTaint(int SIdx, int tValue);
        int getSTaint(int SIdx);
        void clearSTaint(int SIdx);
        int setMem4ToS(int SIdx, int startAddr);
        void setSToMem4(int startAddr, int SIdx);
        void setSToReg(int regIdx, int SIdx);
        void setRegToS(int SIdx,int regIdx);
        void setSToS(int destS, int srcS);
        void setSToD(int D, int S);

#ifdef __cplusplus
}
#endif

#endif
