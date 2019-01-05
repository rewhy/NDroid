#include "cpu.h"
#include "DECAF_shared/DroidScope/taintTracker/taint/TaintEngine.h"

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef int                int32_t;
typedef signed char        int8_t;

#ifdef __cplusplus
extern "C" 
{
#endif

void initDump();
void endDump();
void DumpArm(const uint8_t* instr, uint32_t addr, CPUState* env);
size_t DumpThumb(const uint8_t* instr, uint32_t addr, CPUState* env);

#ifdef __cplusplus
}
#include <vector>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <ostream>
#include <sstream>
#include <fstream>



class DisassemblerArm{
 public:

  void DumpArm(const uint8_t* instr, uint32_t addr, CPUState* env);
  size_t DumpThumb16(const uint8_t* instr, uint32_t addr, CPUState* env);
  size_t DumpThumb32(const uint8_t* instr_ptr, uint32_t addr, CPUState* env);

};
#endif
