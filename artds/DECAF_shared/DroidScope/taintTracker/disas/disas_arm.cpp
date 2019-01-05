#include "disas_arm.h"
using namespace std;

#define UINT64_C(x)  (x ## ULL)

static inline bool HasBitSet(uint32_t value, uint32_t bit) {
  return (value & (1 << bit)) != 0;
}

int darm_bit_count_16(int bit_string){
	int bitCount = 0;
	int i = 0;
	for(; i < 16; i++){
		if((bit_string & (0b1 << i)) == 1){
			bitCount++;
		}
	}
	return bitCount;
}


static uint32_t ReadU16(const uint8_t* ptr) {
  return ptr[0] | (ptr[1] << 8);
}

static uint32_t ReadU32(const uint8_t* ptr) {
  return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
}



struct ArmRegister {
  explicit ArmRegister(uint32_t r) : r(r) {}
  ArmRegister(uint32_t instruction, uint32_t at_bit) : r((instruction >> at_bit) & 0xf) {}
  uint32_t r;
};


struct ThumbRegister : ArmRegister {
  ThumbRegister(uint16_t instruction, uint16_t at_bit) : ArmRegister((instruction >> at_bit) & 0x7) {}
};

struct Rm {
  explicit Rm(uint32_t instruction) : shift((instruction >> 4) & 0xff), rm(instruction & 0xf) {}
  uint32_t shift;
  ArmRegister rm;
};

struct RegisterList {
  explicit RegisterList(uint32_t instruction) : register_list(instruction & 0xffff) {}
  uint32_t register_list;
};


struct FpRegister {
  explicit FpRegister(uint32_t instr, uint16_t at_bit, uint16_t extra_at_bit) {
    size = (instr >> 8) & 1;
    uint32_t Vn = (instr >> at_bit) & 0xF;
    uint32_t N = (instr >> extra_at_bit) & 1;
    r = (size != 0 ? ((N << 4) | Vn) : ((Vn << 1) | N));
  }
  explicit FpRegister(uint32_t instr, uint16_t at_bit, uint16_t extra_at_bit,
                      uint32_t forced_size) {
    size = forced_size;
    uint32_t Vn = (instr >> at_bit) & 0xF;
    uint32_t N = (instr >> extra_at_bit) & 1;
    r = (size != 0 ? ((N << 4) | Vn) : ((Vn << 1) | N));
  }
  FpRegister(const FpRegister& other, uint32_t offset)
      : size(other.size), r(other.r + offset) {}

  uint32_t size;  // 0 = f32, 1 = f64
  uint32_t r;
};


struct FpRegisterRange {
  explicit FpRegisterRange(uint32_t instr)
      : first(instr, 12, 22), imm8(instr & 0xFF) {}
  FpRegister first;
  uint32_t imm8;
};


void DisassemblerArm::DumpArm( const uint8_t* instr_ptr,uint32_t addr, CPUState* env) {
    uint32_t instruction = ReadU32(instr_ptr);
    uint32_t op1 = (instruction >> 25) & 0x7;
    switch (op1) {
    case 0:
    case 1:  
      {
          if ((instruction & 0x0fffffd0) == 0x012fff10) {  
              setRegToReg(15,ArmRegister(instruction & 0xf).r); //TAINT
              break;
          }
      }
      break;
    case 2:  
      {
        bool p = (instruction & (1 << 24)) != 0;
        bool b = (instruction & (1 << 22)) != 0;
        bool w = (instruction & (1 << 21)) != 0;
        bool l = (instruction & (1 << 20)) != 0;
        ArmRegister rn(instruction, 16);        
        uint32_t memAddr=0;//TAINT
        if (rn.r == 0xf) {
        } else {
          bool wback = !p || w;
          uint32_t offset = (instruction & 0xfff);
          if (p && !wback) {
            memAddr=env->regs[rn.r]+offset;//TAINT
          } else if (p && wback) {
            memAddr=env->regs[rn.r]+offset;//TAINT
          } else if (!p && wback) {
            memAddr=env->regs[rn.r];//TAINT
          } 
        }

        /*TAINT*/
        if (l) {//ldr
            if (b) {
                setMemToReg(ArmRegister(instruction, 12).r,memAddr);
            }else{
                setMem4ToReg(ArmRegister(instruction, 12).r,memAddr);
            }
        }else{//str
            if (b) {
                setRegToMem(memAddr,ArmRegister(instruction, 12).r);
            }else{
                setRegToMem4(memAddr,ArmRegister(instruction, 12).r);
            }
        }
        /*TAINT*/
      }
      break;
    case 4:  // Load/store multiple.
      {
        bool p = (instruction & (1 << 24)) != 0;
        bool u = (instruction & (1 << 23)) != 0;
        bool l = (instruction & (1 << 20)) != 0;

        /*TAINT*/
        uint32_t memAddr=0;
        if (l) {//ldm
            if (u) {//towards high and obverse
                if (p) {//before
                    memAddr=env->regs[ArmRegister(instruction, 16).r]+4;
                }else{//after
                    memAddr=env->regs[ArmRegister(instruction, 16).r];
                }
                for (size_t i = 0,j = 0; i < 16; i++) {
                    if ((RegisterList(instruction).register_list & (1 << i)) != 0) {
                        setMem4ToReg(ArmRegister(i).r,memAddr+4*j);
                        j++;
                    }
                }
            }else{//towards low and reverse
                if (p) {//before
                    memAddr=env->regs[ArmRegister(instruction, 16).r]-4;
                }else{//after
                    memAddr=env->regs[ArmRegister(instruction, 16).r];
                }
                for (size_t i = 0,j = 0; i < 16; i++) {
                    if ((RegisterList(instruction).register_list & (0x8000 >> i)) != 0) {
                        setMem4ToReg(ArmRegister(i).r,memAddr-4*j);
                        j++;
                    }
                }
            }
        } else { //stm
            if (u) {//towards high and obverse
                if (p) {//before
                    memAddr=env->regs[ArmRegister(instruction, 16).r]+4;
                }else{//after
                    memAddr=env->regs[ArmRegister(instruction, 16).r];
                }
                for (size_t i = 0,j = 0; i < 16; i++) {
                    if ((RegisterList(instruction).register_list & (1 << i)) != 0) {
                        setRegToMem4(memAddr+4*j,ArmRegister(i).r);
                        j++;
                    }
                }
            }else{//towards low and reverse
                if (p) {//before
                    memAddr=env->regs[ArmRegister(instruction, 16).r]-4;
                }else{//after
                    memAddr=env->regs[ArmRegister(instruction, 16).r];
                }
                for (size_t i = 0,j = 0; i < 16; i++) {
                    if ((RegisterList(instruction).register_list & (0x8000 >> i)) != 0) {
                        setRegToMem4(memAddr-4*j,ArmRegister(i).r);
                        j++;
                    }
                }
            }
        }
        /*TAINT*/
      }
      break;
    default:
      break;
    }
}

int32_t ThumbExpand(int32_t imm12) {
  if ((imm12 & 0xC00) == 0) {
    switch ((imm12 >> 8) & 3) {
      case 0:
        return imm12 & 0xFF;
      case 1:
        return ((imm12 & 0xFF) << 16) | (imm12 & 0xFF);
      case 2:
        return ((imm12 & 0xFF) << 24) | ((imm12 & 0xFF) << 8);
      default:  // 3
        return ((imm12 & 0xFF) << 24) | ((imm12 & 0xFF) << 16) | ((imm12 & 0xFF) << 8) |
            (imm12 & 0xFF);
    }
  } else {
    uint32_t val = 0x80 | (imm12 & 0x7F);
    int32_t rotate = (imm12 >> 7) & 0x1F;
    return (val >> rotate) | (val << (32 - rotate));
  }
}

uint32_t VFPExpand32(uint32_t imm8) {
  uint32_t bit_a = (imm8 >> 7) & 1;
  uint32_t bit_b = (imm8 >> 6) & 1;
  uint32_t slice = imm8 & 0x3f;
  return (bit_a << 31) | ((1 << 30) - (bit_b << 25)) | (slice << 19);
}



size_t DisassemblerArm::DumpThumb32( const uint8_t* instr_ptr, uint32_t addr, CPUState* env) {
  uint32_t instr = (ReadU16(instr_ptr) << 16) | ReadU16(instr_ptr + 2);
  uint32_t op1 = (instr >> 27) & 3;

  if (op1 == 0) {
    return DumpThumb16(instr_ptr, addr, env);
  }

  uint32_t op2 = (instr >> 20) & 0x7F;
  switch (op1) {
    case 0:
      break;
    case 1:
      if ((op2 & 0x64) == 0) {  // 00x x0xx
        uint32_t op = (instr >> 23) & 3;
        uint32_t L = (instr >> 20) & 1;
        ArmRegister Rn(instr, 16);
        /* ARTDS START */
        uint32_t regList = RegisterList(instr).register_list;
        uint32_t memAddr = env->regs[Rn.r];
        size_t regIdx = 0;
        /* ARTDS END */
        if (op == 1 || op == 2) {
          if (op == 1) {
            if (L == 0) {
              /* ARTDS START */
              for (regIdx = 0; regIdx < 16; regIdx++){
                  if ((regList & (1 << regIdx)) != 0){
                      setRegToMem4(memAddr, regIdx);
                      memAddr += 4;
                  }
              }
              /* ARTDS END */
            } else {
              /* ARTDS START */
              for (regIdx = 0; regIdx < 16; regIdx++){
                  if ((regList & (1 << regIdx)) != 0){
                      setMem4ToReg(regIdx, memAddr);
                      memAddr += 4;
                  }
              }
              /* ARTDS END */
            }
          } else {
            if (L == 0) {
              /* ARTDS START */
              memAddr = env->regs[Rn.r] - (4 * darm_bit_count_16(regList));
              for (regIdx  = 0; regIdx < 16; regIdx++){
                  if ((regList & (1 << regIdx)) != 0){
                      setRegToMem4(memAddr, regIdx);
                      memAddr += 4;
                  }
              }
              /* ARTDS END */
            } else {
              /* ARTDS START */
              memAddr = env->regs[Rn.r] - (4 * darm_bit_count_16(regList));
              for (regIdx  = 0; regIdx < 16; regIdx++){
                  if ((regList & (1 << regIdx)) != 0){
                      setMem4ToReg(regIdx, memAddr);
                      memAddr += 4;
                  }
              }
              /* ARTDS END */
            }
          }
        }
      } else if ((op2 & 0x64) == 4) {  // 00x x1xx
        uint32_t op3 = (instr >> 23) & 3;
        uint32_t op4 = (instr >> 20) & 3;
        ArmRegister Rn(instr, 16);
        ArmRegister Rt(instr, 12);
        ArmRegister Rd(instr, 8);
        uint32_t imm8 = instr & 0xFF;
        if ((op3 & 2) == 2) {     // 1x
          int W = (instr >> 21) & 1;
          int U = (instr >> 23) & 1;
          int P = (instr >> 24) & 1;
          if (P == 0 && W == 1) {
            if ((op4 & 1) == 1) {
                setMem4ToReg(Rt.r,env->regs[Rn.r]);
                setMem4ToReg(Rd.r,env->regs[Rn.r]+4);
            }else{
                setRegToMem4(env->regs[Rn.r],Rt.r);
                setRegToMem4(env->regs[Rn.r]+4,Rd.r);
            }
          } else {
            if ((op4 & 1) == 1) {
                if (U) {
                    setMem4ToReg(Rt.r,env->regs[Rn.r]+(imm8 << 2));
                    setMem4ToReg(Rd.r,env->regs[Rn.r]+(imm8 << 2)+4);
                }else{
                    setMem4ToReg(Rt.r,env->regs[Rn.r]-(imm8 << 2));
                    setMem4ToReg(Rd.r,env->regs[Rn.r]-(imm8 << 2)+4);
                }
            } else {
                if (U) {
                    setRegToMem4(env->regs[Rn.r]+(imm8 << 2),Rt.r);
                    setRegToMem4(env->regs[Rn.r]+(imm8 << 2)+4,Rd.r);
                }else{
                    setRegToMem4(env->regs[Rn.r]-(imm8 << 2),Rt.r);
                    setRegToMem4(env->regs[Rn.r]-(imm8 << 2)+4,Rd.r);
                }
            }
          }
        } else {// 0x
            switch (op4) {
            case 0:
              if (op3 == 0) {   // op3 is 00, op4 is 00
                setRegToMem4(env->regs[Rn.r]+(imm8<<2),Rt.r);
              } else {          // op3 is 01, op4 is 00
                int op5 = (instr >> 4) & 0xf;
                switch (op5) {
                  case 4:
                  case 5:
                    Rd = ArmRegister(instr, 0);
                    if (op5 == 4) {
                        setRegToMem(env->regs[Rn.r], Rt.r);
                    }else{
                        setRegToMem2(env->regs[Rn.r],Rt.r);
                    }
                    break;
                  case 7:
                    ArmRegister Rt2 = Rd;
                    Rd = ArmRegister(instr, 0);
                    setRegToMem4(env->regs[Rn.r],Rt.r);
                    setRegToMem4(env->regs[Rn.r]+4,Rt2.r);
                    break;
                }
              }
              break;
            case 1:
              if (op3 == 0) {  // op3 is 00, op4 is 01
                setMem4ToReg(Rt.r,env->regs[Rn.r]+(imm8<<2));
              } else {          // op3 is 01, op4 is 01
                int op5 = (instr >> 4) & 0xf;
                switch (op5) {
                  case 4:
                  case 5:
                    if (op5 == 4) {
                        setMemToReg(Rt.r,env->regs[Rn.r]);
                    }else{
                        setMem2ToReg(Rt.r,env->regs[Rn.r]);
                    }
                    break;
                  case 7:
                    setMem4ToReg(Rt.r,env->regs[Rn.r]);
                    setMem4ToReg(Rd.r,env->regs[Rn.r]+4);
                    break;
                  default:break;
                }
              }
              break;
            case 2:     // op3 is 0x, op4 is 10
            case 3:   // op3 is 0x, op4 is 11
              int W = (instr >> 21) & 1;
              int U = (instr >> 23) & 1;
              int P = (instr >> 24) & 1;

              if (P == 0 && W == 1) {
                  if (op4 == 2) {
                      setRegToMem4(env->regs[Rn.r],Rt.r);
                      setRegToMem4(env->regs[Rn.r]+4,Rd.r);
                  }else{
                      setMem4ToReg(Rt.r,env->regs[Rn.r]);
                      setMem4ToReg(Rd.r,env->regs[Rn.r]+4);
                  }
              } else {
                if (op4 == 2) {
                    if (U) {
                        setRegToMem4(env->regs[Rn.r]+imm8,Rt.r);
                        setRegToMem4(env->regs[Rn.r]+imm8+4,Rd.r);
                    }else{
                        setRegToMem4(env->regs[Rn.r]-imm8,Rt.r);
                        setRegToMem4(env->regs[Rn.r]-imm8+4,Rd.r);
                    }
                }else{
                    if (U) {
                        setMem4ToReg(Rt.r,env->regs[Rn.r]+imm8);
                        setMem4ToReg(Rd.r,env->regs[Rn.r]+imm8+4);
                    }else{
                        setMem4ToReg(Rt.r,env->regs[Rn.r]-imm8);
                        setMem4ToReg(Rd.r,env->regs[Rn.r]-imm8+4);
                    }
                }
              }
              break;
          }
        }
      } else if ((op2 & 0x60) == 0x20) {  // 01x xxxx
        uint32_t op3 = (instr >> 21) & 0xF;
        ArmRegister Rd(instr, 8);
        ArmRegister Rn(instr, 16);
        ArmRegister Rm(instr, 0);
        switch (op3) {
          case 0x0:
            if (Rd.r != 0xF) {
              /* ARTDS START */
              setRegToReg(Rd.r, Rn.r);
              addRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            } 
            break;
          case 0x1:
            /* ARTDS START */
            setRegToReg(Rd.r, Rn.r);
            addRegToReg(Rd.r, Rm.r);
            /* ARTDS END */
            break;
          case 0x2:
            if (Rn.r != 0xF) {
              /* ARTDS START */
              setRegToReg(Rd.r, Rn.r);
              addRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            } else {
              /* ARTDS START */
              setRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            }
            break;
          case 0x3:
            if (Rn.r != 0xF) {
              /* ARTDS START */
              setRegToReg(Rd.r, Rn.r);
              addRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            } else {
              /* ARTDS START */
              setRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            }
            break;
          case 0x4:
            if (Rd.r != 0xF) {
              /* ARTDS START */
              setRegToReg(Rd.r, Rn.r);
              addRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            } 
            break;
          case 0x6:
            /* ARTDS START */
            setRegToReg(Rd.r, Rn.r);
            addRegToReg(Rd.r, Rm.r);
            /* ARTDS END */
            break;
          case 0x8:
            if (Rd.r != 0xF) {
              /* ARTDS START */
              setRegToReg(Rd.r, Rn.r);
              addRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            }
            break;
          case 0xA:
            /* ARTDS START */
            setRegToReg(Rd.r, Rn.r);
            addRegToReg(Rd.r, Rm.r);
            /* ARTDS END */
            break;
          case 0xB:
            /* ARTDS START */
            setRegToReg(Rd.r, Rn.r);
            addRegToReg(Rd.r, Rm.r);
            /* ARTDS END */
            break;
          case 0xD:
            if (Rd.r != 0xF) {
              /* ARTDS START */
              setRegToReg(Rd.r, Rn.r);
              addRegToReg(Rd.r, Rm.r);
              /* ARTDS END */
            } 
            break;
          case 0xE: 
            /* ARTDS START */
            setRegToReg(Rd.r, Rn.r);
            addRegToReg(Rd.r, Rm.r);
            /* ARTDS END */
            break;
          default:break;
        }
      } else if ((op2 & 0x40) == 0x40) {  // 1xx xxxx
        uint32_t op3 = (instr >> 20) & 0x3F;
        uint32_t coproc = (instr >> 8) & 0xF;
        uint32_t op4 = (instr >> 4) & 0x1;
        if (coproc == 0xA || coproc == 0xB) {   // 101x
          if (op3 < 0x20 && (op3 & ~5) != 0) {  // 0xxxxx and not 000x0x
            uint32_t P = (instr >> 24) & 1;
            uint32_t U = (instr >> 23) & 1;
            uint32_t W = (instr >> 21) & 1;
            if (P == U && W == 1) {
            } else {
              uint32_t L = (instr >> 20) & 1;
              uint32_t S = (instr >> 8) & 1;
              ArmRegister Rn(instr, 16);
              if (P == 1 && W == 0) {  // VLDR
                FpRegister d(instr, 12, 22);
                uint32_t imm8 = instr & 0xFF;
                if (L) {
                    if (S) {
                        if (U) {
                            setMem8ToD(d.r,env->regs[Rn.r]+(imm8<<2));
                        }else{
                            setMem8ToD(d.r,env->regs[Rn.r]-(imm8<<2));
                        }
                    }else{
                        if (U) {
                            setMem4ToS(d.r,env->regs[Rn.r]+(imm8<<2));
                        }else{
                            setMem4ToS(d.r,env->regs[Rn.r]-(imm8<<2));
                        }
                    }
                }else{
                     if (S) {
                        if (U) {
                            setDToMem8(env->regs[Rn.r]+(imm8<<2),d.r);
                        }else{
                            setDToMem8(env->regs[Rn.r]-(imm8<<2),d.r);
                        }
                    }else{
                        if (U) {
                            setSToMem4(env->regs[Rn.r]+(imm8<<2),d.r);
                        }else{
                            setSToMem4(env->regs[Rn.r]-(imm8<<2),d.r);
                        }
                    }
                }
              } else if (Rn.r == 13 && W == 1 && U == L) {  // VPUSH/VPOP
                FpRegisterRange rhs(instr);
                int count = (rhs.first.size != 0 ? ((rhs.imm8 + 1u) >> 1) : rhs.imm8);
                if (L) {
                    if (S) {
                        for (int i=0;i<count;i++) {
                            setMem8ToD(FpRegister(rhs.first,i).r,env->regs[13]+i*8);
                        }
                    }else{
                        for (int i=0;i<count;i++) {
                            setMem4ToS(FpRegister(rhs.first,i).r,env->regs[13]+i*4);
                        }
                    }
                }else{
                    if (S) {
                        for (int i=0;i<count;i++) {
                            setDToMem8(env->regs[13]-8*(i+1),FpRegister(rhs.first,i).r);
                        }
                    }else{
                        for (int i=0;i<count;i++) {
                            setSToMem4(env->regs[13]-4*(i+1),FpRegister(rhs.first,i).r);
                        }
                    }
                }
              } else {  // VLDM
                FpRegisterRange rhs(instr);
                int count = (rhs.first.size != 0 ? ((rhs.imm8 + 1u) >> 1) : rhs.imm8);
                if (L) {
                    if (S) {
                        for (int i=0;i<count;i++) {
                            setMem8ToD(FpRegister(rhs.first,i).r,env->regs[Rn.r]+i*8);
                        }
                    }else{
                        for (int i=0;i<count;i++) {
                            setMem4ToS(FpRegister(rhs.first,i).r,env->regs[Rn.r]+i*4);
                        }
                    }
                }else{
                    if (S) {
                        for (int i=0;i<count;i++) {
                            setDToMem8(env->regs[Rn.r]+8*i,FpRegister(rhs.first,i).r);
                        }
                    }else{
                        for (int i=0;i<count;i++) {
                            setSToMem4(env->regs[Rn.r]+4*i,FpRegister(rhs.first,i).r);
                        }
                    }
                }
              }
            }
          } else if ((op3 >> 1) == 2) {
            if ((instr & 0xD0) == 0x10) {
              uint32_t L = (instr >> 20) & 1;
              uint32_t S = (instr >> 8) & 1;
              ArmRegister Rt2(instr, 16);
              ArmRegister Rt(instr, 12);
              FpRegister m(instr, 0, 5);
              if (S) {
                if (L) {
                    setDToReg(Rt.r, m.r);
                    setDToReg(Rt2.r,m.r);
                }else{
                    setRegToD(m.r,Rt.r);
                    setRegToD(m.r,Rt2.r);
                }
              } else {
                if (L) {
                    setSToReg(Rt.r, m.r);
                    setSToReg(Rt2.r,m.r+1);
                }else{
                    setRegToS(m.r,Rt.r);
                    setRegToS(m.r+1,Rt2.r);
                }
              }
            }
          } else if ((op3 >> 4) == 2 && op4 == 0) {  // 10xxxx, op = 0
            uint32_t S = (instr >> 8) & 1;
            uint32_t Q = (instr >> 6) & 1;
            FpRegister d(instr, 12, 22);
            FpRegister n(instr, 16, 7);
            FpRegister m(instr, 0, 5);
            if ((op3 & 0xB) == 0) {  // 100x00
              if (S) {
                  setDToD(d.r,m.r);
                  setDToD(d.r,n.r);
              }else{
                  setSToS(d.r,m.r);
                  setSToS(d.r,n.r);
              }
              
            } else if ((op3 & 0xB) == 0x2) {  // 100x10
              if (S) {
                  setDToD(d.r,m.r);
                  setDToD(d.r,n.r);
              }else{
                  setSToS(d.r,m.r);
                  setSToS(d.r,n.r);
              }

            } else if ((op3 & 0xB) == 0x3) {  // 100x11
              if (S) {
                  setDToD(d.r,m.r);
                  setDToD(d.r,n.r);
              }else{
                  setSToS(d.r,m.r);
                  setSToS(d.r,n.r);
              }

            } else if ((op3 & 0xB) == 0x8 && Q == 0) {  // 101x00, Q == 0
              if (S) {
                  setDToD(d.r,m.r);
                  setDToD(d.r,n.r);
              }else{
                  setSToS(d.r,m.r);
                  setSToS(d.r,n.r);
              }

            } else if ((op3 & 0xB) == 0xB && Q == 0) {  // 101x11, Q == 0
              if (S) {
                  clearDTaint(d.r);
              }else{
                  clearSTaint(d.r);
              }

            } else if ((op3 & 0xB) == 0xB && Q == 1) {
              uint32_t op5 = (instr >> 16) & 0xF;
              uint32_t op = (instr >> 7) & 1;
              FpRegister Dd(instr, 12, 22, 1);
              FpRegister Sd(instr, 12, 22, 0);
              FpRegister Dm(instr, 0, 5, 1);
              FpRegister Sm(instr, 0, 5, 0);
              if (op5 == 0) {
                if (S) {
                    setDToD(d.r,m.r);
                }else{
                    setSToS(d.r,m.r);
                }
              } else if (op5 == 1) {
                if (S) {
                    setDToD(d.r,m.r);
                }else{
                    setSToS(d.r,m.r);
                }
              } else if (op5 == 0xD) {
                if (S == 1) {
                  // vcvt{r}.s32.f64
                  setDToS(Sd.r,Dm.r);
                } else {
                  // vcvt{r}.s32.f32
                  setSToS(Sd.r,Sm.r);
                }
              } else if (op5 == 0xC) {
                if (S == 1) {
                  // vcvt{r}.u32.f64
                  setDToS(Sd.r,Dm.r);
                } else {
                  // vcvt{r}.u32.f32
                  setSToS(Sd.r,Sm.r);
                }
              } else if (op5 == 0x8) {
                if (S == 1) {
                  // vcvt.f64.<Tm>
                  setSToD(Dd.r,Sm.r);
                } else {
                  // vcvt.f32.<Tm>
                  setSToS(Sd.r,Sm.r);
                }
              } else if (op5 == 0x7) {
                if (op == 1) {
                  if (S == 1) {
                    // vcvt.f64.f32
                    setSToD(Dd.r,Sm.r);
                  } else {
                    // vcvt.f32.f64
                    setDToS(Sd.r,Dm.r);
                  }
                }
              } 
          }
        } else if ((op3 >> 4) == 2 && op4 == 1) {     // 10xxxx, op = 1
            if (coproc == 10 && (op3 & 0xE) == 0) {  // VMOV (between ARM core register and single-precision register)
              uint32_t op = op3 & 1;
              ArmRegister Rt(instr, 12);
              FpRegister n(instr, 16, 7);
              if (op) {
                  setSToReg(Rt.r,n.r);
              } else {
                  setRegToS(n.r,Rt.r);
              }
            } 
          }
        }
      }
      break;
    case 2:
      if ((instr & 0x8000) == 0 && (op2 & 0x20) == 0) {
        uint32_t op3 = (instr >> 21) & 0xF;
        uint32_t S = (instr >> 20) & 1;
        ArmRegister Rn(instr, 16);
        ArmRegister Rd(instr, 8);
        if (Rn.r == 0xF && (op3 == 0x2 || op3 == 0x3)) {
          /* ARTDS START */
          clearRegTaint(Rd.r);
          /* ARTDS END */
        } else if (Rd.r == 0xF && S == 1 &&
                   (op3 == 0x0 || op3 == 0x4 || op3 == 0x8 || op3 == 0xD)) {
        } else {
          /* ARTDS START */
          setRegToReg(Rd.r, Rn.r);
          /* ARTDS END */
        }
      } else if ((instr & 0x8000) == 0 && (op2 & 0x20) != 0) {
        uint32_t op3 = (instr >> 20) & 0x1F;
        switch (op3) {
          case 0x00: case 0x0A: {
            ArmRegister Rd(instr, 8);
            ArmRegister Rn(instr, 16);
            /* ARTDS START */
            setRegToReg(Rd.r, Rn.r);
            /* ARTDS END */
            break;
          }
          case 0x04: case 0x0C: {
            ArmRegister Rd(instr, 8);
            /* ARTDS START */
            if (op3 == 0x04){
                clearRegTaint(Rd.r);
            }
            /* ARTDS END */
            break;
          }
          case 0x16: {
            ArmRegister Rd(instr, 8);
            ArmRegister Rn(instr, 16);
            uint32_t msb = instr & 0x1F;
            uint32_t imm2 = (instr >> 6) & 0x3;
            uint32_t imm3 = (instr >> 12) & 0x7;
            uint32_t lsb = (imm3 << 2) | imm2;
            uint32_t width = msb - lsb + 1;
            if (Rn.r != 0xF) {
              /* ARTDS START */
              if (width == 32){
                  setRegToReg(Rd.r, Rn.r);
              }else{
                  addRegToReg(Rd.r, Rn.r);
              }
              /* ARTDS END */
            } else {
              /* ARTDS START */
              if (width == 32){
                  clearRegTaint(Rd.r);
              }
              /* ARTDS END */
            }
            break;
          }
          default:
            break;
        }
      } 
      break;
    case 3:
      switch (op2) {
        case 0x00: case 0x02: case 0x04: case 0x06:  // 000xxx0
        case 0x08: case 0x09: case 0x0A: case 0x0C: case 0x0E: {

          uint32_t op3 = (instr >> 21) & 7;
          switch (op3) {
            case 0x0: case 0x4: {
              ArmRegister Rn(instr, 16);
              ArmRegister Rt(instr, 12);

              /* ARTDS START */
              uint32_t memAddr = 0;
              /* ARTDS END */

              if (HasBitSet(instr, 23)) {
              } else if ((instr & 0x800) != 0) {
                  uint32_t imm8 = instr & 0xFF;
                  memAddr = env->regs[Rn.r] + imm8; //ARTDS
              } else {
                uint32_t imm2 = (instr >> 4) & 3;
                ArmRegister Rm(instr, 0);
                if (imm2 != 0) {
                  memAddr = env->regs[Rn.r] + (env->regs[Rm.r] << imm2);//ARTDS
                }else{//ARTDS
                    memAddr = env->regs[Rn.r] + env->regs[Rm.r];//ARTDS
                }//ARTDS
                /* ARTDS START */
                setRegToMem(memAddr, Rt.r);
                /* ARTDS END */
              }
              break;
            }
            case 0x1: case 0x5: {
              ArmRegister Rn(instr, 16);
              ArmRegister Rt(instr, 12);
              if (HasBitSet(instr, 23)) {
                uint32_t imm12 = instr & 0xFFF;
                setRegToMem2(env->regs[Rn.r]+imm12,Rt.r);
              }else if ((instr & 0x800) != 0) {
                uint32_t imm8 = instr & 0xFF;
                setRegToMem2(env->regs[Rn.r]+imm8,Rt.r);
              } else {
                uint32_t imm2 = (instr >> 4) & 3;
                ArmRegister Rm(instr, 0);
                setRegToMem2(env->regs[Rn.r]+(env->regs[Rm.r]<<imm2),Rt.r);
              }
              break;
            }
            case 0x2: case 0x6: {
              ArmRegister Rn(instr, 16);
              ArmRegister Rt(instr, 12);
              if (op3 == 2) {
                if ((instr & 0x800) != 0) {
                  uint32_t P = (instr >> 10) & 1;
                  uint32_t U = (instr >> 9) & 1;
                  uint32_t W = (instr >> 8) & 1;
                  uint32_t imm8 = instr & 0xFF;
                  int32_t imm32 = (imm8 << 24) >> 24;  // sign-extend imm8
                  if (Rn.r == 13 && P == 1 && U == 0 && W == 1 && imm32 == 4) {
                    /* ARTDS START */
                    setRegToMem4(env->regs[13], Rt.r);
                    /* ARTDS END */
                  } else if (Rn.r == 15 || (P == 0 && W == 0)) {
                  } else {
                    uint32_t memAddr = 0; //ARTDS
                    if (P == 0 && W == 1) {
                      memAddr = env->regs[Rn.r]; //ARTDS
                    } else {
                      memAddr = env->regs[Rn.r] + imm32; //ARTDS
                    }
                    setRegToMem4(memAddr, Rt.r);//ARTDS
                  }
                } else {
                  ArmRegister Rm(instr, 0);
                  uint32_t imm2 = (instr >> 4) & 3;
                  uint32_t memAddr = 0;//ARTDS
                  if (imm2 != 0) {
                    memAddr = env->regs[Rn.r] + (env->regs[Rm.r] << imm2);//ARTDS
                  }else{//ARTDS
                    memAddr = env->regs[Rn.r] + env->regs[Rm.r]; //ARTDS
                  }//ARTDS
                  setRegToMem4(memAddr, Rt.r);//ARTDS
                }
              } else if (op3 == 6) {
                uint32_t imm12 = instr & 0xFFF;
                /* ARTDS START */
                uint32_t memAddr = env->regs[Rn.r] + imm12;
                setRegToMem4(memAddr, Rt.r);
                /* ARTDS END */
              }
              break;
            }
          }

          break;
        }
        case 0x03: case 0x0B: case 0x11: case 0x13: case 0x19: case 0x1B: {  // 00xx011
          uint32_t op3 = (instr >> 23) & 3;
          ArmRegister Rn(instr, 16);
          ArmRegister Rt(instr, 12);
          if (Rt.r != 15) {
            if (op3 == 1) {
              uint32_t imm12 = instr & 0xFFF;
              /* ARTDS START */
              setMem2ToReg(Rt.r, env->regs[Rn.r] + imm12);
              /* ARTDS END */
            } else if (op3 == 3) {
              uint32_t imm12 = instr & 0xFFF;
              /* ARTDS START */
              setMem2ToReg(Rt.r, env->regs[Rn.r] + imm12);
              /* ARTDS END */
            }else if(op3 == 0){
                ArmRegister Rm(instr,0);
                uint32_t imm2=instr>>4&3;
                setMem2ToReg(Rt.r,env->regs[Rn.r]+(env->regs[Rm.r]<<imm2));
            }
          }
          break;
        }
        case 0x05: case 0x0D: case 0x15: case 0x1D: {  // 00xx101
          uint32_t op3 = (instr >> 23) & 3;
          uint32_t op4 = (instr >> 6) & 0x3F;
          ArmRegister Rn(instr, 16);
          ArmRegister Rt(instr, 12);
          if (op3 == 1 || Rn.r == 15) {
            uint32_t imm12 = instr & 0xFFF;
            /* ARTDS START */
            setMem4ToReg(Rt.r, env->regs[Rn.r] + imm12);
            /* ARTDS END */
          } else if (op4 == 0) {
            uint32_t imm2 = (instr >> 4) & 0xF;
            ArmRegister rm(instr, 0);
            uint32_t memAddr = 0; //ARTDS
            if (imm2 != 0) {
              memAddr = env->regs[Rn.r] + (env->regs[rm.r] << imm2); //ARTDS
            }else{//ARTDS
              memAddr = env->regs[Rn.r] + env->regs[rm.r]; //ARTDS
	    }//ARTDS
            setMem4ToReg(Rt.r, memAddr);//ARTDS
          } else {
            bool p = (instr & (1 << 10)) != 0;
            bool w = (instr & (1 << 8)) != 0;
            bool u = (instr & (1 << 9)) != 0;
            if (p && u && !w) {
              uint32_t imm8 = instr & 0xFF;
              /* ARTDS START */
              setMem4ToReg(Rt.r, env->regs[Rn.r] + imm8);
              /* ARTDS END */
            }else if (Rn.r == 13 && !p && u && w && (instr & 0xff) == 4) {
              setMem4ToReg(Rt.r,env->regs[13]);
           } else {
              bool wback = !p || w;
              uint32_t offset = (instr & 0xff);
              if (p && !wback) {
                setMem4ToReg(Rt.r,env->regs[Rn.r]+offset);
              } else if (p && wback) {
                setMem4ToReg(Rt.r,env->regs[Rn.r]+offset);
              } else if (!p && wback) {
                setMem4ToReg(Rt.r,env->regs[Rn.r]);
              } 
            }
          }
          break;
        }
        default:      // more formats
        if ((op2 >> 4) == 2) {      // 010xxxx
          if ((instr & 0x0080f0f0) == 0x0000f000) {
            ArmRegister Rd(instr, 8);
            ArmRegister Rn(instr, 16);
            ArmRegister Rm(instr, 0);
            setRegToReg(Rd.r,Rn.r);
            setRegToReg(Rd.r,Rm.r);
          }
        } else if ((op2 >> 3) == 6) {       // 0110xxx
          op1 = (instr >> 20) & 0x7;
          op2 = (instr >> 4) & 0x2;
          ArmRegister Ra(instr, 12);
          ArmRegister Rn(instr, 16);
          ArmRegister Rm(instr, 0);
          ArmRegister Rd(instr, 8);
          switch (op1) {
          case 0:
            if (op2 == 0) {
              if (Ra.r == 0xf) {
                setRegToReg(Rd.r,Rn.r);
                setRegToReg(Rd.r,Rm.r);
              } else {
                setRegToReg(Rd.r,Rn.r);
                setRegToReg(Rd.r,Rm.r);
                setRegToReg(Rd.r,Ra.r);
              }
            } else {
              setRegToReg(Rd.r,Rn.r);
              setRegToReg(Rd.r,Rm.r);
              setRegToReg(Rd.r,Ra.r);
            }
            break;
          case 1:
          case 2:
          case 3:
          case 4:
          case 5:
          case 6:
              break;        // do these sometime
          }
          } else if ((op2 >> 3) == 7) {       // 0111xxx
          op1 = (instr >> 20) & 0x7;
          op2 = (instr >> 4) & 0xf;
          ArmRegister Rn(instr, 16);
          ArmRegister Rm(instr, 0);
          ArmRegister Rd(instr, 8);
          ArmRegister RdHi(instr, 8);
          ArmRegister RdLo(instr, 12);
          switch (op1) {
          case 0:
            setRegToReg(RdLo.r,Rn.r);
            setRegToReg(RdHi.r,Rn.r);
            setRegToReg(RdLo.r,Rm.r);
            setRegToReg(RdHi.r,Rm.r);
            break;
          case 1:
            setRegToReg(Rd.r,Rn.r);
            setRegToReg(Rd.r,Rm.r);
            break;
          case 2:
            setRegToReg(RdLo.r,Rn.r);
            setRegToReg(RdHi.r,Rn.r);
            setRegToReg(RdLo.r,Rm.r);
            setRegToReg(RdHi.r,Rm.r);
            break;
          case 3:
            setRegToReg(Rd.r,Rn.r);
            setRegToReg(Rd.r,Rm.r);
            break;
          case 4:
          case 5:
          case 6:
            break;     
          }
        }
      }
      break;
    default:
      break;
  }
  return 4;
}  

size_t DisassemblerArm::DumpThumb16( const uint8_t* instr_ptr, uint32_t addr, CPUState* env) {
  uint16_t instr = ReadU16(instr_ptr);
  bool is_32bit = ((instr & 0xF000) == 0xF000) || ((instr & 0xF800) == 0xE800);
  if (is_32bit) {
    return DumpThumb32(instr_ptr, addr, env);
  } else {
     uint16_t opcode1 = instr >> 10;
    if (opcode1 < 0x10) {
      uint16_t opcode2 = instr >> 9;
      switch (opcode2) {
        case 0x0: case 0x1: case 0x2: case 0x3: case 0x4: case 0x5: case 0x6: case 0x7:
        case 0x8: case 0x9: case 0xA: case 0xB: {
          ThumbRegister rm(instr, 3);
          ThumbRegister Rd(instr, 0);
          /* ARTDS START */
          setRegToReg(Rd.r, rm.r);
          /* ARTDS END */
          break;
        }
        case 0xC: case 0xD: case 0xE: case 0xF: {
          uint16_t imm3_or_Rm = (instr >> 6) & 7;
          ThumbRegister Rn(instr, 3);
          ThumbRegister Rd(instr, 0);

          /* ARTDS START */
          setRegToReg(Rd.r, Rn.r);
          /* ARTDS END */
          if ((opcode2 & 2) == 0) {
            ArmRegister Rm(imm3_or_Rm);
            /* ARTDS START */
            addRegToReg(Rd.r, Rm.r);
            /* ARTDS END */
          }
          break;
        }
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x14: case 0x15: case 0x16: case 0x17:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x1C: case 0x1D: case 0x1E: case 0x1F: {
          ThumbRegister Rn(instr, 8);
          switch (opcode2 >> 2) {
            case 4:
              /* ARTDS START */
              clearRegTaint(Rn.r);
              /* ARTDS END */
              break;
              default:break;
          }
          break;
        }
        default:
          break;
      }
    } else if (opcode1 == 0x10) {
      uint16_t opcode2 = (instr >> 6) & 0xF;
      ThumbRegister rm(instr, 3);
      ThumbRegister rdn(instr, 0);
      /* ARTDS START */
      if (opcode2 < 0x8){
          addRegToReg(rdn.r, rm.r);
      }else if (opcode2 >= 0xc && opcode2 <= 0xe){
          addRegToReg(rdn.r, rm.r);
      }else if (opcode2 == 0x9 || opcode1 == 0xf){
          setRegToReg(rdn.r, rm.r);
      }
      /* ARTDS END */
    } else if (opcode1 == 0x11) {
      uint16_t opcode2 = (instr >> 6) & 0x0F;
      switch (opcode2) {
        case 0x0: case 0x1: case 0x2: case 0x3: {
          uint16_t DN = (instr >> 7) & 1;
          ArmRegister rm(instr, 3);
          uint16_t Rdn = instr & 7;
          ArmRegister DN_Rdn((DN << 3) | Rdn);
          /* ARTDS START */
          addRegToReg(DN_Rdn.r, rm.r);
          /* ARTDS END */
          break;
        }
        case 0x8: case 0x9: case 0xA: case 0xB: {
          uint16_t DN = (instr >> 7) & 1;
          ArmRegister rm(instr, 3);
          uint16_t Rdn = instr & 7;
          ArmRegister DN_Rdn((DN << 3) | Rdn);
          /* ARTDS START */
          setRegToReg(DN_Rdn.r, rm.r);
          /* ARTDS END */
          break;
        }
        default:
          break;
      }
    } else if (opcode1 == 0x12 || opcode1 == 0x13) {  // 01001x
      ThumbRegister Rt(instr, 8);
      uint16_t imm8 = instr & 0xFF;
      /* ARTDS START */
      uint32_t memAddr = env->regs[15] + (imm8 << 2);
      setMemToReg(Rt.r, memAddr);
      /* ARTDS END */
    } else if ((opcode1 >= 0x14 && opcode1 <= 0x17) ||  // 0101xx
               (opcode1 >= 0x18 && opcode1 <= 0x1f) ||  // 011xxx
               (opcode1 >= 0x20 && opcode1 <= 0x27)) {  // 100xxx
      uint16_t opA = (instr >> 12) & 0xF;
      if (opA == 0x5) {
        uint16_t opB = (instr >> 9) & 0x7;
        ThumbRegister Rm(instr, 6);
        ThumbRegister Rn(instr, 3);
        ThumbRegister Rt(instr, 0);
        uint32_t memAddr = env->regs[Rm.r] + env->regs[Rn.r];//ARTDS
        switch (opB) {
          case 0:
            setRegToMem4(memAddr, Rt.r);//ARTDS
            break;
          case 1:
            setRegToMem2(memAddr, Rt.r);//ARTDS
	    break;
          case 2: 
            setRegToMem(memAddr, Rt.r);//ARTDS
	    break;
          case 3: 
            setMemToReg(Rt.r, memAddr);//ARTDS
	    break;
          case 4: 
            setMem4ToReg(Rt.r, memAddr);//ARTDS
	    break;
          case 5: 
            setMem2ToReg(Rt.r, memAddr);//ARTDS
	    break;
          case 6: 
            setMemToReg(Rt.r, memAddr);//ARTDS
	    break;
          case 7:
            setMem2ToReg(Rt.r, memAddr);//ARTDS
            break;
        }
      } else if (opA == 9) {
        uint16_t opB = (instr >> 11) & 1;
        ThumbRegister Rt(instr, 8);
        uint16_t imm8 = instr & 0xFF;
        /* ARTDS START */
        uint32_t memAddr = env->regs[13] + (imm8 << 2);
        if (opB == 0){
            setRegToMem4(memAddr, Rt.r);
        }else{
            setMem4ToReg(Rt.r, memAddr);
        }
        /* ARTDS END */
      } else {
        uint16_t imm5 = (instr >> 6) & 0x1F;
        uint16_t opB = (instr >> 11) & 1;
        ThumbRegister Rn(instr, 3);
        ThumbRegister Rt(instr, 0);
        uint32_t memAddr = 0; //ARTDS
        switch (opA) {
          case 6:
            imm5 <<= 2;
            /* ARTDS START */
            memAddr = env->regs[Rn.r] + imm5;
            if (opB == 0){
                setRegToMem4(memAddr, Rt.r);
            }else{
                setMem4ToReg(Rt.r, memAddr);
            }
            /* ARTDS END */
            break;
          case 7:
            imm5 <<= 0;
            /* ARTDS START */
            memAddr = env->regs[Rn.r] + imm5;
            if (opB == 0){
                setRegToMem(memAddr, Rt.r);
            }else{
                setMemToReg(Rt.r, memAddr);
            }
            /* ARTDS END */
            break;
          case 8:
            imm5 <<= 1;
            /* ARTDS START */
            memAddr = env->regs[Rn.r] + imm5;
            if (opB == 0){
                setRegToMem2(memAddr, Rt.r);
            }else{
                setMem2ToReg(Rt.r, memAddr);
            }
            /* ARTDS END */
            break;
        }
      }
    } else if (opcode1 >= 0x34 && opcode1 <= 0x37) {  
    } else if ((instr & 0xF800) == 0xA800) {
      ThumbRegister rd(instr, 8);
      /* ARTDS START */
      setRegToReg(rd.r, 13);
      /* ARTDS END */
    } else if ((instr & 0xF000) == 0xB000) {
    } else if (((instr & 0xF000) == 0x5000) || ((instr & 0xE000) == 0x6000) ||
        ((instr & 0xE000) == 0x8000)) {
      uint16_t opA = instr >> 12;
      switch (opA) {
        case 0x6: {
          uint16_t imm5 = (instr >> 6) & 0x1F;
          ThumbRegister Rn(instr, 3);
          ThumbRegister Rt(instr, 0);
          /* ARTDS START */
          uint32_t memAddr = env->regs[Rn.r] + (imm5 << 2);
          if ((instr & 0x800) == 0){//str
              setRegToMem4(memAddr, Rt.r);
          }else{
              setMem4ToReg(Rt.r, memAddr);
          }
          /* ARTDS END */
          break;
        }
        case 0x9: {
          uint16_t imm8 = instr & 0xFF;
          ThumbRegister Rt(instr, 8);
          /* ARTDS START */
          uint32_t memAddr = env->regs[13] + (imm8 << 2);
          if ((instr & 0x800) == 0){
              setRegToMem4(memAddr, Rt.r);
          }else{
              setMem4ToReg(Rt.r, memAddr);
          }
          /* ARTDS END */
          break;
        }
        default:
          break;
      }
    } 
  }
  return 2;
}


DisassemblerArm *dis_arm=NULL;

void initDump()
{
    dis_arm= new DisassemblerArm;
}
void endDump()
{
    delete dis_arm;
}
void DumpArm(const uint8_t* instr,uint32_t addr, CPUState* env)
{
    dis_arm->DumpArm(instr, addr, env);
}
size_t DumpThumb(const uint8_t* instr,uint32_t addr, CPUState* env)
{
    return dis_arm->DumpThumb16(instr, addr, env);
}

