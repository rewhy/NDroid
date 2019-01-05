#!/usr/bin/python
########################################
# Created By Chenxiong Qian
########################################

import sys
import re
import string

typeIdxClassName = {}    #typeIdx --> className
methodIdxTypeIdx = {}    #methodIdx --> typeIdx
methodIdxMethodName = {} #methodIdx --> methodName
codeOffsetMethodIdx = {} #codeOffset --> methodIdx
methodIdxMethodNameInvoketype = {}
methodIdxMethodNameNativetype = {}

def createFile():
    with open(sys.argv[2], 'w') as f:
        for k in codeOffsetMethodIdx.keys():
            codeOffset = int(k, 16) & 0xfffffffe
            for methodIdx in codeOffsetMethodIdx[k]:
                methodName = methodIdxMethodName[methodIdx]
                typeIdx = methodIdxTypeIdx[methodIdx]
                className = typeIdxClassName[typeIdx]
                invoketype = methodIdxMethodNameInvoketype[methodIdx]
                nativetype=methodIdxMethodNameNativetype[methodIdx]

                if isNative==1:
                    if cmp("native",nativetype)!=0:
                        continue
                if isNative==0:
                    if cmp("non-native",nativetype)!=0:
                        continue

                f.write("%d@%s@%s" % (codeOffset, methodName, className))  
                if cmp("static",invoketype):
                    f.write("@0")         #non-static
                else:
                    f.write("@1")

                ret=methodName.split(" ")
                if cmp("void",ret[0].strip())==0:
                    f.write("@0")
                else:
                    if cmp("double",ret[0].strip())==0:
                        f.write("@2")
                    else:
                        if cmp("long",ret[0].strip())==0:
                             f.write("@2")
                        else:
                            if cmp("char",ret[0].strip())==0:
                                f.write("@1")
                            else:
                                if cmp("byte",ret[0].strip())==0:
                                    f.write("@1")
                                else:
                                    if cmp("int",ret[0].strip())==0:
                                        f.write("@1")
                                    else:
                                        if cmp("float",ret[0].strip())==0:
                                            f.write("@1")
                                        else:
                                            if cmp("short",ret[0].strip())==0:
                                                f.write("@1")
                                            else:
                                                if cmp("boolean",ret[0].strip())==0:
                                                    f.write("@1")
                                                else:
                                                    f.write("@9")

                tmp=re.split("\(|\)",methodName)
                if len(tmp[1])==0:
                    f.write("@0\n")
                    continue 
                value=tmp[1].split(",")
                length=len(value)
                f.write("@%d@" % (length))
                for i in range(0,length):
                    if cmp("double",value[i].strip())==0:
                        f.write("2")
                    else:
                         if cmp("long",value[i].strip())==0:
                             f.write("2")
                         else:
                             if cmp("char",value[i].strip())==0:
                                 f.write("1")
                             else:
                                 if cmp("byte",value[i].strip())==0:
                                     f.write("1")
                                 else:
                                     if cmp("int",value[i].strip())==0:
                                         f.write("1")
                                     else:
                                         if cmp("float",value[i].strip())==0:
                                             f.write("1")
                                         else:
                                             if cmp("short",value[i].strip())==0:
                                                 f.write("1")
                                             else:
                                                 if cmp("boolean",value[i].strip())==0:
                                                     f.write("1")
                                                 else:
                                                     f.write("9")
                f.write("\n")


currTypeIdx = None
currMethodIdx = None
currChecksum = None
isNative = None

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "python createOATOffsetsDB.py input.dump output.db true/false"
    else:
	if cmp(sys.argv[3],"true")==0:
		isNative=0
	else:
		isNative=1	
	
        with open(sys.argv[1], 'r') as f:
            for line in f.readlines():
                #dex checksum
                if line.startswith("checksum: 0x"):
                    currChecksum = line.split("checksum: ")[1].strip()
                    print "checksum", currChecksum

                #type_idx = checksum#type_idx
                if "(type_idx=" in line:
                    className = line.split(';')[0].split(':')[1].strip()
                    typeIdx = currChecksum + "#" + line.split("(type_idx=")[1].split(')')[0].strip()
                    typeIdxClassName[typeIdx] = className
                    currTypeIdx = typeIdx

                #dex_method_idx = currTypeIdx#dex_method_idx = checksum#type_idx#dex_method_idx
                if "(dex_method_idx=" in line:
                    methodIdx = currTypeIdx + "#" + line.split("(dex_method_idx=")[1].split(')')[0].strip()
                    ##print "methodIdx: " + methodIdx ##zhouhao
                    ## start resolving method_access_flag ##zhouhao
                    method_access_flag = string.atoi(line.split("(dex_method_idx=")[1].split(')')[1].strip())
                    ##print "method_access_flag: " + str(method_access_flag)
                    if method_access_flag & 0x0008 != 0:
                        invoketype = "static"
                    else:
                        invoketype = "other"
                    if (method_access_flag & 0x0100 != 0) or (method_access_flag & 0x00080000 != 0):
                        nativetype = "native"
                    else:
                        nativetype = "non-native"
                    ## end ##zhouhao
                    ##invoketype = line.split("(dex_method_idx=")[1].split(')')[1].strip().split(' ')[0].strip()
                    ##print "invoketype: " + invoketype ##zhouhao
                    ##nativetype = line.split("(dex_method_idx=")[1].split(')')[1].strip().split(' ')[1].strip()
                    ##print "nativetype: " + nativetype ##zhouhao
                    methodName = line.split("(dex_method_idx=")[0].split(':')[1].strip()
                    ##print methodName
                    methodIdxTypeIdx[methodIdx] = currTypeIdx
                    methodIdxMethodNameInvoketype[methodIdx] = invoketype
                    methodIdxMethodNameNativetype[methodIdx] = nativetype
                    methodIdxMethodName[methodIdx] = methodName
                    currMethodIdx = methodIdx

                #CODE: ... (code_offset=0x******** size=) ## modify to match the structure obainted from oatdump -- zhouhao
                if "CODE" in line and "(code_offset=" in line:
                    codeOffset = line.split("(code_offset=")[1].split(' ')[0]
                    ##print "codeOffset: " + codeOffset
                    if codeOffset in codeOffsetMethodIdx.keys() and codeOffset != "0x00000000":
                        codeOffsetMethodIdx[codeOffset].append(currMethodIdx)
                    else:
                        codeOffsetMethodIdx[codeOffset] = []
                        codeOffsetMethodIdx[codeOffset].append(currMethodIdx)

        createFile()
