#!/usr/bin/python
########################################
# Created By Zhou Hao
######################################## 
import sys
import re
import string

methodOffsetList = []
methodNameList = []

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "python createSoOffsetFile.py input.dump output.db"
    else:
        with open(sys.argv[1], 'r') as f, open(sys.argv[2], 'w') as fw:
            for line in f.readlines():
                line_without_line_number = line.split(": ")[1]
                size = len(line_without_line_number.split(" "))
		methodOffset = line_without_line_number.split(" ")[0]
		methodName = line_without_line_number.split(" ")[size-1]
                fw.write("%x\t%s" % (int(methodOffset, 16) & 0xfffffffe, methodName))
            fw.close()         
            f.close()
