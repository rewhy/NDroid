#include "dex_offset.h"
#include <map>
#include <fstream>
#include <iostream>
#include <string.h>
#include "DECAF_shared/utils/OutputWrapper.h"

using namespace std;

typedef struct methodInfo_{
    char methodName[1024];
    char className[1024];
    int ret;
    int num;
    int type;
    char *args;
} methodInfo;

static fstream f;
multimap<int, methodInfo*> dexMethodMap;
typedef pair<int, methodInfo*> int_methodInfo_pair;

void initDex(){
    f.open("dex_offsets.txt", ios::in);
    // start -- zhouhao
		if(!f) {
			  printf("dex_offsets.txt is not exist\n");
				return;
		}
		// end
		char buf[2048+16];
    while (!f.eof()){
        f.getline(buf, 2048+16, '\n');
        char* p;
        //code offset
        p = strtok(buf, "@");
        if (p){
            int codeOffset = atoi(p);
            methodInfo* mInfo = (methodInfo*)calloc(1, sizeof(methodInfo));
            //method name
            p = strtok(0, "@"); 
            strncpy(mInfo->methodName, p, 1024);
            //class name
            p = strtok(0, "@");
            strncpy(mInfo->className, p, 1024);

            p = strtok(0,"@");
            mInfo->type=atoi(p);

            p = strtok(0,"@");
            mInfo->ret=atoi(p);

            p = strtok(0,"@");
            mInfo->num=atoi(p);

            if (mInfo->num==0) {
                mInfo->args=0;
            }else{
                mInfo->args=(char*)calloc(1,mInfo->num+1);
                mInfo->args[mInfo->num]=0;
                p = strtok(0, "@");
                strncpy(mInfo->args,p,mInfo->num);
            }
            dexMethodMap.insert(int_methodInfo_pair(codeOffset, mInfo));
        }
    }
    f.close();
    printf("initDex done! map entry size: %d\n", dexMethodMap.size());
}

int dex_query(unsigned int codeOffset, char **className, char** methodName,int *type,int *ret,int* num,char ** args){
    multimap<int,methodInfo*>::iterator it = dexMethodMap.find(codeOffset);
    if (it == dexMethodMap.end()){
        return (-1);
    }

    *className=it->second->className;
    *methodName=it->second->methodName;
    *type=it->second->type;
    *ret=it->second->ret;
    *num=it->second->num;
    *args=it->second->args;
    return (0);
}

