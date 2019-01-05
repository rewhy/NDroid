#include "nativejava.h"
#include <list>
#include <algorithm>
#include <map>
#include <fstream>
#include <iostream>
#include <string.h>
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
list<unsigned> jni_point;
multimap<int, methodInfo*> nativeMethodMap;
typedef pair<int, methodInfo*> int_methodInfo_pair;

bool find_point(unsigned offset){
    list<unsigned>::iterator it;
    it=find(jni_point.begin(), jni_point.end(), offset);
    if(it!=jni_point.end()){
        return true;
    }
    return false;
}

void trav_point(){
    list<unsigned>::iterator it;
    for (it=jni_point.begin();it!=jni_point.end();++it) {
        cout<<hex<<*it<<endl;
    }
}

void initNative(){
    f.open("native_offsets.txt", ios::in);
    // start -- zhouhao
		if(!f) {
			  printf("native_offsets.txt is not exist");
				return;
		}
		// -- end
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
            nativeMethodMap.insert(int_methodInfo_pair(codeOffset, mInfo));
            jni_point.push_back(codeOffset);
        }
    }
    printf("initNative done! map entry size: %d\n", nativeMethodMap.size());
    f.close();
}


int native_query(unsigned int codeOffset, char **className, char** methodName,int *type,int *ret,int* num,char ** args){
    multimap<int,methodInfo*>::iterator it = nativeMethodMap.find(codeOffset);
    if (it == nativeMethodMap.end()){
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
