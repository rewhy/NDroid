/**
 * Created By Chenxiong Qian
 * date: 2014-11-25
 */
#include "framework_offsets.h"
#include <fstream>
#include <iostream>
//#include <hash_map>
#include <string.h>
#include <map>
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

multimap<int, methodInfo*> codeOffsetMethodInfoMap;
typedef pair<int, methodInfo*> int_methodInfo_pair;

void initFramework(){
	  printf("invoke initFramework() start\n");
    f.open("boot_offsets.txt", ios::in);
    char buf[2048+16];
    while (!f.eof()){
        f.getline(buf, 2048+16, '\n');
				// printf("line content: %s\n", buf);
        char* p;
        // code offset
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
						// DECAF_printf("Offset=%x, MethodName=%s, ClassName=%s, Type=%d, Ret=%d, Num=%d\n",codeOffset, mInfo->methodName, mInfo->className, mInfo->type, mInfo->ret, mInfo->num); // -- zhouhao
            codeOffsetMethodInfoMap.insert(int_methodInfo_pair(codeOffset, mInfo));
        }
    }
		printf("invoke initFramework() end\n");
    f.close();
    printf("initFramework done! map entry size: %d\n", codeOffsetMethodInfoMap.size());
}


int framework_query(unsigned int codeOffset, char **className, char** methodName,int *type,int *ret,int* num,char ** args){
    multimap<int,methodInfo*>::iterator it = codeOffsetMethodInfoMap.find(codeOffset);
    if (it == codeOffsetMethodInfoMap.end()){
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

//test
/*
int main(){
    initFramework();
    char* methodName;
    char* className;
    
    methodName = (char*)calloc(1024, sizeof(char));
    className = (char*)calloc(1024, sizeof(char));
    framework_query(41906092, className, methodName);
    printf("%s --> %s\n", className, methodName);
    free(methodName);
    free(className);

    methodName = (char*)calloc(1024, sizeof(char));
    className = (char*)calloc(1024, sizeof(char));
    framework_query(29846444, className, methodName);
    printf("%s --> %s\n", className, methodName);
    free(methodName);
    free(className);

    methodName = (char*)calloc(1024, sizeof(char));
    className = (char*)calloc(1024, sizeof(char));
    framework_query(28568444, className, methodName);
    printf("%s --> %s\n", className, methodName);
    free(methodName);
    free(className);

    methodName = (char*)calloc(1024, sizeof(char));
    className = (char*)calloc(1024, sizeof(char));
    framework_query(59956076, className, methodName);
    printf("%s --> %s\n", className, methodName);
    free(methodName);
    free(className);

    methodName = (char*)calloc(1024, sizeof(char));
    className = (char*)calloc(1024, sizeof(char));
    framework_query(43418716, className, methodName);
    printf("%s --> %s\n", className, methodName);
    free(methodName);
    free(className);

   	endFramework();
    return (0);
}
*/
