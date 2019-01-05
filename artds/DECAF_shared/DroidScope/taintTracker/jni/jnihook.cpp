#include "jnihook.h"
#include<stdlib.h>
#include <string.h>
#include<map>
#include <iostream>
#include <fstream>
using namespace std;
map<int,char*> jnimethod;
map<int,char*> libcmethod;
map<int,char*> libmmethod;
fstream fs;

void jnihook_init(){
    fs.open("jnimethod.txt", ios::in);
    // start -- zhouhao
		if(!fs) {
		    printf("jnimethod.txt is not exist\n");
				return;
		}
		// -- end
		char buf[2048];
    while (!fs.eof()){
        fs.getline(buf, 2048, '\n');
        char* p;
        p = strtok(buf, "\t");
        if (p){
            int codeOffset = 0;
            sscanf(p,"%x",&codeOffset);
            p = strtok(0,"\t");
            int len=strlen(p);
            char *name=(char*)calloc(1,len+1);
            memset(name,0,len+1);
            strncpy(name,p,len);
            jnimethod.insert(pair<int,char*>(codeOffset,name));
				}
    }
    fs.close();
}

char * findjni(int offset)
{
		map<int,char*>::iterator it;
		it=jnimethod.find(offset);
    if (it!=jnimethod.end()) {
				return it->second;
    }
    return NULL;
}

void libchook_init(){
    fs.open("libcmethod.txt", ios::in);
    // start -- zhouhao
		if(!fs) {
			  printf("libcmethod.txt is not exist\n");
				return;
		}
		// -- end
    char buf[2048];
    while (!fs.eof()){
        fs.getline(buf, 2048, '\n');
        char* p;
        p = strtok(buf, "\t");
        if (p){
            int codeOffset = 0;
            sscanf(p,"%x",&codeOffset);
						p = strtok(0,"\t");
            int len=strlen(p);
            char *name=(char*)calloc(1,len+1);
            memset(name,0,len+1);
            strncpy(name,p,len);
						libcmethod.insert(pair<int,char*>(codeOffset,name));
        }
    }
    fs.close();
}

char * findlibc(int offset)
{
    map<int,char*>::iterator it;
    it=libcmethod.find(offset);
    if (it!=libcmethod.end()) {
        return it->second;
    }
    return NULL;
}

void libmhook_init(){
    fs.open("libmmethod.txt", ios::in);
		// start -- zhouhao
		if(!fs) {
		    printf("libmmethod.txt is not exist\n");
				return;
		}
		// -- end
    char buf[2048];
    while (!fs.eof()){
        fs.getline(buf, 2048, '\n');
        char* p;
        p = strtok(buf, "\t");
        if (p){
            int codeOffset = 0;
            sscanf(p,"%x",&codeOffset);
            p = strtok(0,"\t");
            int len=strlen(p);
            char *name=(char*)calloc(1,len+1);
            memset(name,0,len+1);
            strncpy(name,p,len);
            libmmethod.insert(pair<int,char*>(codeOffset,name));
        }
    }
    fs.close();
}

char * findlibm(int offset)
{
    map<int,char*>::iterator it;
    it=libmmethod.find(offset);
    if (it!=libmmethod.end()) {
        return it->second;
    }
    return NULL;
}
