#include "framework_prop.h"
#include <iostream>
#include <fstream>
#include <stdlib.h> 
#include <string.h>

struct cmp_str
{
    bool operator()(char const *a, char const *b)
    {
        return strcmp(a, b) < 0;
    }
};

map<char const *,Args *,cmp_str> api_prop;

static fstream f;

void init_apiprop()
{
    f.open("prop.txt", ios::in);
		if(!f) {
		    printf("prop.txt is not exist\n");
				return;
		}	
    char buf[2048+16];
    char *strtokstate = NULL;
    char *strtokstate2 = NULL;
    while (!f.eof()){
        f.getline(buf, 2048+16, '\n');
        char* p;
        p = strtok_r(buf,"@",&strtokstate);
        if (p){
            int len=strlen(p);
            char *methodName=new char[len+1];
            memset(methodName,0,len+1);
            strncpy(methodName,p,len);
            Args * args=new Args;
            p=strtok_r(0,"@",&strtokstate);
            char i=1;

            while (p) {
                if (strcmp(p,"N")!=0) {
                    char tmp[10]={0};
                    int k=0;
                    char * t=strtok_r(p,",",&strtokstate2);

                    while (t) {
                        tmp[k]=atoi(t);
                        k++;
                        t=strtok_r(0,",",&strtokstate2);
                    }

                    char * arrays=new char[k+1];
                    arrays[0]=k;
                    for (int y=0;y<k;y++) {
                        arrays[y+1]=tmp[y];
                    }

                    args->insert(pair<char, char *>(i,arrays));
                }
                i++;
                p=strtok_r(0,"@",&strtokstate);
            }

            api_prop.insert(pair<char const*,Args *>(methodName,args));
        }
    }
    f.close();
    printf("initprop done! map entry size: %d\n", api_prop.size());
}

Args * query_argsmap(char const* methodName){
    map<char const *, Args *>::iterator it;
    it=api_prop.find(methodName);
    if (it==api_prop.end()) {
        return NULL;
    }
    return it->second;
}

char * query_argseffect(Args * args,char argsn)// if no method match ,return false; others no arg effect, res=NULL or return args array
{
    map<char, char *>::iterator ps;
    ps=args->find(argsn);
    if (ps==args->end()) {
        return NULL;
    }
    return ps->second;
} 
