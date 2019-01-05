#include "pointer.h"
#include<map>
#include<iostream>
using namespace std;
map<unsigned int,unsigned int> pointer_map;
void insert_pointer(unsigned int taint,unsigned int pointer)
{
    map<unsigned int,unsigned int>::iterator pos = pointer_map.find(pointer);
    if (pos != pointer_map.end())
    {
        pointer_map.erase(pos);
    }
    pointer_map.insert(std::pair<unsigned int,unsigned int>(pointer,taint));
}

unsigned int find_pointer(unsigned int pointer)
{
    map<unsigned int,unsigned int>::iterator it;
    it=pointer_map.find(pointer);
    if (it != pointer_map.end())
    {
        return it->second;
    }else{
        return 0;
    }
}

void clear_pmap(){
    pointer_map.clear();
}

