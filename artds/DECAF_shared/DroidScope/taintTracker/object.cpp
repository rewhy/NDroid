#include<map>
#include<iostream>
#include "object.h"
using namespace std;
map<unsigned int,unsigned int> object;
void insert(unsigned int taint,unsigned int ref)
{
    map<unsigned int,unsigned int>::iterator pos = object.find(ref);
    if (pos != object.end())
    {
        object.erase(pos);
    }
    object.insert(std::pair<unsigned int,unsigned int>(ref,taint));
}

unsigned int find(unsigned int ref)
{
    map<unsigned int,unsigned int>::iterator objectIterator;
    objectIterator=object.find(ref);
    if (objectIterator != object.end())
    {
        return objectIterator->second;
    }else{
        return 0;
    }
}

void clear_refmap()
{
    object.clear();
}

void trav()
{
    map<unsigned int,unsigned int>::iterator objectIterator=object.begin();
    for (;objectIterator!=object.end();objectIterator++) {
        cout<<hex<<objectIterator->first<<endl;
    }
}
