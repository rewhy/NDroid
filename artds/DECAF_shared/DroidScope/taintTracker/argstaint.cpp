#include <map>
#include "argstaint.h"
using namespace std;

extern map<int,unsigned>* argsindex;
void insert_args(int index,unsigned taint)
{
    map<int,unsigned>::iterator pos = (*argsindex).find(index);
    if (pos != (*argsindex).end())
    {
        (*argsindex).erase(pos);
    }
    (*argsindex).insert(std::pair<int,unsigned>(index,taint));
}

unsigned find_args(int index)
{
    map<int,unsigned>::iterator objectIterator;
    objectIterator=(*argsindex).find(index);
    if (objectIterator != (*argsindex).end())
    {
        return objectIterator->second;
    }else{
        return 0;
    }
}

void clear_args()
{
    (*argsindex).clear();
}


extern map<int,unsigned>* java_args;
void insert_java(int index,unsigned taint)
{
    map<int,unsigned>::iterator pos = (*java_args).find(index);
    if (pos != (*java_args).end())
    {
        (*java_args).erase(pos);
    }
    (*java_args).insert(std::pair<int,unsigned>(index,taint));
}

unsigned find_java(int index)
{
    map<int,unsigned>::iterator objectIterator;
    objectIterator=(*java_args).find(index);
    if (objectIterator != (*java_args).end())
    {
        return objectIterator->second;
    }else{
        return 0;
    }
}

void clear_java()
{
    (*java_args).clear();
}

