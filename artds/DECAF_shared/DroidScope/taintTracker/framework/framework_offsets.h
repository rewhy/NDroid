/**
 * Created By Chenxiong Qian
 * date: 2014-11-25
 */
#ifndef __FRAMEWORK_OFFSETS_H__
#define __FRAMEWORK_OFFSETS_H__

#ifdef __cplusplus
extern "C"
{
#endif

void initFramework();

/*
 * return 0 if found, return -1 otherwise.
 */
int framework_query(unsigned int codeOffset, char **className, char** methodName,int *type,int *ret,int* num,char ** args);

#ifdef __cplusplus
}
#endif

#endif
