#ifdef __cplusplus
extern "C"
{
#endif

void initDex();
int dex_query(unsigned int codeOffset, char **className, char** methodName,int *type,int *ret,int* num,char ** args);

#ifdef __cplusplus
}
#endif
