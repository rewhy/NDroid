#ifdef __cplusplus
extern "C"
{
#endif

bool find_point(unsigned offset);
void initNative();
int native_query(unsigned int codeOffset, char **className, char** methodName,int *type,int *ret,int* num,char ** args);
void trav_point();

#ifdef __cplusplus
}
#endif
