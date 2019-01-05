#ifdef __cplusplus
extern "C"
{
#endif 

void insert_args(int index,unsigned taint);
unsigned find_args(int index);
void clear_args();

void insert_java(int index,unsigned taint);
unsigned find_java(int index);
void clear_java();

#ifdef __cplusplus
}
#endif
