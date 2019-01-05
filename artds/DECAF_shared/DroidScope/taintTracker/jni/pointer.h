#ifdef __cplusplus
extern "C"
{
#endif

void insert_pointer(unsigned int taint,unsigned int pointer);
unsigned int find_pointer(unsigned int pointer);
void clear_pmap();

#ifdef __cplusplus
}
#endif
