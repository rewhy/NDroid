#ifdef __cplusplus
extern "C"
{
#endif

void insert(unsigned int taint,unsigned int ref);
unsigned int find(unsigned int ref);
void clear_refmap();
void trav();

#ifdef __cplusplus
}
#endif
