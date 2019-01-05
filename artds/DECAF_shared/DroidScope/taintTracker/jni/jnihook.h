#ifdef __cplusplus
extern "C"
{
#endif

void jnihook_init();
void libchook_init();
void libmhook_init();
char * findlibc(int offset);
char * findlibm(int offset);
char * findjni(int offset);

#ifdef __cplusplus
}
#endif
