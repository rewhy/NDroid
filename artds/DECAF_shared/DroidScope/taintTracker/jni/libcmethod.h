#ifndef LIBCMETHOD
#define LIBCMETHOD
#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*LibcHook) (CPUState* env,int afterInvoking);
void libcmethod_init();
LibcHook libchook(char *name);

#ifdef __cplusplus
}
#endif
#endif
