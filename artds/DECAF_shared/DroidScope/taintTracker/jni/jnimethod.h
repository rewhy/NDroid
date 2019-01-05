#ifndef JNIMETHOD
#define JNIMETHOD
#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*JNIHook) (CPUState* env,int afterInvoking);
void jnimethod_init();
JNIHook jnihook(char *name);

#ifdef __cplusplus
}
#endif
#endif
