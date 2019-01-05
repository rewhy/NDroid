#ifdef __cplusplus

#include <map>
using namespace std;
typedef map<char ,char *> Args;
char * query_argseffect(Args * args,char argsn);
Args * query_argsmap(char const* methodName);

extern "C"
{

#endif
void init_apiprop();

#ifdef __cplusplus
}
#endif
