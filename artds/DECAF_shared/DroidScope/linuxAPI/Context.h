void context_init();
gpid_t getCurrentPID();
gpa_t getCurrentPGD();
target_ulong getCurrentUID();
void update_mod(CPUState* env, gpid_t pid);
void linux_print_mod(Monitor* mon, gpid_t pid);
void get_symbol(CPUState* env, gpid_t pid, gva_t addr);
void get_symbol_address(Monitor* mon, int pid, const char* strModule, const char* strName);
void linux_ps(Monitor* mon);
void linux_pt(Monitor* mon);


