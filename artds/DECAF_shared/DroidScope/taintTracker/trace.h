/**
 * Created by YQ @2014-11-21
 *
 * Modified by CX @2014-11-22
 */

#ifndef __TAINT_TRACKER_H_
#define __TAINT_TRACKER_H_

#ifdef TARGET_ARM
void wait_uid(Monitor* mon, target_ulong uid);
void start_tracing_pid(target_ulong pid);
void stop_trace(Monitor *mon);
#endif

#endif
