#include "../src/launch_observation.h"
#include <assert.h>
#include <stdio.h>
int main(void){struct fl_launch_observation s={0};for(int i=0;i<30;i++)assert(!fl_observe_launch(&s,1,101));
 assert(!fl_observe_launch(&s,-1,0));assert(s.pid==101);assert(!fl_observe_launch(&s,1,101));
 for(int i=0;i<7;i++)assert(!fl_observe_launch(&s,0,0));assert(!fl_observe_launch(&s,1,101));
 assert(!fl_observe_launch(&s,1,102));assert(s.stable==1);for(int i=1;i<119;i++)assert(!fl_observe_launch(&s,1,102));assert(fl_observe_launch(&s,1,102)==1);
 s=(struct fl_launch_observation){0};for(int i=0;i<7;i++)assert(!fl_observe_launch(&s,-1,0));assert(fl_observe_launch(&s,-1,0)==-2);
 s=(struct fl_launch_observation){0};for(int i=0;i<7;i++)assert(!fl_observe_launch(&s,0,0));assert(fl_observe_launch(&s,0,0)==-1);
 s=(struct fl_launch_observation){0};assert(fl_observe_launch(&s,2,555)==-3);
 puts("PASS: snapshot failure is not exit; transient gap, same-app PID handoff, settled process, uncertainty and identity guards");}
