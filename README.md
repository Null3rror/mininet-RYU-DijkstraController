# mininet-RYU-DijkstraController
we got the original code from:
 http://csie.nqu.edu.tw/smallko/sdn/dijkstra_ryu.htm
and fix some of its bug!

If you want to test the code, first you need to open a terminal bash and write:\
 ```sudo mn --topo tree,3  --mac --switch ovsk --controller remote -x && sudo mn -c```\
if you want to run on a custom topology the write:\
 ```sudo mn --custom ./customTopo.py --topo mytopo --mac --switch ovsk --controller remote -x && sudo mn -c
```\
then goto the controller:c0 and write:\
 ```ryu-manager --verbose ryu/app/controller.py --observe-links```\
then you can write in mininet terminal:\
 ```pingall```\
if you want to check the flow table of a switch, for example for s2, then write the below command in switch:s2:\
 ```ovs-ofctl dump-flows s2```\
if you want to capture the packets of a certain host, for example for h1, then write the below command in host:h1:\
 ```tcpdump -en -i h1-eth0```
