# myFireWall
a demo firewall for linux based on netfilter hooks (HUST网络空间安全课程设计)

```shell
编译源码
sudo make
安装，内核模块加载至Linux内核中
sudo make install
```

```shell
#一条命令只执行一次动作，如有冲突按照以下显示顺序优先执行靠下的命令
./firewall -help
./firewall -mod ["rule","nat","show"] #required
(rule模式) 
	-default ["drop","accept"] #修改默认策略，初始为accept,无需指定其他变量
	
	-del [规则名] #删除一条过滤规则,最大长度11,无需指定其他变量
	
	-add [规则名] #添加一条过滤规则,最大长度11,需要指定其他变量
	-insert [规则名] #选择插入到链表的某个规则后面,缺省则默认插入最后
	-sip [IP/掩码] #源IP
	-sport [端口-端口,"any"] #源端口范围，大小顺序都可
	-dip [IP/掩码] #目的IP
	-dport [端口-端口,"any"] #目的端口范围，大小顺序都可
	-protocol ["TCP","UDP","ICMP","any"] #协议
	-deny #策略为拒绝，和-accept冲突且必选其一
	-accept #策略为接受，和-deny冲突且必选其一
	-log #记录日志，否则不记录

(nat模式)	
	-del [规则序号] #删除指定NAT规则,无需指定其他变量
	
	-add ["NAT","nat"]#添加一条NAT规则,序号自动设定,需要指定其他变量
	-sip [IP/掩码] #源IP
	-natip [IP] #NAT IP
	-natport [端口-端口,"any"] #目的端口范围，大小顺序都可
	
(show模式)
	-logs 或 -logs=[数字] #打印所有日志或者打印最后[数字]条
	-rules #打印所有过滤规则 
	-nats #打印所有NAT规则
	-connections #打印所有当前已有连接
	                  
```

Test:

ICMP

```shell
1.外网主机ping内网主机
ping 192.168.242.2

2.内网主机ping外网主机
ping 192.168.248.2

./firewall -mod show -connections

3.防火墙主机加规则,过滤外向内
./firewall -mod rule -add icmprule -protocol ICMP -sip 192.168.248.0/24 -sport any -dip 192.168.242.0/24 -dport any -deny -log

./firewall -mod show -rules

4.内网主机ping外网主机
ping 192.168.248.2

5.外网主机ping内网主机
ping 192.168.242.2

./firewall -mod show -logs
./firewall -mod rule -del icmprule
```

TCP

```shell
sudo apt-get install openbsd-inetd telnetd -y

1.外网主机
sudo /etc/init.d/openbsd-inetd restart
telnet 192.168.242.2

2.内网主机
sudo /etc/init.d/openbsd-inetd restart
telnet 192.168.248.2

3.防火墙主机加规则,过滤外向内
./firewall -mod rule -add tcprule -protocol TCP -sip 192.168.248.0/24 -sport any -dip 192.168.242.0/24 -dport any -deny -log

./firewall -mod show -rules

4.内网主机
telnet 192.168.248.2

5.外网主机
telnet 192.168.242.2

./firewall -mod show -logs
./firewall -mod rule -del tcprule
```

UDP

```shell
1.外网主机
nc -lu 8888

2.内网主机
nc -u 192.168.248.2 8888

3.防火墙主机加规则,过滤外向内
./firewall -mod rule -add udprule -protocol UDP -sip 192.168.248.0/24 -sport any -dip 192.168.242.0/24 -dport any -deny -log

此时内网发消息外网能接受，外网发消息内网无法接受
./firewall -mod show -rules

./firewall -mod show -logs
./firewall -mod rule -del udprule
```

默认动作

```shell
1.外网主机ping内网主机
ping 192.168.242.2

2.内网主机ping外网主机
ping 192.168.248.2

3.防火墙默认
./firewall -mod rule -default drop

./firewall -mod rule -add icmprule -protocol ICMP -sip 192.168.248.0/24 -sport any -dip 192.168.242.0/24 -dport any -accept -log

./firewall -mod rule -add icmprule -protocol ICMP -sip 192.168.242.0/24 -sport any -dip 192.168.248.0/24 -dport any -accept -log

./firewall -mod show -rules
./firewall -mod rule -del icmprule
```

NAT

```shell
内网主机ping外网主机
ping 192.168.248.2

./firewall -mod show -connections

3.防火墙主机加规则
./firewall -mod nat -add nat -sip 192.168.242.0/24 -natip 192.168.248.1 -natport any

./firewall -mod show -nats
./firewall -mod show -connections

./firewall -mod nat -del 0
```

log

```shell
./firewall -mod show -logs=5
./firewall -mod show -logs
./firewall -mod show -logs | grep "TCP"
```
