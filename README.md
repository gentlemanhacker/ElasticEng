# ElasticEng
:space_invader: Elastic Engineering :space_invader:



## Key Addresses
| Host Sensor | Netmask | Gateway/Edge | DNS Servers | pfSense | 
| --------------- | --------------- | --------------- | --------------- | --------------- |
| 172.16.30. | 172.16.30. | 172.16.30. |172.16.30. | 172.16.30. |
| --------------- | --------------- | --------------- | --------------- | --------------- |


## General Order of Things
Setup -> CentOS -> pfSense -> tap/ethtool script -> local.repo -> install rockNSM ( Stenographer, Suricata, Zeek, Zookeeper, Kafka, Filebeat, Elasticsearch, Logstash, Kibana) -> Restart all services

## Key Files
| File | App | Location |  
| --------------- | --------------- | --------------- | 
filebeat.yml | Filebeat | /etc/filebeat/ |
elasticsearch.yml | ElasticSearch | /etc/elasticsearch/config |
jvm.options| ElasticSearch | /etc/elasticsearch/config |
server.properties | Kafka | /etc/kafka | 
kibana.yml | Kibana | /etc/kibana/ | 
firewall.d | Linux FW | /etc/firewalld |
| --------------- | --------------- | --------------- | 


## CentOS Install

### Setting up the NUC
1. Boot to USB F11 to boot bios
2. Ensure Centos 7
3. Select English
4. select network and hostname
  - change hostname to `x.local.lan`
    - hit apply
  - en01 is management and hit configure
    - ipv4 settings
      - method change to manual
      - add address `172.16.40.x`
      - add netmask `255.255.255.0`
      - add gateway `172.16.40.x`
      - DNS server `172.16.40.x`
    - ipv6 settings
      - method change to ignore
       - changing the IPv6 Settings to ignore wont totally disable IPv6. You will have to disable IPv6 via the terminal later.
    - hit save
  - hit done  
5. Select Day and Time
  - region to etc
  - city to coordinate universal time
  - network time on normally not in lab
  - hit done
6. Select "kdump"
  - deselect "enable kdump"
  - hit "done"
7. Ensure minimal install for software selection on sensor builds
8. Select installation destination
  - click both disks ensure they are selected
  - check "I would like to make additional space"
  - hit done
    - hit "delete all"
    - hit "reclaim space"
9. Select installation destination
  - hit radio button "I will configure partition"
  - hit "done"
    - ensure lvm is selected
    - click automation blue link
      - Do not change boot or boot efi
      - ensure that folders are in correct volume group data to data and the rest to OS
      - hit "update settings"

| Logical Volume |	Desired Capacity |
| --------------- | --------------- |
 |/home |	100 GiB |
 |/data/kafka |	100 GiB |
 |/var/log |	50 GiB |
 |/data/stenographer |	500 GiB |
 |/data/suricata |	25 GiB |
 |/data/elasticsearch |	300 GiB |
 |/tmp	 |5 GiB |
 |/var |	50 GiB |
 |/boot |	1 GiB |
 |/boot/efi	 |200 MiB |
 |/	 |Remaining capacity 99999 |
 |swap	 |15.69 GiB |

10. hit "begin installation"
    - hit "User Creation"
      - make name
        - select radio button make this user an administrator
        - set password
        - hit "done"
    - hit "reboot" when it is ready
11. login to shell after reboot
  - run command
~~~
     cd /etc/sysconfig/network-scripts/
     sudo vi ifcfg-eno1     
~~~
  - change "ONBOOT" to yes


`vim /etc/sysctl.conf`
~~~
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
~~~
`vim /etc/hosts`
 - remove second line

`sudo systemctl  restart network`
### Notes
.125gb for 1GB
Steno, Elastic, Kafka, and Suricata writes to disks
use log rotate or cron to handle read write and deletion 24hr
324TB worse case. 10.8TB for pcap / steno. suricata 1% of pcap so 108GB round up 125GB rotating buffer that is rotated out. Zeek 10%  1TB. 30TB to Elastic.

### Kafka Notes
kafka has 3 partitions
 - Suricata
 - Zeek
 - FSF


## Configure pfSense
1. on the target host, select the boot menu and select the proper boot media that you are installing pfsense from. e.g. boot from UEFI usb.
2. Install pfSense
3. Default Keymat
4. How would you like to partition your disk? - Select Auto (UFS) - Select <Entire Disk> then <Yes> - Select GPT and <OK> - Select <Finish> then <Commit> - Select <No> - Select <Reboot> and remove the USB drive
5. after Reboot you will go to option menu - type 1 for Assign interfaces and press enter - type n and press enter - type em0 for the WAN interface and press enter - type em1 for the LAN interface and press enter - press enter without typing anything - verify the interfaces and type y then press enter - you will eventually return to your option menu - type 2 for Set interface(s) IP addresses and press enter - type 1 and press enter - type y and press enter - type n and press enter - press enter without typing anything - type y and press enter
- Note: if your using certs you will need to configure HTTPS by selecting n and pressing enter - press enter - type 2 and press enter - type 2 and press enter - type the pfSense/gateway IP and press enter
- 172.16.20.1 - type the netmask for the pfSense/gateway IP and press enter
24 (e.g. 255.255.255.0) - press enter without typing anything - press enter again without typing anything - type y and press enter - type in your network IP ranges starting IP and press enter
- 172.16.30.101 - type in your network IP ranges starting IP and press enter
- 172.16.30.254
- press enter to continue
6. Plug in a computer via ethernet cable to the LAN 2 port to configure pfSense.
- make sure your pc has the fist IP in the range that was configured on the pfSense.
- open terminal and type ip a to see 172.16.30.101
- open browser and type 172.16.30.1 in the address bar
    - The user name is admin and the password is pfsense
- Select next and then next again
- Primary DNS is the edge router 192.168.2.1
- Host name is pfSense-sg3
- Select next then next again
- On Wizard/pfSense Setup/Configure WAN Interface
- de-select the checkboxes for Block RFC1918 Private Networks and Block bogon networks
- Select next
- type pfsense in the second password Block and select next
- Select Reload then Finish
- Navigate to Firewall then rules then add
    -Change protocol to any
    - source to any
      - Note: in production you would want to use LAN net
- duplicate the above for LAN
- navigate to Diagnostics then Halt System. Select halt and confirm.
    
## Configure NUC for TAP to monitor

1. ssh box@172.16.30.x
2. create ethtoolsscript.sh 
3. sudo chmod +x ethtools.sh
4. sudo ./ethtoolscript.sh enp5s0

## Configure Repo
~~~
sudo -s
cd /etc/yum.repos.d./
rm *
sudo vi  local.repo
~~~
- Copy from the local.repo file
- then run 
    - sudo yum clean all sudo yum makechache fast
    
## Continue Installation
#### Verify Cache
`sudo yum makecache`

### Suricata
`sudo yum install suricata`

`sudo vi /etc/suricata/suricata.yaml`

###### Edit File

1. :set nu
2. /default-log-dir:
3. edit to /data/suricata
4. /outputs:
5. turn stats off line 404
6. change interface to enp5s0

##### Edit Options file
`vi /etc/sysconfig/suricata`  
change to `OPTIONS="--af-packet=enp5s0 --user suricata "`

##### update rules
`suricata-update add-source local-emerging-threats http://192.168.2.11:8009/suricata-5.0/emerging.rules.tar.gz`

`suricata-update`

##### Start Suricata
`systemctl enable suricata`  
`yum install tcpdump`  
`tcpdump -i enp5s0`
`chown -R suricata: /data/suricata`  
`systemctl start suricata`  
`systemctl status suricata`  
`journalctl -xu suricata`  


##### Setup logrotate
`vi /etc/logrotate.d/suricata.conf`
~~~
/data/suricata/*.log /data/suricata/*.json
{
  rotate 3
  missingok
  nocompress
  create
  sharedscripts
  postrotate
          /bin/kill -HUP $(cat /var/run/suricata.pid)
  endscript
}
~~~


### Setup Zeek
`yum install zeek zeek-plugin-kafka zeek-plugin-af_packet vim`

##### Edit
`vim /etc/zeek/networks.cfg`
~~~
/8     switch
/12    sensors
/16    edge router and laptops
~~~

`vim /etc/zeek/zeekctl.cfg`  
 add to end
~~~
lb_custom.InterfacePrefix=af_packet::
~~~
`vim node.cfg`
~~~
# Example ZeekControl node configuration.
#
# This example has a standalone node ready to go except for possibly changing
# the sniffing interface.

# This is a complete standalone configuration.  Most likely you will
# only need to change the interface.
#[zeek]
#type=standalone
#host=localhost
#interface=eth0

## Below is an example clustered configuration. If you use this,
## remove the [zeek] node above.

[logger]
type=logger
host=localhost

[manager]
type=manager
host=localhost
pin_cpus=1

[proxy-1]
type=proxy
host=localhost

[worker-1]
type=worker
host=localhost
interface=enp5s0
lb_method=custom
lb_procs=2
pin_cpus=2,3
env_vars=fanout_id=77
~~~
### Scripts
`cd /usr/share/zeek/site/`  
`mkdir scripts`  
`cd scripts`  
`vim af_packet.zeek`
~~~
redef AF_Packet::fanout_id = strcmp(getenv("fanout_id"),"") == 0 ? 0 : to_count(getenv("fanout_id"));
~~~
`vim kafka.zeek`
~~~
@load Apache/Kafka/logs-to-kafka

redef Kafka::topic_name = "zeek-raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json =F;
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "172.16.40.100:9092"
);


event zeek_init() &priority=-5
{
    for (stream_id in Log::active_streams)
    {
        if (|Kafka::logs_to_send| == 0 || stream_id in Kafka::logs_to_send)
        {
            local filter: Log::Filter = [
                $name = fmt("kafka-%s", stream_id),
                $writer = Log::WRITER_KAFKAWRITER,
                $config = table(["stream_id"] = fmt("%s", stream_id))
            ];

            Log::add_filter(stream_id, filter);
        }
    }
}

~~~

`vim extension.zeek`
~~~
type Extension: record {
   ## The log stream that this log was written to.
   stream:   string &log;
   ## The name of the system that wrote this log. This
   ## is defined in the  const so that
   ## a system running lots of processes can give the
   ## same value for any process that writes a log.
   system:   string &log;
   ## The name of the process that wrote the log. In
   ## clusters, this will typically be the name of the
   ## worker that wrote the log.
   proc:     string &log;
};

function add_log_extension(path: string): Extension
{
   return Extension($stream = path,
                    $system = "sensor1",
                    $proc   = peer_description);
}

redef Log::default_ext_func   = add_log_extension;
redef Log::default_ext_prefix = "@";
redef Log::default_scope_sep  = "_";
~~~

##### load scripts
`vim ../local.zeek`

append
~~~
@load ./scripts/kafka.zeek
@load ./scripts/af_packet.zeek
@load ./scripts/extension.zeek
~~~
#### Deploy Zeek
`zeekctl check`  
`zeekctl deploy`

### Stenographer
`yum install stenographer -y`

`vim /etc/stenographer/config`
~~~
{
  "Threads": [
    { "PacketsDirectory": "/data/stenographer/packets"
    , "IndexDirectory": "/data/stenographer/indices"
    , "MaxDirectoryFiles": 30000
    , "DiskFreePercentage": 10
    }
  ]
  , "StenotypePath": "/usr/bin/stenotype"
  , "Interface": "enp5s0"
  , "Port": 1234
  , "Host": "127.0.0.1"
  , "Flags": []
  , "CertPath": "/etc/stenographer/certs"
}
~~~
`cd /data`  
`chown -R stenographer: stenographer/`  
`stenokeys.sh stenographer stenographer`  
`systemctl start stenographer`

### Zookeeper
`sudo yum install zookeeper kafka`  
`sudo vim /etc/zookeeper/zoo.cfg` - if you want to make changes server.1=ipaddress:2182:2183  
`sudo systemctl start zookeeper`  
`sudo systemctl enable zookeeper`  
`vim /etc/kafka/server.properties`
~~~
line 31 and 36 need to be updated with ip address 172.16.40.100
line 60 change to /data/kafka
line 65 to 3
line 107 uncomment and add two 0's change 10 to 8
~~~

`cd /data`  
`chown -R kafka: /data/kafka/`  

##### Firewall Setup
`firewall-cmd --add-port=2181/tcp --permanent`  
`firewall-cmd --add-port=9092/tcp --permanent`  

#### Start Kafka
`systemctl start kafka`

`vim /usr/share/kafka/config/producer.properties`
~~~
bootstrap.servers=172.16.40.100
~~~

`vim /usr/share/kafka/config/consumer.properties`
~~~
bootstrap.servers=172.16.40.100
~~~

`cd /usr/share/kafka/bin` - shows scripts   

`./kafka-topics.sh --bootstrap-server 172.16.40.100:9092 --describe --topic zeek-raw`
`./kafka-topics.sh --bootstrap-server 172.16.40.100:9092 --create --topic test --partitions 5 --replication-factor 1`  

###### Test
`./kafka-console-producer.sh --broker-list 172.16.40.100:9092 --topic test`
`./kafka-console-consumer.sh --bootstrap-server 172.16.40.100:9092 --topic test --from-beginning`

#### Filebeat
`yum install filebeat`  
`cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.back`  
`vim /etc/filebeat/filebeat.yml`  
hit: gg 9999 dd
~~~
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /data/suricata/eve.json
  json.keys_under_root: true
  fields:
    kafka_topic: suricata-raw
  fields_under_root: true
output.kafka:
  hosts: ["172.16.40.100:9092"]
  topic: '%{[kafka_topic]}'
  required_acks: 1
  compression: gzip
  max_message_bytes: 1000000
~~~

#### Start Filebeat
`systemctl start filebeat`
`systemctl enable filebeat`
`cd /usr/share/kafka/bin`
`./kafka-topics.sh --bootstrap-server 172.16.40.100:9092 --list`
`./kafka-topics.sh --bootstrap-server 172.16.40.100:9092 --describe --topic suricata-raw`


##### random notes
disable unused services  
never use processor 0  
cape stack  
`yum install jq`- nice tool for reading json. tail | jq  
`suricata/ zeek-config`for zeek config information


##### Cluster
`vim /var/lib/zookeeper/myid`
`4`
`vim /etc/zookeeper/zoo.cfg`

append
~~~
server.1=172.16.10.100:2182:2183
server.2=172.16.20.100:2182:2183
server.3=172.16.30.100:2182:2183
server.4=172.16.40.100:2182:2183
server.5=172.16.50.100:2182:2183
server.7=172.16.1.100:2182:2183
~~~

`firewall-cmd --add-port=2182/tcp --permanent`  
`firewall-cmd --add-port=2183/tcp --permanent`  
`firewall-cmd --reload`  
`systemctl start zookeeper`  
`vim /etc/kafka/server.properties`  
zokeeper.connect=<all ip addresses>
~~~
172.16.1.100:2181,172.16.10.100:2181,172.16.20.100:2181,172.16.30.100:2181, 172.16.40.100:2181,172.16.50.100:2181
~~~
`systemctl start kafka`

