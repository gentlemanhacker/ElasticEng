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



    
