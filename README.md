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
