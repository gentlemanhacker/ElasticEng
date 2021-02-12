# ElasticEng
Elastic Engineering



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
