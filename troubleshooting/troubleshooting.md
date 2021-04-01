# Troubleshooting Steps

## Logstash Troubleshooting
/_cat/indices

## Elasticsearch Troubleshooting
GET _cat/nodes?v
GET _cluster/state
GET _cluster/health

## Kibana Troubleshooting
watch -d "curl ip:9200/_cat_indices" #shows indices growing hopefully

## FW Troubleshooting

no route - firewalld conn refused - selinux

ss -lnt

## Stenographer/Moloch Troubleshooting
df –h for space

Moloch:
Curl –XGET http://localhost:9200/_cluster/health?pretty
Curl –XGET http://localhost:9200/_cat/nodes
Curl –XGET http://localhost:9200/_cat/allocation?v


## Kafka/Zookeeper Troubleshooting

Read Kafka data in real time
* systemctl stop logstash
* /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.30.102:9092 --topic zeek-raw

Kafka.service, zookeeper.service, filbeat.service
Ps aux | grep kafka to ensure it is running

- `systemctl stop kafka zookeeper` -takes a few minutes
- `rm -rf /var/lib/zookeeper/version-2/*`
- `rm -rf /data/kafka/*`
- `systemctl start zookeeper kafka`

**Cluster Sizing/Performance Issues**
Determine MTTD to find out how long you want to retain data
Determine Storage per day
example 90 days, 100 Gb storage
x2 for replica
=90x200Gb or ~18Tb

Workload Ratio , RAM:DISK , 64Gb Theoretical RAM
Hot 1:32    2Tb 
Warm 1:(64-96)    4Tb
Cold 1:128    8Tb

Then only use 80% of theoretical max

Equates to 24 days hot, 48 days warm, 96 days cold - 168 total days

600 shard/node max
Shard 25-50 Gb
1Gb Heap/20 shards

Lots of shards bad for query speed
