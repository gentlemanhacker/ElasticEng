# Troubleshooting Steps

## Logstash Troubleshooting
/_cat/indices

## Elasticsearch Troubleshooting

## Kibana Troubleshooting

## FW Troubleshooting

no route - firewalld conn refused - selinux

ss -lnt

## Stenographer Troubleshooting

## Kafka/Zookeeper Troubleshooting

Read Kafka data in real time
* systemctl stop logstash
* /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.30.102:9092 --topic zeek-raw
