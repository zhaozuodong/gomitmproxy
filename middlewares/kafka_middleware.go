package middlewares

import (
	"bytes"
	"github.com/IBM/sarama"
	"github.com/zhaozuodong/gomitmproxy/log"
	"github.com/zhaozuodong/gomitmproxy/proxyutil"
	"io"

	"net/http"
	"strings"
)

type kafkaMiddleware struct {
	topic        string
	producer     sarama.SyncProducer
	allowTlsUrls []string
}

func NewKafkaMiddleware(topic string, brokers, urls []string) Middleware {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true

	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.Debugf("Error creating Kafka producer: %v", err)
	}
	return &kafkaMiddleware{
		topic:        topic,
		producer:     producer,
		allowTlsUrls: urls,
	}
}

func (m *kafkaMiddleware) Send(topic, key, val string) {
	message := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.StringEncoder(val),
	}
	partition, offset, err := m.producer.SendMessage(message)
	if err != nil {
		log.Debugf("Failed to produce message: %v", err)
	}
	log.Debugf("Produced message to topic %s, partition %d, offset %d\n", topic, partition, offset)
}

func (m *kafkaMiddleware) MitmRequest(req *http.Request) error {
	return nil
}

func (m *kafkaMiddleware) MitmResponse(res *http.Response) error {
	contentType := res.Header.Get("Content-Type")
	if strings.Contains(contentType, "json") {
		url := res.Request.URL.String()
		for _, u := range m.allowTlsUrls {
			if strings.Contains(url, u) {
				body, err := io.ReadAll(res.Body)
				if err != nil {
					return nil
				}
				enc := res.Header.Get("Content-Encoding")
				res.Body = io.NopCloser(bytes.NewReader(body))
				go func() {
					decodedBody, _ := proxyutil.BodyDecode(enc, body)
					m.Send(m.topic, url, string(decodedBody))
				}()
				break
			}
		}
	}
	return nil
}
