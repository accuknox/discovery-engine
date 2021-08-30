package feedconsumer

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/rs/zerolog"

	"github.com/spf13/viper"

	cfg "github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	"github.com/accuknox/knoxAutoPolicy/src/plugin"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	cilium "github.com/cilium/cilium/api/v1/flow"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ( // status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

// ====================== //
// == Global Variables == //
// ====================== //

var numOfConsumers int
var consumers []*KnoxFeedConsumer

var Status string

var waitG sync.WaitGroup
var stopChan chan struct{}

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()

	waitG = sync.WaitGroup{}
	Status = STATUS_IDLE

	consumers = []*KnoxFeedConsumer{}
}

// ======================== //
// == Knox Feed Consumer == //
// ======================== //

type KnoxFeedConsumer struct {
	id           int
	kafkaConfig  kafka.ConfigMap
	topics       []string
	eventsBuffer int

	netLogEvents      []types.NetworkLogEvent
	netLogEventsCount int

	syslogEvents      []types.SystemLogEvent
	syslogEventsCount int
}

func (cfc *KnoxFeedConsumer) setupKafkaConfig() {
	bootstrapServers := viper.GetString("feed-consumer.kafka.bootstrap-servers")
	brokderAddressFamily := viper.GetString("feed-consumer.kafka.broker-address-family")
	sessionTimeoutMs := viper.GetString("feed-consumer.kafka.session-timeout-ms")
	autoOffsetReset := viper.GetString("feed-consumer.kafka.auto-offset-reset")

	groupID := viper.GetString("feed-consumer.kafka.group-id") + strconv.FormatUint(uint64(time.Now().Unix()), 10)
	cfc.topics = viper.GetStringSlice("feed-consumer.kafka.topics")
	cfc.eventsBuffer = viper.GetInt("feed-consumer.kafka.events.buffer")

	cfc.netLogEvents = make([]types.NetworkLogEvent, 0, cfc.eventsBuffer)
	cfc.syslogEvents = make([]types.SystemLogEvent, 0, cfc.eventsBuffer)

	sslEnabled := viper.GetBool("feed-consumer.kafka.ssl.enabled")
	securityProtocol := viper.GetString("feed-consumer.kafka.security.protocol")
	sslCALocation := viper.GetString("feed-consumer.kafka.ca.location")
	sslKeystoreLocation := viper.GetString("feed-consumer.kafka.keystore.location")
	sslKeystorePassword := viper.GetString("feed-consumer.kafka.keystore.pword")

	// Set up required configs
	cfc.kafkaConfig = kafka.ConfigMap{
		"enable.auto.commit":      true,
		"auto.commit.interval.ms": 1000,
		"bootstrap.servers":       bootstrapServers,
		"broker.address.family":   brokderAddressFamily,
		"group.id":                groupID,
		"session.timeout.ms":      sessionTimeoutMs,
		"auto.offset.reset":       autoOffsetReset,
	}

	// Set up SSL specific configs if SSL is enabled
	if sslEnabled {
		if err := cfc.kafkaConfig.SetKey("security.protocol", securityProtocol); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := cfc.kafkaConfig.SetKey("ssl.ca.location", sslCALocation); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := cfc.kafkaConfig.SetKey("ssl.keystore.location", sslKeystoreLocation); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := cfc.kafkaConfig.SetKey("ssl.keystore.password", sslKeystorePassword); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func (cfc *KnoxFeedConsumer) startConsumer() {
	defer waitG.Done()

	c, err := kafka.NewConsumer(&cfc.kafkaConfig)
	if err != nil {
		log.Error().Msgf("Failed to create consumer: %s", err)
		return
	}
	log.Debug().Msgf("Created Consumer %v", c)

	err = c.SubscribeTopics(cfc.topics, nil)
	if err != nil {
		log.Error().Msgf("Failed to subscribe topics: %s", err)
		return
	}

	log.Info().Msgf("Starting consumer %d, topics: %v", cfc.id, cfc.topics)

	run := true
	for run {
		select {
		case <-stopChan:
			log.Info().Msgf("Got a signal to terminate the consumer %d", cfc.id)
			run = false

		default:
			ev := c.Poll(100)
			if ev == nil {
				continue
			}

			switch e := ev.(type) {
			case *kafka.Message:
				if *e.TopicPartition.Topic != "kubearmor-syslogs" { // cilium-hubble
					if err := cfc.processNetworkLogMessage(e.Value); err != nil {
						log.Error().Msg(err.Error())
					}
					if e.Headers != nil {
						log.Debug().Msgf("Headers: %v", e.Headers)
					}
				} else { // kubearmor-syslogs
					if err := cfc.processSystemLogMessage(e.Value); err != nil {
						log.Error().Msg(err.Error())
					}
					if e.Headers != nil {
						log.Debug().Msgf("Headers: %v", e.Headers)
					}
				}
			case kafka.Error:
				// Errors should generally be considered
				// informational, the client will try to
				// automatically recover.
				// But in this example we choose to terminate
				// the application if all brokers are down.
				log.Error().Msgf("Error: %v: %v\n", e.Code(), e)
				if e.Code() == kafka.ErrAllBrokersDown {
					run = false
				}
			default:
				log.Debug().Msgf("Ignored %v\n", e)
			}
		}
	}

	log.Info().Msgf("Closing consumer %d", cfc.id)
	if err := c.Close(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func (cfc *KnoxFeedConsumer) processNetworkLogMessage(message []byte) error {
	event := types.NetworkLogEvent{}
	var eventMap map[string]json.RawMessage
	if err := json.Unmarshal(message, &eventMap); err != nil {
		return err
	}

	// FIXME: Couldn't find any field cluster_name in the received network log
	// Error Msg: unexpected end of JSON input
	//
	// clusterName := eventMap["cluster_name"]
	// clusterNameStr := ""
	// if err := json.Unmarshal(clusterName, &clusterNameStr); err != nil {
	// 	log.Error().Stack().Msg(err.Error())
	// 	return err
	// }
	// add cluster_name to the event
	// event.ClusterName = clusterNameStr //Refer above comment

	flowEvent, exists := eventMap["flow"]
	if !exists {
		return nil
	}
	if err := json.Unmarshal(flowEvent, &event); err != nil {
		return err
	}

	cfc.netLogEvents = append(cfc.netLogEvents, event)
	cfc.netLogEventsCount++

	if cfc.netLogEventsCount == cfc.eventsBuffer {
		if len(cfc.netLogEvents) > 0 {
			for _, netLog := range cfc.netLogEvents {
				time, _ := strconv.ParseInt(netLog.Time, 10, 64)
				flow := cilium.Flow{
					TrafficDirection: cilium.TrafficDirection(plugin.TrafficDirection[netLog.TrafficDirection]),
					PolicyMatchType:  uint32(netLog.PolicyMatchType),
					DropReason:       uint32(netLog.DropReason),
					Verdict:          cilium.Verdict(plugin.Verdict[netLog.Verdict]),
					Time: &timestamppb.Timestamp{
						Seconds: time,
					},
				}
				var err error
				if netLog.EventType != nil {
					err = json.Unmarshal(netLog.EventType, &flow.EventType)
					if err != nil {
						log.Error().Msg("Error while unmarshing event type :" + err.Error())
						continue
					}
				}

				if netLog.Source != nil {
					err = json.Unmarshal(netLog.Source, &flow.Source)
					if err != nil {
						log.Error().Msg("Error while unmarshing source :" + err.Error())
						continue
					}
				}

				if netLog.Destination != nil {
					err = json.Unmarshal(netLog.Destination, &flow.Destination)
					if err != nil {
						log.Error().Msg("Error while unmarshing destination :" + err.Error())
						continue
					}
				}

				if netLog.IP != nil {
					err = json.Unmarshal(netLog.IP, &flow.IP)
					if err != nil {
						log.Error().Msg("Error while unmarshing ip :" + err.Error())
						continue
					}
				}

				if netLog.L4 != nil {
					err = json.Unmarshal(netLog.L4, &flow.L4)
					if err != nil {
						log.Error().Msg("Error while unmarshing l4 :" + err.Error())
						continue
					}
				}

				if netLog.L7 != nil {
					l7Byte := netLog.L7
					if len(l7Byte) != 0 {
						err = json.Unmarshal(l7Byte, &flow.L7)
						if err != nil {
							log.Error().Msg("Error while unmarshing l7 :" + err.Error())
							continue
						}
					}
				}

				plugin.CiliumFlowsKafkaMutex.Lock()
				plugin.CiliumFlowsKafka = append(plugin.CiliumFlowsKafka, &flow)
				plugin.CiliumFlowsKafkaMutex.Unlock()
			}
			cfc.netLogEvents = nil
			cfc.netLogEvents = make([]types.NetworkLogEvent, 0, cfc.eventsBuffer)
		}

		cfc.netLogEventsCount = 0
	}

	return nil
}

func (cfc *KnoxFeedConsumer) PushNetworkLogToDB() bool {
	if err := libs.InsertNetworkLogToDB(cfg.GetCfgDB(), cfc.netLogEvents); err != nil {
		log.Error().Msgf("InsertNetworkFlowToDB err: %s", err.Error())
		return false
	}

	return true
}

// == //

func (cfc *KnoxFeedConsumer) processSystemLogMessage(message []byte) error {
	syslogEvent := types.SystemLogEvent{}

	err := json.Unmarshal(message, &syslogEvent)
	if err != nil {
		log.Error().Msgf("Error unumarshaling event: %s\n", err.Error())
		return err
	}

	cfc.syslogEvents = append(cfc.syslogEvents, syslogEvent)
	cfc.syslogEventsCount++

	if cfc.syslogEventsCount == cfc.eventsBuffer {
		if len(cfc.syslogEvents) > 0 {
			for _, syslog := range cfc.syslogEvents {
				log := pb.Log{
					ClusterName:   syslog.ClusterName,
					HostName:      syslog.HostName,
					NamespaceName: syslog.NamespaceName,
					PodName:       syslog.PodName,
					Source:        syslog.Source,
					Operation:     syslog.Operation,
					Resource:      syslog.Resource,
					Data:          syslog.Data,
					Result:        syslog.Result,
				}
				plugin.KubeArmorKafkaLogsMutex.Lock()
				plugin.KubeArmorKafkaLogs = append(plugin.KubeArmorKafkaLogs, &log)
				plugin.KubeArmorKafkaLogsMutex.Unlock()
			}
			cfc.syslogEvents = nil
			cfc.syslogEvents = make([]types.SystemLogEvent, 0, cfc.eventsBuffer)
		}

		cfc.syslogEventsCount = 0
	}

	return nil
}

func (cfc *KnoxFeedConsumer) PushSystemLogToDB() bool {
	if err := libs.InsertSystemLogToDB(cfg.GetCfgDB(), cfc.syslogEvents); err != nil {
		log.Error().Msgf("InsertSystemLogToDB err: %s", err.Error())
		return false
	}

	return true
}

// =================== //
// == Consumer Main == //
// =================== //

func StartConsumer() {
	numOfConsumers = viper.GetInt("feed-consumer.kafka.number-of-consumers")

	if Status == STATUS_RUNNING {
		log.Info().Msg("There is already running consumer(s)")
		return
	}

	n := 0
	log.Info().Msgf("%d Knox feed consumer(s) started", numOfConsumers)

	for n < numOfConsumers {
		c := &KnoxFeedConsumer{
			id: n + 1,
		}

		c.setupKafkaConfig()
		consumers = append(consumers, c)
		go c.startConsumer()
		waitG.Add(1)
		n++
	}

	stopChan = make(chan struct{})
	Status = STATUS_RUNNING

	log.Info().Msg("Knox feed consumer(s) started")
}

func StopConsumer() {
	if Status != STATUS_RUNNING {
		log.Info().Msg("There is no running consumer(s)")
		return
	}

	Status = STATUS_IDLE
	close(stopChan)
	waitG.Wait()

	consumers = []*KnoxFeedConsumer{} // clear

	log.Info().Msg("Knox feed consumer(s) stopped")
}
