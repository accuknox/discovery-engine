package feedconsumer

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/rs/zerolog"

	"github.com/spf13/viper"

	cfg "github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

const ( // status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

// ====================== //
// == Gloabl Variables == //
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

	numOfConsumers = viper.GetInt("feed-consumer.kafka.number-of-consumers")
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

	groupID := viper.GetString("feed-consumer.kafka.group-id")
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

	clusterName := eventMap["cluster_name"]
	clusterNameStr := ""
	if err := json.Unmarshal(clusterName, &clusterNameStr); err != nil {
		return err
	}

	flowEvent := eventMap["flow"]
	if err := json.Unmarshal(flowEvent, &event); err != nil {
		return err
	}

	// add cluster_name to the event
	event.ClusterName = clusterNameStr
	cfc.netLogEvents = append(cfc.netLogEvents, event)
	cfc.netLogEventsCount++

	if cfc.netLogEventsCount == cfc.eventsBuffer {
		if len(cfc.netLogEvents) > 0 {
			isSuccess := cfc.PushNetworkLogToDB()
			if !isSuccess {
				return errors.New("error saving to DB")
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
			isSuccess := cfc.PushSystemLogToDB()
			if !isSuccess {
				return errors.New("error saving to DB")
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
	if Status == STATUS_RUNNING {
		log.Info().Msg("There is already running consumer(s)")
		return
	}

	n := 0
	log.Info().Msgf("Knox feed consumer(s) started %d", numOfConsumers)

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
