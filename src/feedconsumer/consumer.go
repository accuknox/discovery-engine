package feedconsumer

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/accuknox/knoxAutoPolicy/src/core"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

// ====================== //
// == Gloabl Variables == //
// ====================== //

var consumer *CiliumFeedsConsumer

// Status global
var Status string

var waitG sync.WaitGroup
var stopChan chan struct{}

var events []types.NetworkFlowEvent
var eventsCount int

const ( // status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

// Consumer - Consumes Cilium Feeds
type CiliumFeedsConsumer struct {
	kafkaConfig  kafka.ConfigMap
	topics       []string
	eventsBuffer int
}

func (cfc *CiliumFeedsConsumer) setupKafkaConfig() {
	bootstrapServers := viper.GetString("kafka.bootstrap-servers")
	brokderAddressFamily := viper.GetString("kafka.broker-address-family")
	sessionTimeoutMs := viper.GetString("kafka.session-timeout-ms")
	autoOffsetReset := viper.GetString("kafka.auto-offset-reset")

	groupID := viper.GetString("kafka.group-id")
	cfc.topics = viper.GetStringSlice("kafka.topics")

	cfc.eventsBuffer = viper.GetInt("kafka.events.buffer")
	events = make([]types.NetworkFlowEvent, 0, cfc.eventsBuffer)

	sslEnabled := viper.GetBool("kafka.ssl.enabled")
	securityProtocol := viper.GetString("kafka.security.protocol")
	sslCALocation := viper.GetString("kafka.ssl.ca.location")
	sslKeystoreLocation := viper.GetString("kafka.ssl.keystore.location")
	sslKeystorePassword := viper.GetString("kafka.ssl.keystore.Password")

	// Set up required configs
	cfc.kafkaConfig = kafka.ConfigMap{
		"bootstrap.servers":     bootstrapServers,
		"broker.address.family": brokderAddressFamily,
		"group.id":              groupID,
		"session.timeout.ms":    sessionTimeoutMs,
		"auto.offset.reset":     autoOffsetReset,
	}

	// Set up SSL specific configs if SSL is enabled
	if sslEnabled {
		cfc.kafkaConfig.SetKey("security.protocol", securityProtocol)
		cfc.kafkaConfig.SetKey("ssl.ca.location", sslCALocation)
		cfc.kafkaConfig.SetKey("ssl.keystore.location", sslKeystoreLocation)
		cfc.kafkaConfig.SetKey("ssl.keystore.password", sslKeystorePassword)
	}
}

func (cfc *CiliumFeedsConsumer) startConsumer() {
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

	log.Debug().Msgf("Topics: %v", cfc.topics)

	run := true
	for run == true {
		select {
		case sig := <-stopChan:
			log.Info().Msgf("Got a signal to terminate the consumer %v", sig)
			run = false

		default:
			ev := c.Poll(100)
			if ev == nil {
				continue
			}

			switch e := ev.(type) {
			case *kafka.Message:
				cfc.processMessage(e.Value)
				if e.Headers != nil {
					log.Debug().Msgf("Headers: %v", e.Headers)
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

	log.Info().Msgf("Closing consumer")
	c.Close()
}

func (cfc *CiliumFeedsConsumer) processMessage(message []byte) error {
	event := types.NetworkFlowEvent{}
	var eventMap map[string]json.RawMessage
	err := json.Unmarshal(message, &eventMap)
	if err != nil {
		log.Error().Msgf("Error unumarshaling event: %s\n", err.Error())
		return err
	}

	clusterName := eventMap["cluster_name"]
	clusterNameStr := ""
	json.Unmarshal(clusterName, &clusterNameStr)

	flowEvent := eventMap["flow"]

	errFlow := json.Unmarshal(flowEvent, &event)
	if err != nil {
		log.Error().Msgf("Error unumarshaling event data: %s\n", err.Error())
		return errFlow
	}

	// add cluster_name to the event
	event.ClusterName = clusterNameStr
	events = append(events, event)
	eventsCount++

	if eventsCount == cfc.eventsBuffer {
		if len(events) > 0 {
			isSuccess := cfc.PushToDB()
			if !isSuccess {
				return errors.New("Error saving to DB")
			}
			events = nil
			events = make([]types.NetworkFlowEvent, 0, cfc.eventsBuffer)
		}

		eventsCount = 0
	}

	return nil
}

func (cfc *CiliumFeedsConsumer) PushToDB() bool {
	if err := libs.InsertNetworkFlowToDB(core.Cfg.ConfigDB, events); err != nil {
		log.Error().Msgf("InsertNetworkFlowToDB err: %s", err.Error())
		return false
	}

	return true
}

// ============== //
// == Consumer == //
// ============== //

// StartConsumer function
func StartConsumer() {
	if consumer == nil {
		stopChan = make(chan struct{})
		waitG = sync.WaitGroup{}
		waitG.Add(1)

		consumer = &CiliumFeedsConsumer{}
		consumer.setupKafkaConfig()
		Status = STATUS_IDLE
	}

	if Status != STATUS_IDLE {
		log.Info().Msg("There is no idle consumer")
		return
	}

	go consumer.startConsumer()
	Status = STATUS_RUNNING

	log.Info().Msg("Cilium feeds consumer started")
}

// StopConsumer function
func StopConsumer() {
	if Status != STATUS_RUNNING {
		log.Info().Msg("There is no running consumer")
		return
	}

	Status = STATUS_IDLE

	close(stopChan)
	waitG.Wait()

	log.Info().Msg("The consumer stopped")
}
