package feedconsumer

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apache/pulsar-client-go/pulsar"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/rs/zerolog"

	"github.com/spf13/viper"

	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/plugin"
	types "github.com/accuknox/auto-policy-discovery/src/types"
	cilium "github.com/cilium/cilium/api/v1/flow"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const ( // status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

const (
	DRIVER_KAFKA  = "kafka"
	DRIVER_PULSAR = "pulsar"
)

const (
	MSG_OFFSET_EARLIEST = "earliest"
	MSG_OFFSET_LATEST   = "latest"
)

// ====================== //
// == Global Variables == //
// ====================== //

var numOfConsumers int
var consumers []*KnoxFeedConsumer
var Status string

var ConsumerMutex sync.Mutex
var waitG sync.WaitGroup
var stopChan chan struct{}

var pulsarReceiver chan pulsar.ConsumerMessage

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()

	ConsumerMutex = sync.Mutex{}
	waitG = sync.WaitGroup{}
	Status = STATUS_IDLE

	consumers = []*KnoxFeedConsumer{}

	pulsarReceiver = make(chan pulsar.ConsumerMessage, 100)
}

// ======================== //
// == Knox Feed Consumer == //
// ======================== //

type KnoxFeedConsumer struct {
	id             int
	driver         string
	kafkaConfig    kafka.ConfigMap
	pulsarConfig   pulsar.ClientOptions
	ciliumTopic    string
	kubearmorTopic string
	consumerGroup  string
	messageOffset  string
	eventsBuffer   int

	netLogEvents      []types.NetworkLogEvent
	netLogEventsCount int

	syslogEvents      []types.SystemLogEvent
	syslogEventsCount int
}

func (cfc *KnoxFeedConsumer) setupConfig() {
	cfc.driver = viper.GetString("feed-consumer.driver")
	servers := viper.GetStringSlice("feed-consumer.servers")

	cfc.consumerGroup = viper.GetString("feed-consumer.consumer-group") + "-" + libs.RandSeq(15)
	cfc.ciliumTopic = viper.GetString("feed-consumer.topic.cilium")
	cfc.kubearmorTopic = viper.GetString("feed-consumer.topic.kubearmor")

	cfc.messageOffset = viper.GetString("feed-consumer.message-offset")
	cfc.eventsBuffer = viper.GetInt("feed-consumer.event-buffer-size")

	cfc.netLogEvents = make([]types.NetworkLogEvent, 0, cfc.eventsBuffer)
	cfc.syslogEvents = make([]types.SystemLogEvent, 0, cfc.eventsBuffer)

	encryptEnabled := viper.GetBool("feed-consumer.encryption.enable")
	caCertPath := viper.GetString("feed-consumer.encryption.ca-cert")
	authEnabled := viper.GetBool("feed-consumer.auth.enable")
	keyPath := viper.GetString("feed-consumer.auth.key")
	certPath := viper.GetString("feed-consumer.auth.cert")
	keystorePath := viper.GetString("feed-consumer.auth.keystore.path")
	keystorePassword := viper.GetString("feed-consumer.auth.keystore.password")

	if cfc.driver == DRIVER_KAFKA {
		cfc.kafkaConfig = kafka.ConfigMap{
			"enable.auto.commit":      true,
			"auto.commit.interval.ms": 1000,
			"bootstrap.servers":       strings.Join(servers, ","),
			"broker.address.family":   viper.GetString("feed-consumer.kafka.server-address-family"),
			"group.id":                cfc.consumerGroup,
			"session.timeout.ms":      viper.GetString("feed-consumer.kafka.session-timeout"),
			"auto.offset.reset":       cfc.messageOffset,
		}

		// Set up TLS encryption/authentication configs
		if encryptEnabled {
			if err := cfc.kafkaConfig.SetKey("security.protocol", "SSL"); err != nil {
				log.Error().Msg(err.Error())
			}
			if err := cfc.kafkaConfig.SetKey("ssl.ca.location", caCertPath); err != nil {
				log.Error().Msg(err.Error())
			}
			if authEnabled {
				if err := cfc.kafkaConfig.SetKey("ssl.keystore.location", keystorePath); err != nil {
					log.Error().Msg(err.Error())
				}
				if err := cfc.kafkaConfig.SetKey("ssl.keystore.password", keystorePassword); err != nil {
					log.Error().Msg(err.Error())
				}
			}
		}
	} else if cfc.driver == DRIVER_PULSAR {
		connTimeout := viper.GetInt64("feed-consumer.pulsar.connection-timeout")
		opTimeout := viper.GetInt64("feed-consumer.pulsar.operation-timeout")
		cfc.pulsarConfig.ConnectionTimeout = time.Duration(connTimeout) * time.Second
		cfc.pulsarConfig.OperationTimeout = time.Duration(opTimeout) * time.Second
		if encryptEnabled {
			cfc.pulsarConfig.URL = "pulsar+ssl://" + strings.Join(servers, ",")
			cfc.pulsarConfig.TLSTrustCertsFilePath = caCertPath
			if authEnabled {
				cfc.pulsarConfig.Authentication = pulsar.NewAuthenticationTLS(certPath, keyPath)
			}
		} else {
			cfc.pulsarConfig.URL = "pulsar://" + strings.Join(servers, ",")
		}
	} else {
		log.Error().Msg("Invalid feed-consumer driver. Supported drivers are 'kafka' and 'pulsar'.")
	}
}

func (cfc *KnoxFeedConsumer) HandlePollEvent(ev interface{}) bool {
	var topic string
	var msg []byte

	switch e := ev.(type) {
	case pulsar.Message:
		topic = e.Topic()
		msg = e.Payload()
	case *kafka.Message:
		topic = *e.TopicPartition.Topic
		msg = e.Value
	case kafka.Error:
		// Errors should generally be considered
		// informational, the client will try to
		// automatically recover.
		// But in this example we choose to terminate
		// the application if all brokers are down.
		log.Error().Msgf("Error: %v: %v\n", e.Code(), e)
		if e.Code() == kafka.ErrAllBrokersDown {
			return false
		}
	default:
		log.Debug().Msgf("Ignored %v\n", e)
	}

	if topic == cfc.ciliumTopic {
		if err := cfc.processNetworkLogMessage(msg); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if topic == cfc.kubearmorTopic {
		if err := cfc.processSystemLogMessage(msg); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if topic != "" {
		log.Info().Msgf("Received message from unknown topic %s\n", topic)
	}

	return true
}

func (cfc *KnoxFeedConsumer) getSubscriptionTopics() []string {
	subTopics := []string{}

	if cfg.GetCfgNetworkLogFrom() == "feed-consumer" {
		subTopics = append(subTopics, cfc.ciliumTopic)
	}

	if cfg.GetCfgSystemLogFrom() == "feed-consumer" {
		subTopics = append(subTopics, cfc.kubearmorTopic)
	}
	return subTopics
}

func (cfc *KnoxFeedConsumer) startConsumer() {
	if cfc.driver == DRIVER_KAFKA {
		cfc.startConsumerKafka()
	} else if cfc.driver == DRIVER_PULSAR {
		cfc.startConsumerPulsar()
	}
}

func (cfc *KnoxFeedConsumer) startConsumerKafka() {
	defer waitG.Done()

	c, err := kafka.NewConsumer(&cfc.kafkaConfig)
	if err != nil {
		log.Error().Msgf("Failed to create consumer: %s", err)
		return
	}
	log.Debug().Msgf("Created Consumer %v", c)

	subTopics := cfc.getSubscriptionTopics()
	err = c.SubscribeTopics(subTopics, nil)
	if err != nil {
		log.Error().Msgf("Failed to subscribe topics: %s", err)
		return
	}

	log.Info().Msgf("Starting consumer %d, topics: %v", cfc.id, subTopics)

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
			run = cfc.HandlePollEvent(ev)
		}
	}

	log.Info().Msgf("Closing consumer %d", cfc.id)
	if err := c.Close(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func (cfc *KnoxFeedConsumer) startConsumerPulsar() {
	defer waitG.Done()

	c, err := pulsar.NewClient(cfc.pulsarConfig)
	if err != nil {
		log.Error().Msgf("Failed to create pulsar client: %s", err)
		return
	}
	defer c.Close()

	log.Debug().Msgf("Created pulsar client %v", c)

	subTopics := cfc.getSubscriptionTopics()

	subOffset := pulsar.SubscriptionPositionLatest
	if cfc.messageOffset == MSG_OFFSET_EARLIEST {
		subOffset = pulsar.SubscriptionPositionEarliest
	}

	sub, err := c.Subscribe(pulsar.ConsumerOptions{
		Topics:                      subTopics,
		SubscriptionName:            cfc.consumerGroup,
		Type:                        pulsar.Shared,
		SubscriptionInitialPosition: subOffset,
		MessageChannel:              pulsarReceiver,
	})
	if err != nil {
		log.Error().Msgf("Failed to subscribe topics: %s", err)
		return
	}
	defer sub.Close()

	log.Info().Msgf("Starting consumer %d, topics: %v", cfc.id, subTopics)

	run := true
	for run {
		select {
		case <-stopChan:
			log.Info().Msgf("Got a signal to terminate the consumer %d", cfc.id)
			run = false

		default:
			ev := <-pulsarReceiver
			_ = sub.Ack(ev)
			run = cfc.HandlePollEvent(ev.Message)
		}
	}

	log.Info().Msgf("Closing consumer %d", cfc.id)
}

func (cfc *KnoxFeedConsumer) processNetworkLogMessage(message []byte) error {
	event := types.NetworkLogEvent{}
	var eventMap map[string]json.RawMessage
	if err := json.Unmarshal(message, &eventMap); err != nil {
		return err
	}

	clusterName, exists := eventMap["cluster_name"]

	clusterNameStr := ""
	if !exists {
		clusterNameStr = "default"
	} else {
		if err := json.Unmarshal(clusterName, &clusterNameStr); err != nil {
			log.Error().Stack().Msg(err.Error())
			return err
		}
	}

	flowEvent, exists := eventMap["flow"]
	if !exists {
		return errors.New("Unable to parse feed-consumer message")
	}
	if err := json.Unmarshal(flowEvent, &event); err != nil {
		log.Error().Msg(err.Error())
		return err
	}

	// add cluster_name to the event
	event.ClusterName = clusterNameStr
	cfc.netLogEvents = append(cfc.netLogEvents, event)
	cfc.netLogEventsCount++

	if cfc.netLogEventsCount == cfc.eventsBuffer {
		if len(cfc.netLogEvents) > 0 {
			for _, netLog := range cfc.netLogEvents {
				time, _ := strconv.ParseInt(netLog.Time, 10, 64)
				flow := &cilium.Flow{
					TrafficDirection: cilium.TrafficDirection(plugin.TrafficDirection[netLog.TrafficDirection]),
					PolicyMatchType:  uint32(netLog.PolicyMatchType),
					DropReason:       uint32(netLog.DropReason),
					Verdict:          cilium.Verdict(plugin.Verdict[netLog.Verdict]),
					Time: &timestamppb.Timestamp{
						Seconds: time,
					},
					EventType:   &cilium.CiliumEventType{},
					Source:      &cilium.Endpoint{},
					Destination: &cilium.Endpoint{},
					IP:          &cilium.IP{},
					L4:          &cilium.Layer4{},
					L7:          &cilium.Layer7{},
					IsReply:     &wrapperspb.BoolValue{Value: netLog.Reply},
				}

				// _ = is to ignore the return value
				_ = plugin.GetFlowData(netLog.EventType, flow.EventType)
				_ = plugin.GetFlowData(netLog.Source, flow.Source)
				_ = plugin.GetFlowData(netLog.Destination, flow.Destination)
				_ = plugin.GetFlowData(netLog.IP, flow.IP)
				_ = plugin.GetFlowData(netLog.L4, flow.L4)
				_ = plugin.GetFlowData(netLog.L7, flow.L7)

				knoxFlow, valid := plugin.ConvertCiliumFlowToKnoxNetworkLog(flow)
				if valid {
					knoxFlow.ClusterName = netLog.ClusterName
					plugin.CiliumFlowsFCMutex.Lock()
					plugin.CiliumFlowsFC = append(plugin.CiliumFlowsFC, &knoxFlow)
					plugin.CiliumFlowsFCMutex.Unlock()
				}
			}
			cfc.netLogEvents = nil
			cfc.netLogEvents = make([]types.NetworkLogEvent, 0, cfc.eventsBuffer)
		}

		cfc.netLogEventsCount = 0
	}

	return nil
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
				log := pb.Alert{
					ClusterName:   syslog.ClusterName,
					HostName:      syslog.HostName,
					NamespaceName: syslog.NamespaceName,
					ContainerName: syslog.ContainerName,
					PodName:       syslog.PodName,
					Source:        syslog.Source,
					Operation:     syslog.Operation,
					Resource:      syslog.Resource,
					Data:          syslog.Data,
					Result:        syslog.Result,
				}

				knoxLog, err := plugin.ConvertKubeArmorLogToKnoxSystemLog(&log)
				if err != nil {
					continue
				}
				knoxLog.ClusterName = syslog.Clustername
				plugin.KubeArmorFCLogsMutex.Lock()
				plugin.KubeArmorFCLogs = append(plugin.KubeArmorFCLogs, &knoxLog)
				plugin.KubeArmorFCLogsMutex.Unlock()
			}
			cfc.syslogEvents = nil
			cfc.syslogEvents = make([]types.SystemLogEvent, 0, cfc.eventsBuffer)
		}

		cfc.syslogEventsCount = 0
	}

	return nil
}

// =================== //
// == Consumer Main == //
// =================== //

func StartConsumer() {
	if Status == STATUS_RUNNING {
		return
	}

	numOfConsumers = viper.GetInt("feed-consumer.number-of-consumers")

	n := 0
	log.Info().Msgf("%d Knox feed consumer(s) started", numOfConsumers)

	for n < numOfConsumers {
		c := &KnoxFeedConsumer{
			id: n + 1,
		}

		c.setupConfig()
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
