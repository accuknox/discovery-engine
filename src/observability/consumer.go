package observability

import (
	"sync"

	ppb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/publisher"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"google.golang.org/grpc"
)

type SummaryConsumer struct {
	ClusterName   string
	ContainerName string
	PodName       string
	Namespace     string
	Labels        string
	Deployment    string
	Operation     string
	Events        chan *types.SystemSummary
}

type SummaryStore struct {
	Consumers map[*SummaryConsumer]struct{}
	Mutex     sync.Mutex
}

var SysSummary SummaryStore

func init() {
	SysSummary = SummaryStore{
		Consumers: map[*SummaryConsumer]struct{}{},
		Mutex:     sync.Mutex{},
	}
}

// NewSummaryConsumer - Consumer struct for publisher
func NewSummaryConsumer(req *ppb.SummaryRequest) *SummaryConsumer {
	return &SummaryConsumer{
		ClusterName: req.ClusterName,
		PodName:     req.PodName,
		Namespace:   req.Namespace,
		Labels:      req.Labels,
		Deployment:  req.DeploymentName,
		Operation:   req.Operation,
		Events:      make(chan *types.SystemSummary),
	}
}

// AddConsumer adds a new SummaryConsumer to the store
func (sc *SummaryStore) AddConsumer(c *SummaryConsumer) {
	sc.Mutex.Lock()
	defer sc.Mutex.Unlock()

	sc.Consumers[c] = struct{}{}
	log.Info().Msgf("New consumer added")
}

// RemoveConsumer removes a SummaryConsumer from the store
func (sc *SummaryStore) RemoveConsumer(c *SummaryConsumer) {
	sc.Mutex.Lock()
	defer sc.Mutex.Unlock()

	log.Info().Msgf("Consumer removed")
	delete(sc.Consumers, c)
}

// Publish -- Publish messages to gRPC stream
func (sc *SummaryStore) Publish(summary *types.SystemSummary) {
	sc.Mutex.Lock()
	defer sc.Mutex.Unlock()

	for consumer := range sc.Consumers {
		if validateSummaryRequest(consumer, *summary) {
			consumer.Events <- summary
		}
	}
}

func validateSummaryRequest(consumer *SummaryConsumer, summary types.SystemSummary) bool {

	// validate if the request matches with the summary data
	if consumer.ClusterName != "" && consumer.ClusterName != summary.ClusterName {
		return false
	}

	if consumer.Deployment != "" && consumer.Deployment != summary.Deployment {
		return false
	}

	if consumer.Labels != "" && consumer.Labels != summary.Labels {
		return false
	}

	if consumer.PodName != "" && consumer.PodName != summary.PodName {
		return false
	}

	if consumer.Namespace != "" && consumer.Namespace != summary.NamespaceName {
		return false
	}

	if consumer.Operation != "" && consumer.Operation != summary.Operation {
		return false
	}

	return true
}

func convertSystemSummaryToGrpcResponse(summary *types.SystemSummary) *ppb.SummaryResponse {
	var workload *ppb.Workload
	workload.Type = summary.Workload.Type
	workload.Name = summary.Workload.Name
	return &ppb.SummaryResponse{
		ClusterName:   summary.ClusterName,
		ClusterId:     summary.ClusterId,
		NamespaceName: summary.NamespaceName,
		NamespaceId:   summary.NamespaceId,
		ContainerName: summary.ContainerName,
		ContainerId:   summary.ContainerID,
		PodName:       summary.PodName,
		PodId:         summary.PodId,
		Operation:     summary.Operation,
		Labels:        summary.Labels,
		Source:        summary.Source,
		Destination:   summary.Destination,
		DestNamespace: summary.DestNamespace,
		DestLabels:    summary.DestLabels,
		NwType:        summary.NwType,
		IP:            summary.IP,
		Port:          summary.Port,
		Protocol:      summary.Protocol,
		Action:        summary.Action,
		Count:         summary.Count,
		UpdatedTime:   summary.UpdatedTime,
		WorkspaceId:   summary.WorkspaceId,
		Workload:      workload,
	}
}

func sendSummaryInGrpcStream(stream grpc.ServerStream, summary *types.SystemSummary) error {
	resp := convertSystemSummaryToGrpcResponse(summary)
	err := stream.SendMsg(resp)
	if err != nil {
		log.Error().Msgf("sending summary in grpc stream failed err=%v", err.Error())
		return err
	}
	return nil
}

// RelaySummaryEventToGrpcStream
func (sc *SummaryStore) RelaySummaryEventToGrpcStream(stream grpc.ServerStream, consumer *SummaryConsumer) error {
	for {
		select {
		case <-stream.Context().Done():
			// client disconnected
			sc.RemoveConsumer(consumer)
			return nil
		case summary, ok := <-consumer.Events:
			if !ok {
				// channel closed and all items are consumed
				return nil
			}
			if err := sendSummaryInGrpcStream(stream, summary); err != nil {
				return err
			}
		}
	}
}
