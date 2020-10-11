package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	autopol "github.com/seungsoo-lee/knoxAutoPolicy/autodiscovery"
	"github.com/seungsoo-lee/knoxAutoPolicy/dbase"

	"github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
)

//ConnectHubbleRelay function
func ConnectHubbleRelay() *grpc.ClientConn {
	url := os.Getenv("HUBBLE_URL")
	port := os.Getenv("HUBBLE_PORT")
	addr := url + ":" + port
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	return conn
}

//to get cluster name from labels
func getCluster(value string) (string, error) {
	pos := strings.LastIndex(value, "=")
	if pos == -1 {
		return "", errors.New("error")
	}
	adjustedPos := pos + len("=")
	if adjustedPos >= len(value) {
		return "", errors.New("error")
	}
	return value[adjustedPos:], nil

}

//insertFlow populate the aggrgator with network flows.
func insertFlow(res *observer.GetFlowsResponse) error {
	db := dbase.Conn()
	defer db.Close()

	switch r := res.ResponseTypes.(type) {
	case *observer.GetFlowsResponse_Flow:
		flow := r.Flow

		var ethernet, ip, source, destination, l4, l7, eventType, sourceService, destinationService []byte
		var err error

		if flow.Ethernet != nil {
			eth := &observer.Ethernet{Source: flow.Ethernet.Source, Destination: flow.Ethernet.Destination}
			ethernet, err = json.Marshal(eth)
			if err != nil {
				return err
			}
		}
		if flow.IP != nil {
			i := &observer.IP{Source: flow.IP.Source, Destination: flow.IP.Destination}
			ip, err = json.Marshal(i)
			if err != nil {
				return err
			}
		}

		switch layer4 := flow.L4.Protocol.(type) {
		case *observer.Layer4_TCP:
			t := &observer.TCP{
				SourcePort:      layer4.TCP.SourcePort,
				DestinationPort: layer4.TCP.DestinationPort,
				Flags:           layer4.TCP.Flags}

			ly4 := &observer.Layer4_TCP{
				TCP: t,
			}

			l4, err = json.Marshal(ly4)
			if err != nil {
				return err
			}

		case *observer.Layer4_UDP:

			t := &observer.UDP{
				SourcePort:      layer4.UDP.SourcePort,
				DestinationPort: layer4.UDP.DestinationPort}

			ly4 := &observer.Layer4_UDP{
				UDP: t,
			}

			l4, err = json.Marshal(ly4)
			if err != nil {
				return err
			}

		case *observer.Layer4_ICMPv4:

			t := &observer.ICMPv4{
				Type: layer4.ICMPv4.Type,
				Code: layer4.ICMPv4.Code}

			ly4 := &observer.Layer4_ICMPv4{
				ICMPv4: t,
			}

			l4, err = json.Marshal(ly4)
			if err != nil {
				return err
			}

		case *observer.Layer4_ICMPv6:

			t := &observer.ICMPv6{
				Type: layer4.ICMPv6.Type,
				Code: layer4.ICMPv6.Code}

			ly4 := &observer.Layer4_ICMPv6{
				ICMPv6: t,
			}
			l4, err = json.Marshal(ly4)
			if err != nil {
				return err
			}
		}

		if flow.Type == 2 {
			switch layer7 := flow.L7.Record.(type) {
			case *observer.Layer7_Dns:
				dns := &observer.DNS{
					Query:             layer7.Dns.Query,
					Ips:               layer7.Dns.Ips,
					Ttl:               layer7.Dns.Ttl,
					Cnames:            layer7.Dns.Cnames,
					ObservationSource: layer7.Dns.ObservationSource,
					Rcode:             layer7.Dns.Rcode,
					Qtypes:            layer7.Dns.Qtypes,
					Rrtypes:           layer7.Dns.Rrtypes,
				}
				DNS := &observer.Layer7_Dns{
					Dns: dns,
				}
				w := &observer.Layer7{
					Type:      flow.L7.Type,
					LatencyNs: flow.L7.LatencyNs,
					Record:    DNS,
				}
				l7, err = json.Marshal(w)
				if err != nil {
					return err
				}
			case *observer.Layer7_Http:
				var headers []*observer.HTTPHeader
				for i := 0; i < len(layer7.Http.Headers); i++ {
					h := &observer.HTTPHeader{
						Key:   layer7.Http.Headers[i].Key,
						Value: layer7.Http.Headers[i].Value,
					}
					headers = append(headers, h)
				}
				http := &observer.HTTP{
					Code:     layer7.Http.Code,
					Method:   layer7.Http.Method,
					Url:      layer7.Http.Url,
					Protocol: layer7.Http.Protocol,
					Headers:  headers,
				}
				HTTP := &observer.Layer7_Http{
					Http: http,
				}
				w := &observer.Layer7{
					Type:      flow.L7.Type,
					LatencyNs: flow.L7.LatencyNs,
					Record:    HTTP,
				}
				l7, err = json.Marshal(w)
				if err != nil {
					return err
				}

			case *observer.Layer7_Kafka:
				k := &observer.Kafka{
					ErrorCode:     layer7.Kafka.ErrorCode,
					ApiVersion:    layer7.Kafka.ApiVersion,
					ApiKey:        layer7.Kafka.ApiKey,
					CorrelationId: layer7.Kafka.CorrelationId,
					Topic:         layer7.Kafka.Topic,
				}
				kafka := &observer.Layer7_Kafka{
					Kafka: k,
				}
				w := &observer.Layer7{
					Type:      flow.L7.Type,
					LatencyNs: flow.L7.LatencyNs,
					Record:    kafka,
				}
				l7, err = json.Marshal(w)
				if err != nil {
					return err
				}
			}
		}

		if flow.Source != nil {
			s := &observer.Endpoint{
				ID:        flow.Source.ID,
				Identity:  flow.Source.Identity,
				Namespace: flow.Source.Namespace,
				Labels:    flow.Source.Labels,
				PodName:   flow.Source.PodName,
			}
			source, err = json.Marshal(s)
			if err != nil {
				return err
			}
		}

		if flow.Destination != nil {
			d := &observer.Endpoint{
				ID:        flow.Destination.ID,
				Identity:  flow.Destination.Identity,
				Namespace: flow.Destination.Namespace,
				Labels:    flow.Destination.Labels,
				PodName:   flow.Destination.PodName,
			}
			destination, err = json.Marshal(d)
			if err != nil {
				return err
			}
		}

		if flow.EventType != nil {
			ev := &observer.CiliumEventType{
				Type:    flow.EventType.Type,
				SubType: flow.EventType.SubType,
			}

			eventType, err = json.Marshal(ev)
			if err != nil {
				return err
			}
		}

		if flow.SourceService != nil {
			srcSrv := &observer.Service{
				Name:      flow.SourceService.Name,
				Namespace: flow.SourceService.Namespace,
			}
			sourceService, err = json.Marshal(srcSrv)
			if err != nil {
				return err
			}
		}

		if flow.DestinationService != nil {
			destSrv := &observer.Service{
				Name:      flow.DestinationService.Name,
				Namespace: flow.DestinationService.Namespace,
			}
			destinationService, err = json.Marshal(destSrv)
			if err != nil {
				return err
			}
		}

		var sr string
		for i := 0; i < len(flow.Source.Labels); i++ {
			if strings.Contains(flow.Source.Labels[i], "cluster") {
				srcCluster, err := getCluster(flow.Source.Labels[i])
				if err != nil {
					return err
				}
				sr = srcCluster
			}
		}

		var dr string
		for i := 0; i < len(flow.Destination.Labels); i++ {
			if strings.Contains(flow.Destination.Labels[i], "cluster") {
				destCluster, err := getCluster(flow.Destination.Labels[i])
				if err != nil {
					return err
				}
				dr = destCluster
			}
		}

		srcPodName := flow.Source.PodName
		destPodName := flow.Destination.PodName

		stmt, err := db.Prepare("INSERT INTO network_flow(time,src_cluster_name,dest_cluster_name,src_pod_name,dest_pod_name,verdict,drop_reason,type,node_name,traffic_direction,trace_observation_point,summary,ethernet,ip,l4,l7,reply,source,destination,event_type,source_service,destination_service,policy_match_type) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
		if err != nil {
			return err
		}
		_, err = stmt.Exec(flow.Time.Seconds, sr, dr, srcPodName, destPodName, flow.Verdict, flow.DropReason, flow.Type, flow.NodeName, flow.TrafficDirection, flow.TraceObservationPoint, flow.Summary, ethernet, ip, l4, l7, flow.Reply, source, destination, eventType, sourceService, destinationService, flow.PolicyMatchType)
		if err != nil {
			return err
		}

	}
	return nil
}

//StartFeederService fetch the stream of network flow to the aggregator.
func StartFeederService(ctx context.Context) error {
	conn := ConnectHubbleRelay()
	defer conn.Close()

	client := observer.NewObserverClient(conn)

	req := &observer.GetFlowsRequest{
		Number:    20,
		Follow:    true,
		Whitelist: nil,
		Blacklist: nil,
		Since:     nil,
		Until:     nil,
	}

	if stream, err := client.GetFlows(ctx, req); err == nil {
		for {
			res, err := stream.Recv()
			if err == io.EOF {
				return errors.New("end of file")
			}
			if err != nil {
				return errors.New("can't receive network flow")
			}
			err = insertFlow(res)
			if err != nil {
				return err
			}
		}
	} else {
		return errors.New("unable to stream network flow")
	}
}

func main() {
	autopol.TestGenerateNetworkPolicies()
	url := os.Getenv("HUBBLE_URL")
	port := os.Getenv("HUBBLE_PORT")
	fmt.Println(url, port)
}
