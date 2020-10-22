package localtest

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/accuknox/knoxAutoPolicy/libs"
	"github.com/rs/zerolog/log"

	_ "github.com/go-sql-driver/mysql"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	pb "github.com/accuknox/knoxServiceFlowMgmt/src/proto"
)

func FlowFilter() flowpb.FlowFilter {
	filter := flowpb.FlowFilter{
		DestinationPort: []string{"53"},
		SourceLabel:     []string{"k8s:io.kubernetes.pod.namespace=multiubuntu"},
		// Verdict:     []flowpb.Verdict{flowbp.Verdict_FORWARDED},
	}
	return filter
}

func Conn() (db *sql.DB) {
	dbDriver := libs.GetEnv("NETWORKFLOW_DB_DRIVER", "mysql")
	dbUser := libs.GetEnv("NETWORKFLOW_DB_USER", "root")
	dbPass := libs.GetEnv("NETWORKFLOW_DB_PASS", "password")
	dbName := libs.GetEnv("NETWORKFLOW_DB_NAME", "flow_management")
	// table "network_flow"

	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@tcp(localhost:3306)/"+dbName)
	if err != nil {
		panic(err.Error())
	}

	return db
}

//getTrafficDirection returns traffic direction.
func getTrafficDirection(trafficDirection int64) (string, error) {

	switch trafficDirection {
	case 0:
		return "TRAFFIC_DIRECTION_UNKNOWN", nil
	case 1:
		return "INGRESS", nil
	case 2:
		return "EGRESS", nil
	}
	fmt.Println("Unknown traffic direction!")
	return "", errors.New("unknown traffic direction")
}

//getverdict returns verdict.
func getVerdict(verdict int64) (string, error) {

	switch verdict {
	case 0:
		return "VERDICT_UNKNOWN", nil
	case 1:
		return "FORWARDED", nil
	case 2:
		return "DROPPED", nil
	case 3:
		return "ERROR", nil
	}
	fmt.Println("Unknown verdict!")
	return "", errors.New("unknown verdict")
}

//getFlowType returns flowtype.
func getFlowType(flowType int64) (string, error) {

	switch flowType {
	case 0:
		return "UNKNOWN_TYPE", nil
	case 1:
		return "L3_L4", nil
	case 2:
		return "L7", nil
	}
	fmt.Println("Unknown FlowType!")
	return "", errors.New("unknown flow type")
}

//flowScanner scans the trafficflow.
func flowScanner(results *sql.Rows) ([]*pb.TrafficFlow, error) {
	var trafficFlows []*pb.TrafficFlow
	var err error
	for results.Next() {
		trafficFlow := &pb.TrafficFlow{}
		src := &pb.Endpoint{}
		dest := &pb.Endpoint{}
		ethernet := &pb.Ethernet{}
		ip := &pb.IP{}
		l4 := &pb.Layer4{}
		l7 := &pb.Layer7{}
		srcService := &pb.Service{}
		destService := &pb.Service{}
		var verdict, flowType, trafficDirection int64
		var srcByte, destByte, ethByte, ipByte, l4Byte, l7Byte, srcServiceByte, destServiceByte, srcLabelsByte, destLabelsByte []byte
		err = results.Scan(
			&trafficFlow.Id,
			&trafficFlow.Time,
			&verdict,
			&srcByte,
			&destByte,
			&ethByte,
			&ipByte,
			&flowType,
			&l4Byte,
			&l7Byte,
			&trafficFlow.Reply,
			&srcLabelsByte,
			&destLabelsByte,
			&src.Cluster,
			&src.Pod,
			&dest.Cluster,
			&dest.Pod,
			&trafficFlow.Node,
			&srcServiceByte,
			&destServiceByte,
			&trafficDirection,
			&trafficFlow.Summary,
		)
		if err != nil {
			log.Error().Msg("Error while scanning traffic flows :" + err.Error())
			return nil, err
		}

		trafficFlow.Verdict, err = getVerdict(verdict)
		if err != nil {
			return nil, err
		}

		trafficFlow.FlowType, err = getFlowType(flowType)
		if err != nil {
			return nil, err
		}

		if srcByte != nil {
			err = json.Unmarshal([]byte(srcByte), &src)
			if err != nil {
				log.Error().Msg("Error while unmarshing source :" + err.Error())
				return nil, err
			}
			trafficFlow.Source = src
		}

		if srcLabelsByte != nil {
			var srcLabelStr []string
			err = json.Unmarshal([]byte(srcLabelsByte), &srcLabelStr)
			if err != nil {
				log.Error().Msg("Error while unmarshing source labels :" + err.Error())
				return nil, err
			}
			trafficFlow.Source.Lables = srcLabelStr
		}

		if destByte != nil {
			err = json.Unmarshal([]byte(destByte), &dest)
			if err != nil {
				log.Error().Msg("Error while unmarshing destination :" + err.Error())
				return nil, err
			}
			trafficFlow.Destination = dest
		}

		if srcLabelsByte != nil {
			var destLabelStr []string
			err = json.Unmarshal([]byte(destLabelsByte), &destLabelStr)
			if err != nil {
				log.Error().Msg("Error while unmarshing destination labels :" + err.Error())
				return nil, err
			}
			trafficFlow.Destination.Lables = destLabelStr
		}

		if ethByte != nil {
			err = json.Unmarshal([]byte(ethByte), &ethernet)
			if err != nil {
				log.Error().Msg("Error while unmarshing ethernet :" + err.Error())
				return nil, err
			}
			trafficFlow.Ethernet = ethernet
		}

		if ipByte != nil {
			err = json.Unmarshal([]byte(ipByte), &ip)
			if err != nil {
				log.Error().Msg("Error while unmarshing IP :" + err.Error())
				return nil, err
			}
			trafficFlow.Ip = ip
		}

		if l4Byte != nil {
			err = json.Unmarshal([]byte(l4Byte), &l4)
			if err != nil {
				log.Error().Msg("Error while unmarshing L4 :" + err.Error())
				return nil, err
			}
			trafficFlow.L4 = l4
		}

		if l7Byte != nil {
			err = json.Unmarshal([]byte(l7Byte), &l7)
			if err != nil {
				log.Error().Msg("Error while unmarshing L7 :" + err.Error())
				return nil, err
			}
			trafficFlow.L7 = l7
		}

		if srcServiceByte != nil {
			err = json.Unmarshal([]byte(srcServiceByte), &srcService)
			if err != nil {
				log.Error().Msg("Error while unmarshing Source Service :" + err.Error())
				return nil, err
			}
			trafficFlow.SourceService = srcService
		}

		if destServiceByte != nil {
			err = json.Unmarshal([]byte(destServiceByte), &destService)
			if err != nil {
				log.Error().Msg("Error while unmarshing Destination Service :" + err.Error())
				return nil, err
			}
			trafficFlow.DestinationService = destService
		}

		trafficFlow.TrafficDirection, err = getTrafficDirection(trafficDirection)
		if err != nil {
			return nil, err
		}

		trafficFlows = append(trafficFlows, trafficFlow)
	}
	return trafficFlows, nil
}

func GetTrafficFlow() ([]*pb.TrafficFlow, error) {
	db := Conn()
	defer db.Close()

	results, err := db.Query("select id,time,verdict,source,destination,ethernet,ip,type,l4,l7,reply,source->>'$.labels',destination->>'$.labels',src_cluster_name,src_pod_name,dest_cluster_name,dest_pod_name,node_name,source_service,destination_service,traffic_direction,summary from network_flow")
	if err != nil {
		return nil, err
	}

	return flowScanner(results)
}

func GetTrafficFlowFromTime(after, before int64) ([]*pb.TrafficFlow, error) {
	db := Conn()

	baseQuery := "select id,time,verdict,source,destination,ethernet,ip,type,l4,l7,reply,src_cluster_name,src_pod_name,dest_cluster_name,dest_pod_name,node_name,source_service,destination_service,traffic_direction,summary from network_flow"
	rows, err := db.Query(baseQuery+" where time >= ? and time < ?", after, before)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer rows.Close()

	return flowScanner(rows)
}
