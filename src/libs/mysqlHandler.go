package libs

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"

	_ "github.com/go-sql-driver/mysql"

	pb "github.com/accuknox/knoxServiceFlowMgmt/src/proto"
)

// ConnectMySQL function
func ConnectMySQL() (db *sql.DB) {
	DBDriver := GetEnv("DB_DRIVER", "mysql")
	DBUser = GetEnv("DB_USER", "root")
	DBPass = GetEnv("DB_PASS", "password")
	DBName = GetEnv("DB_NAME", "flow_management")

	ColNetworkFlow = GetEnv("COL_NETWORK_FLOW", "network_flow")
	ColDiscoveredPolicy = GetEnv("COL_DISCOVERED_POLICY", "discovered_policy")

	db, err := sql.Open(DBDriver, DBUser+":"+DBPass+"@tcp(127.0.0.1:3306)/"+DBName)
	for err != nil {
		fmt.Println("connection error :", err.Error())
		time.Sleep(time.Second * 1)
		db, err = sql.Open(DBDriver, DBUser+":"+DBPass+"@tcp(127.0.0.1:3306)/"+DBName)
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
func flowScanner(results *sql.Rows) ([]*types.KnoxTrafficFlow, error) {
	var trafficFlows []*types.KnoxTrafficFlow
	var err error

	for results.Next() {
		knoxFlow := &types.KnoxTrafficFlow{}

		trafficFlow := &pb.TrafficFlow{}
		src := &pb.Endpoint{}
		dest := &pb.Endpoint{}
		ethernet := &pb.Ethernet{}
		ip := &pb.IP{}
		l4 := &pb.Layer4{}
		l7 := &pb.Layer7{}
		srcService := &pb.Service{}
		destService := &pb.Service{}

		// basic info
		var verdict, flowType, trafficDirection int64
		var srcByte, destByte, ethByte, ipByte, l4Byte, l7Byte, srcServiceByte, destServiceByte, srcLabelsByte, destLabelsByte []byte

		// additional info
		var policyMatchType, dropReason int64
		eventType := &types.EventType{}
		var eventTypeByte []byte

		err = results.Scan(
			&trafficFlow.Id,
			&trafficFlow.Time,
			&verdict,
			&policyMatchType,
			&dropReason,
			&eventTypeByte,
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
			trafficFlow.Source.Labels = srcLabelStr
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
			trafficFlow.Destination.Labels = destLabelStr
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

		knoxFlow.TrafficFlow = trafficFlow
		knoxFlow.PolicyMatchType = policyMatchType
		knoxFlow.DropReason = dropReason

		if eventTypeByte != nil {
			err = json.Unmarshal([]byte(eventTypeByte), &eventType)
			if err != nil {
				log.Error().Msg("Error while unmarshing Event Type :" + err.Error())
				return nil, err
			}
			knoxFlow.EventType = eventType
		}

		trafficFlows = append(trafficFlows, knoxFlow)
	}

	return trafficFlows, nil
}

// QueryBase function
var QueryBase string = "select id,time,verdict,policy_match_type,drop_reason,event_type,source,destination,ethernet,ip,type,l4,l7,reply,source->>'$.labels',destination->>'$.labels',src_cluster_name,src_pod_name,dest_cluster_name,dest_pod_name,node_name,source_service,destination_service,traffic_direction,summary from "

// GetTrafficFlowByTime function
func GetTrafficFlowByTime(st, et int64) ([]*types.KnoxTrafficFlow, error) {
	db := ConnectMySQL()
	defer db.Close()

	QueryBase = QueryBase + ColNetworkFlow

	rows, err := db.Query(QueryBase+" where time >= ? and time < ? ", st, et)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScanner(rows)
}

// GetTrafficFlow function
func GetTrafficFlow() ([]*types.KnoxTrafficFlow, error) {
	db := ConnectMySQL()
	defer db.Close()

	rows, err := db.Query(QueryBase)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScanner(rows)
}

// GetExistingPoliciesFromMySQL function
func GetExistingPoliciesFromMySQL(db *sql.DB) ([]string, []types.Spec) {
	existNames := []string{}
	existSpecs := []types.Spec{}

	results, _ := db.Query("SELECT metadata, spec from " + ColDiscoveredPolicy + "")
	for results.Next() {
		existMetadataSlice := []byte{}
		existMetadata := map[string]string{}

		existSpecSlice := []byte{}
		existSpec := types.Spec{}

		results.Scan(
			&existMetadataSlice,
			&existSpecSlice,
		)

		json.Unmarshal(existMetadataSlice, &existMetadata)
		existNames = append(existNames, existMetadata["name"])

		json.Unmarshal(existSpecSlice, &existSpec)
		existSpecs = append(existSpecs, existSpec)
	}

	return existNames, existSpecs
}

// IsExistedPolicySpec function
func IsExistedPolicySpec(existingSpecs []types.Spec, inSpec types.Spec) bool {
	for _, spec := range existingSpecs {
		if cmp.Equal(&spec, &inSpec) {
			return true
		}
	}

	return false
}

// InsertDiscoveredPolicyMySQL function
func InsertDiscoveredPolicyMySQL(db *sql.DB, policy types.KnoxNetworkPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + ColDiscoveredPolicy + "(apiVersion,kind,metadata,spec,generated_time) values(?,?,?,?,?)")
	if err != nil {
		return err
	}

	metadata, err := json.Marshal(policy.Metadata)
	if err != nil {
		return err
	}

	specPointer := &policy.Spec
	spec, err := json.Marshal(specPointer)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(policy.APIVersion, policy.Kind, metadata, spec, policy.GeneratedTime)
	if err != nil {
		return err
	}

	return nil
}

// DoubleCheckPolicyName function
func DoubleCheckPolicyName(names []string, policy types.KnoxNetworkPolicy) types.KnoxNetworkPolicy {
	name := policy.Metadata["name"]

	if ContainsElement(names, name) { // name conflict
		egressPrefix := "autogen-egress"
		ingressPrefix := "autogen-ingress"

		if strings.HasPrefix(name, egressPrefix) {
			newName := egressPrefix + RandSeq(10)
			for ContainsElement(names, newName) {
				newName = egressPrefix + RandSeq(10)
			}

			policy.Metadata["name"] = newName
		} else {
			newName := ingressPrefix + RandSeq(10)
			for ContainsElement(names, newName) {
				newName = ingressPrefix + RandSeq(10)
			}

			policy.Metadata["name"] = newName
		}
	}

	return policy
}

// InsertDiscoveredPoliciesToMySQL function
func InsertDiscoveredPoliciesToMySQL(cfg types.Config, policies []types.KnoxNetworkPolicy) {
	db := ConnectMySQL()
	defer db.Close()

	existingNames, existingSpecs := GetExistingPoliciesFromMySQL(db)

	for _, policy := range policies {
		if IsExistedPolicySpec(existingSpecs, policy.Spec) {
			// fmt.Println("already exist policy, ", policy)
			continue
		} else {
			policy = DoubleCheckPolicyName(existingNames, policy)

			if err := InsertDiscoveredPolicyMySQL(db, policy); err != nil {
				fmt.Println(err)
			}
		}
	}
}
