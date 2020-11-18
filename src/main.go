package main

import (
	"fmt"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/core"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	"github.com/accuknox/knoxAutoPolicy/src/plugin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	cron "github.com/robfig/cron/v3"
)

// network flow between [ startTime <= time < endTime ]
var startTime int64 = 0
var endTime int64 = 0

var cidrBits int = 24

func init() {
	// init time filter
	endTime = time.Now().Unix()
	startTime = 0
}

func updateTimeInterval(lastDoc map[string]interface{}) {
	// time filter update for next interval
	ts := lastDoc["timestamp"].(primitive.DateTime)
	startTime = ts.Time().Unix() + 1
	endTime = time.Now().Unix()
}

// Generate function
func Generate() {
	// get network traffic from  knox aggregation Databse
	docs, err := libs.GetTrafficFlowFromMongo(startTime, endTime)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(docs) < 1 {
		fmt.Println("Traffic flow is not exist: ",
			time.Unix(startTime, 0).Format(libs.TimeFormSimple), " ~ ",
			time.Unix(endTime, 0).Format(libs.TimeFormSimple))

		startTime = endTime
		endTime = time.Now().Unix()
		return
	}
	fmt.Println("the total number of traffic flow from db: ", len(docs))

	updateTimeInterval(docs[len(docs)-1])

	// get all the namespaces from k8s
	namespaces := libs.GetK8sNamespaces()
	skipNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	for _, namespace := range namespaces {
		if libs.ContainsElement(skipNamespaces, namespace) {
			continue
		}

		fmt.Println("policy discovery started for namespace: ", namespace)

		// convert network traffic -> network log, and filter traffic
		networkLogs := plugin.ConvertCiliumFlowsToKnoxLogs(namespace, docs)

		// get k8s services
		services := libs.GetServices(namespace)

		// get k8s endpoints
		endpoints := libs.GetEndpoints(namespace)

		// get pod information
		pods := libs.GetConGroups(namespace)

		// generate network policies
		policies := core.GenerateNetworkPolicies(namespace, cidrBits, networkLogs, services, endpoints, pods)

		if len(policies) > 0 {
			// write discovered policies to files
			libs.WriteCiliumPolicyToFile(namespace, policies)

			// insert discovered policies to db
			libs.InsertDiscoveredPoliciesToMongoDB(policies)
		}

		fmt.Println("policy discovery done for namespace: ", namespace, " ", len(policies))
	}
}

// CronJobDaemon function
func CronJobDaemon() {
	// init cron job
	c := cron.New()
	c.AddFunc("@every 0h0m30s", Generate) // every time interval for test
	c.Start()

	sig := libs.GetOSSigChannel()
	<-sig
	println("Got a signal to terminate the auto policy discovery")

	c.Stop() // Stop the scheduler (does not stop any jobs already running).
}

func main() {
	Generate()
}
