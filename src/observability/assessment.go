// Package scan to scan for risks
package observability

import (
	"context"
	"errors"
	"fmt"
	"github.com/accuknox/auto-policy-discovery/src/cluster"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"

	//"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"regexp"
)

type Volmount struct {
	Mounts    []string
	Podname   string
	MountType string
}

var po []Volmount

func Scan(request *opb.Request) (*opb.AssessmentResponse, error) {

	client := cluster.ConnectK8sClient()
	var v *opb.AssessmentResponse
	podList, err := client.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	fmt.Printf("There are %d Pods in the cluster\n", len(podList.Items))

	//data := &opb.Request{
	//	Label:         o.Labels,
	//	NameSpace:     o.Namespace,
	//	PodName:       o.PodName,
	//	ClusterName:   o.ClusterName,
	//	ContainerName: o.ContainerName,
	//	Aggregate:     o.Aggregation,
	//}
	// create a client
	var sumResponses []*opb.Response

	if err != nil {
		return nil, errors.New("could not connect to the server. Possible troubleshooting:\n- Check if discovery engine is running\n- kubectl get po -n accuknox-agents")
	}

	// create a client
	//defer conn.Close()
	//Sumclient := opb.NewObservabilityClient(conn)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//podNameResp, err := GetPodNames(request)
	//if err != nil {
	//	fmt.Println(err)
	//}
	podNameResp, err := GetPodNames(request)
	for _, podname := range podNameResp.PodName {

		if len(podList.Items) > 0 {
			sumResp, err := GetSummaryData(&opb.Request{
				PodName: podname,
			})
			if err != nil {
				print("ERRRRRRRRRRRRRRRRRROR")
				log.Warn().Msg(err.Error())
				return nil, err
			}
			//log.Info().Msg(sumResp.String())
			sumResponses = append(sumResponses, sumResp)

			//fmt.Print(ShouldSATokenBeAutoMounted(), "\n\n\n")
			v = VolumeUsed(sumResponses, podList)
			//b, _ := json.MarshalIndent(test, "", "    ")
			//fmt.Println(string(b))

		} else {
			log.Warn().Msg("No pods found for the given labels")
		}
	}

	return v, err
}
func Checkmount(Pods *v1.PodList) []Volmount {
	var pod Volmount
	for _, pods := range Pods.Items {
		var mount []string
		for _, p := range pods.Spec.Containers {
			for _, name := range p.VolumeMounts {
				mount = append(mount, name.MountPath)
				pod = Volmount{Podname: pods.Name, Mounts: mount}
			}

		}
		po = append(po, pod)
	}
	return po
}

type containerMountPathServiceAccountToken struct {
	podName          string
	podNamespace     string
	containerName    string
	saTokenMountPath string
}

func removeMatchingElements(slice []string, pattern string) []string {
	r := regexp.MustCompile(pattern)
	result := make([]string, 0)

	for _, s := range slice {
		if !r.MatchString(s) {
			result = append(result, s)
		}
	}

	return result
}

func VolumeUsed(sumResp []*opb.Response, pod *v1.PodList) *opb.AssessmentResponse {
	p := Checkmount(pod)
	//var a []containerMountPathServiceAccountToken
	//for _, pods := range pod.Items {
	//	a, _ = getSATokenMountPath(pods)
	//}
	var resp *opb.AssessmentResponse
	var fi []string
	//AssessmentFileData := [][]string{}
	//fileResp := []*opb.FileAssessmentResp{}
	for _, mounts := range p {
		for _, sum := range sumResp {
			for _, fileData := range sum.FileData {
				fi = append(fi, fileData.Destination)
			}
			for _, file := range sum.FileData {
				r, _ := regexp.Compile("\\/run\\/secrets\\/kubernetes.io\\/serviceaccount\\/[^\\/]+\\/token")
				//fmt.Println(matchesSATokenPath())
				if slices.Contains(mounts.Mounts, file.Destination) && mounts.Podname == sum.PodName {
					resp.PodName = sum.PodName
					resp.Namespace = sum.Namespace
					resp.Label = sum.Label
					resp.ContainerName = sum.ContainerName
					resp.ClusterName = sum.ClusterName

					//fileResp = append(fileResp, &opb.FileAssessmentResp{
					//	Source:      file.Source,
					//	MountPath:   file.Destination,
					//	UpdatedTime: file.UpdatedTime,
					//	Status:      file.Status,
					//	Severity:    "HIGH",
					//})

				} else if r.MatchString(file.Destination) {
					resp.PodName = sum.PodName
					resp.Namespace = sum.Namespace
					resp.Label = sum.Label
					resp.ContainerName = sum.ContainerName
					resp.ClusterName = sum.ClusterName

					//fileResp = append(fileResp, &opb.FileAssessmentResp{
					//	Source:      file.Source,
					//	MountPath:   file.Destination,
					//	UpdatedTime: file.UpdatedTime,
					//	Status:      file.Status,
					//	Severity:    "HIGH",
					//})
				}
			}
			//for _, m := range mounts.Mounts {
			//	if !slices.Contains(fi, m) && mounts.Podname == sum.PodName {
			//		fmt.Println(m)
			//		resp.PodName = sum.PodName
			//		resp.Namespace = sum.Namespace
			//		resp.Label = sum.Label
			//		resp.ContainerName = sum.ContainerName
			//		resp.ClusterName = sum.ClusterName
			//
			//		fileResp = append(fileResp, &opb.FileAssessmentResp{
			//			Source:      file.Source,
			//			MountPath:   file.Destination,
			//			UpdatedTime: file.UpdatedTime,
			//			Status:      file.Status,
			//			Severity:    "HIGH",
			//		})
			//
			//	}
			//}
		}
	}

	//resp.AssessmentFileData = fileResp

	//for i := 0; i < len(result); i++ {
	//	if (opb.AssessmentResponse{}) == result[i] {
	//		result = append(result[:i], result[i+1:]...)
	//		i--
	//	}
	//}
	//result = removeDuplicates(result)
	//fmt.Println(result)

	//for _, r := range result {
	//	fileStrSlice := []string{}
	//	fileStrSlice = append(fileStrSlice, r.Source)
	//	fileStrSlice = append(fileStrSlice, r.MountPath)
	//	fileStrSlice = append(fileStrSlice, r.PodName)
	//	fileStrSlice = append(fileStrSlice, r.UpdatedTime)
	//	fileStrSlice = append(fileStrSlice, r.Status)
	//	fileStrSlice = append(fileStrSlice, r.Severity)
	//	AssessmentFileData = append(AssessmentFileData, fileStrSlice)
	//}
	//WriteTable(FileHeader, AssessmentFileData)
	return resp
}

func myFunc(volSource v1.VolumeSource) (error, reflect.Type) {
	v := reflect.ValueOf(volSource)
	var reqVolume reflect.Value
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.IsNil() {
			reqVolume = field
			break
			//		}
		}
		if reqVolume.CanConvert(reflect.TypeOf(&v1.ProjectedVolumeSource{})) {
			fmt.Println("HER")
			projectedVol := reqVolume.Interface().(*v1.ProjectedVolumeSource)
			fmt.Println(projectedVol)
		}
		fmt.Println(reqVolume)
	}
	return nil, reqVolume.Type()
}

//
//// TODO: Container metadata, volume type, VolumeSource, other table data
//

type Options struct {
	GRPC          string
	Labels        string
	Namespace     string
	PodName       string
	ClusterName   string
	ContainerName string
	Type          string
	Output        string
	RevDNSLookup  bool
	Aggregation   bool
}

var FileHeader = []string{"Accessed By", "Mount Path", "Pod Name", "Last Accessed", "Status", "Severity"}
var port int64 = 9089
var matchLabels = map[string]string{"app": "discovery-engine"}
var DefaultReqType = "process,file,network"
