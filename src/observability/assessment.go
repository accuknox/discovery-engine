package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
	"reflect"
)

func GetData(namespace string, deploymentName string) ([]*Resp, error) {
	var res []*Resp
	client := cluster.ConnectK8sClient()
	deployments := client.AppsV1().Deployments(namespace)
	deployment, err := deployments.Get(context.TODO(), deploymentName, v1.GetOptions{})
	deploymentMatchLabels := deployment.Spec.Selector.MatchLabels

	pods, err := client.CoreV1().Pods(namespace).List(context.TODO(), v1.ListOptions{
		LabelSelector: libs.LabelMapToString(deploymentMatchLabels),
	})

	fmt.Printf("There are %d Pods in the mentioned deployment\n", len(pods.Items))

	if err != nil {
		return nil, err
	}

	PodList := Checkmount(pods)
	// We get Pods along with all their volume mounts
	for _, vol := range PodList {
		podNameResp, err := GetPodNames(&opb.Request{
			PodName: vol.Podname,
		})
		if err != nil {
			fmt.Print(err)
			return nil, err
		}
		for _, podname := range podNameResp.PodName {
			if podname == "" {
				continue
			}
			fmt.Println(podname)
			sumResp, _ := GetSummaryData(&opb.Request{
				PodName:   podname,
				Type:      DefaultReqType,
				Aggregate: false,
			})

			for _, f := range sumResp.FileData {
				if slices.Contains(vol.Mounts, f.Destination) {
					re := &Resp{
						PodName:       sumResp.PodName,
						ClusterName:   sumResp.ClusterName,
						Namespace:     sumResp.Namespace,
						Label:         sumResp.Label,
						ContainerName: sumResp.ContainerName,
						Source:        f.Source,
						UpdatedTime:   f.UpdatedTime,
						Status:        f.Status,
					}
					res = append(res, re)
				}
			}

		}
	}
	fmt.Print("test")
	fmt.Print("\n", res)
	return res, nil

}

type Volmount struct {
	Mounts  []string
	Podname string
}

var po []Volmount

type vol struct {
	Total []Volmount
}

func (vol *vol) addmount(item Volmount) []Volmount {
	vol.Total = append(vol.Total, item)
	return vol.Total
}

func Checkmount(Pods *corev1.PodList) []Volmount {
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

func Scan(o Options) error {
	clientset := cluster.ConnectK8sClient()

	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("There are %d Pods in the cluster\n", len(pods.Items))

	Checkmount(pods)
	res, err := GetFileSummary(o)
	b, err := json.MarshalIndent(res, "", "    ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(b))
	return nil

}

func MountType(volSource corev1.VolumeSource) (error, reflect.Type) {
	v := reflect.ValueOf(volSource)
	var reqVolume reflect.Value
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.IsNil() {
			reqVolume = field
			break
		}
	}
	if reqVolume.CanConvert(reflect.TypeOf(&corev1.ProjectedVolumeSource{})) {
		fmt.Println("HER")
		projectedVol := reqVolume.Interface().(*corev1.ProjectedVolumeSource)
		fmt.Println(projectedVol)
	}
	fmt.Println(reqVolume)
	return nil, reqVolume.Type()
}

// TODO: Container metadata, volume type, VolumeSource, other table data

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

var FileHeader = []string{"Accessed By", "Mount Path", "Pod Name", "Last Accessed", "Status"}
var port int64 = 9089
var matchLabels = map[string]string{"app": "discovery-engine"}
var DefaultReqType = "process,file,network"

type Resp struct {
	PodName       string
	ClusterName   string
	Namespace     string
	Label         string
	ContainerName string
	Source        string
	MountPath     string
	UpdatedTime   string
	Status        string
}

func GetFileSummary(o Options) ([]*Resp, error) {
	// var flag
	var res []*Resp
	var s string

	data := &opb.Request{
		Label:         o.Labels,
		NameSpace:     o.Namespace,
		PodName:       o.PodName,
		ClusterName:   o.ClusterName,
		ContainerName: o.ContainerName,
		Aggregate:     o.Aggregation,
	}

	// create a client

	podNameResp, err := GetPodNames(data)
	if err != nil {
		return nil, err
	}
	//FileData := [][]string{}
	for _, podname := range podNameResp.PodName {
		if podname == "" {
			continue
		}
		sumResp, _ := GetSummaryData(&opb.Request{
			PodName:   podname,
			Type:      DefaultReqType,
			Aggregate: false,
		})

		for _, f := range sumResp.FileData {

			re := &Resp{
				PodName:       podname,
				ClusterName:   sumResp.ClusterName,
				Namespace:     sumResp.Namespace,
				Label:         sumResp.Label,
				ContainerName: sumResp.ContainerName,
				Source:        f.Source,
				MountPath:     s,
				UpdatedTime:   f.UpdatedTime,
				Status:        f.Status,
			}

			res = append(res, re)
		}

	}

	return res, err
}
