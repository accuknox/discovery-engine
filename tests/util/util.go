package util

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	klog "github.com/kubearmor/kubearmor-client/log"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

var k8sClient *kubernetes.Clientset
var k8sConfig *rest.Config
var stopChan chan struct{}

func init() {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("error getting user home dir: %v\n", err)
		os.Exit(1)
	}
	kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
	fmt.Printf("Using kubeconfig: %s\n", kubeConfigPath)
	k8sConfig, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		println("config build error")
	}

	k8sClient, err = kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		println("config build error")
	}
}

// Kubectl execute
func Kubectl(cmdstr string) (string, error) {
	cmdf := strings.Fields(cmdstr)
	cmd := exec.Command("kubectl", cmdf...)
	sout, err := cmd.Output()
	return string(sout), err
}

// K8sApply execute
func K8sApply(files []string) error {
	for _, f := range files {
		_, err := Kubectl(fmt.Sprintf("apply -f %s", f))
		if err != nil {
			return err
		}
	}
	time.Sleep(1 * time.Second) // this sleep is needed because it takes time to apply the command
	return nil
}

// K8sGetPods Check if Pods exists and is/are Running
func K8sGetPods(podstr string, ns string, ants []string, timeout int) ([]string, error) {
	pods := []string{}
	log.Printf("K8sGetPods pod=%s ns=%s ants=%v timeout=%d", podstr, ns, ants, timeout)
	for t := 0; t <= timeout; t++ {
		podList, err := k8sClient.CoreV1().Pods(ns).List(context.TODO(), v1.ListOptions{})
		if err != nil {
			log.Errorf("k8s list pods failed. error=%s", err)
			return nil, err
		}
		pods = []string{}
		for _, p := range podList.Items {
			if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
				continue
			}
			if p.Status.Reason != "" {
				continue
			}
			if !annotationsMatch(p, ants) {
				continue
			}
			if strings.HasPrefix(p.ObjectMeta.Name, podstr) {
				pods = append(pods, p.ObjectMeta.Name)
			} else if match, _ := regexp.MatchString(podstr, p.ObjectMeta.Name); match {
				pods = append(pods, p.ObjectMeta.Name)
			}
		}
		if timeout == 0 || len(pods) > 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if len(pods) == 0 {
		return nil, errors.New("pod not found")
	}
	log.Printf("found K8sGetPods pods=%v", pods)
	return pods, nil
}

func annotationsMatch(pod corev1.Pod, ants []string) bool {
	if ants == nil || len(ants) <= 0 {
		return true
	}
	for _, ant := range ants {
		kv := strings.Split(ant, ":")
		k := strings.Trim(kv[0], " ")
		antFound := false
		if len(kv) > 1 {
			antFound = pod.Annotations[k] == strings.Trim(kv[1], " ")
		} else {
			antFound = pod.Annotations[k] != ""
		}
		if !antFound {
			return false
		}
	}
	return true
}

// PortForwardOpt port forwarding options
type PortForwardOpt struct {
	LocalPort   int
	RemotePort  int
	ServiceName string
	Namespace   string
}

// K8sPortForward enable port forwarding
func K8sPortForward(pf PortForwardOpt) (chan struct{}, error) {
	roundTripper, upgrader, err := spdy.RoundTripperFor(k8sConfig)
	if err != nil {
		log.Errorf("unable to spdy.RoundTripperFor error=%s", err.Error())
		return nil, err
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", pf.Namespace, pf.ServiceName)
	hostIP := strings.TrimLeft(k8sConfig.Host, "https:/")
	serverURL := url.URL{Scheme: "https", Path: path, Host: hostIP}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, &serverURL)

	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{}, 1)
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)

	forwarder, err := portforward.New(dialer, []string{fmt.Sprintf("%d:%d", pf.LocalPort, pf.RemotePort)},
		stopChan, readyChan, out, errOut)
	if err != nil {
		log.Errorf("unable to portforward. error=%s", err.Error())
		return nil, err
	}

	go func() {
		for range readyChan { // Kubernetes will close this channel when it has something to tell us.
		}
		if len(errOut.String()) != 0 {
			panic(errOut.String())
		} else if len(out.String()) != 0 {
			fmt.Println(out.String())
		}
	}()

	go func() {
		if err = forwarder.ForwardPorts(); err != nil { // Locks until stopChan is closed.
			log.Errorf("unable to ForwardPorts. error=%s", err.Error())
		}
	}()
	time.Sleep(100 * time.Millisecond)
	return stopChan, nil
}

// KubearmorPortForward enable port forwarding for kubearmor
func KubearmorPortForward() error {
	if stopChan != nil {
		log.Errorf("kubearmor port forward is already in progress")
		return errors.New("kubearmor port forward is already in progress")
	}
	ns := "kube-system"
	pods, err := K8sGetPods("^kubearmor-.....$", ns, nil, 0)
	if err != nil {
		log.Printf("could not get kubearmor pods assuming process mode")
		return nil
	}
	if len(pods) != 1 {
		log.Errorf("len(pods)=%d", len(pods))
		return errors.New("expecting one kubearmor pod only")
	}
	//	log.Printf("found kubearmor pod:[%s]", pods[0])
	c, err := K8sPortForward(PortForwardOpt{
		LocalPort:   32767,
		RemotePort:  32767,
		ServiceName: pods[0],
		Namespace:   ns})
	if err != nil {
		log.Errorf("could not do kubearmor portforward Error=%s", err.Error())
		return err
	}
	stopChan = c
	return nil
}

// DeleteAllKsp delete all the kubearmorpolicies from all namespaces
func DeleteAllKsp() error {
	namespaces, err := k8sClient.CoreV1().Namespaces().List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Errorf("error getting namespaces %v", err.Error())
		return err
	}

	for _, ns := range namespaces.Items {
		cmd := exec.Command("kubectl", "delete", "ksp", "--all", "-n", ns.Name)
		sout, err := cmd.Output()
		if err != nil {
			log.Errorf("error deleting ksp %v", err.Error())
			return err
		}
		log.Printf("%v\n", string(sout))
	}

	return nil
}

// KarmorLogStop stops the kubearmor-client observer
func KarmorLogStop() {
	klog.StopObserver()
}
