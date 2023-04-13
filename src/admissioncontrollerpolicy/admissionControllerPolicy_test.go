package admissioncontrollerpolicy

import (
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func Test_getSATokenMountPath(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-using-svc-account-df69d4f79-gz26h",
			Namespace: "default",
			Labels: map[string]string{
				"app": "nginx-using-svc-account",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx",
					VolumeMounts: []corev1.VolumeMount{
						{
							MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
							Name:      "kube-api-access-ccp5s",
							ReadOnly:  true,
						},
					},
				},
				{
					Name:  "redis",
					Image: "redis",
					VolumeMounts: []corev1.VolumeMount{
						{
							MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
							Name:      "kube-api-access-ccp5s",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "kube-api-access-ccp5s",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
										Path: "token",
									},
								},
								{
									ConfigMap: &corev1.ConfigMapProjection{
										Items: []corev1.KeyToPath{
											{
												Key:  "ca.crt",
												Path: "ca.crt",
											},
										},
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "kube-root-ca.crt",
										},
									},
								},
								{
									DownwardAPI: &corev1.DownwardAPIProjection{
										Items: []corev1.DownwardAPIVolumeFile{
											{
												FieldRef: &corev1.ObjectFieldSelector{
													APIVersion: "v1",
													FieldPath:  "metadata.namespace",
												},
												Path: "namespace",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	expectedContainersSATokenMountPath := []containerMountPathServiceAccountToken{
		{
			podName:          "nginx-using-svc-account-df69d4f79-gz26h",
			podNamespace:     "default",
			containerName:    "nginx",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			podName:          "nginx-using-svc-account-df69d4f79-gz26h",
			podNamespace:     "default",
			containerName:    "redis",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
	containersSATokenMountPath, err := getSATokenMountPath(pod)
	assert.Nil(t, err)
	assert.Equal(t, expectedContainersSATokenMountPath, containersSATokenMountPath)

	pod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-using-svc-account-df69d4f79-gz26h",
			Namespace: "default",
			Labels: map[string]string{
				"app": "nginx-using-svc-account",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx",
				},
				{
					Name:  "redis",
					Image: "redis",
				},
			},
		},
	}
	_, err = getSATokenMountPath(pod)
	assert.NotNil(t, err)
	assert.Equal(t, "service account token not mounted for nginx-using-svc-account-df69d4f79-gz26h in namespace default", err.Error())
}

func Test_matchesSATokenPath(t *testing.T) {
	saTokenPathh := "/var/run/secrets/kubernetes.io/serviceaccount/token"

	sumRespPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	result := matchesSATokenPath(saTokenPathh, sumRespPath)
	assert.Equal(t, true, result)

	sumRespPath = "/var/run/secrets/kubernetes.io/serviceaccount/..2023_03_28_12_23_09.412453730/token"
	result = matchesSATokenPath(saTokenPathh, sumRespPath)
	assert.Equal(t, true, result)

	sumRespPath = "/run/secrets/kubernetes.io/serviceaccount/..2023_03_28_12_23_09.412453730/token"
	result = matchesSATokenPath(saTokenPathh, sumRespPath)
	assert.Equal(t, true, result)

	sumRespPath = "run/secrets/kubernetes.io/serviceaccount/..2023_03_28_12_23_09.412453730/token"
	result = matchesSATokenPath(saTokenPathh, sumRespPath)
	assert.Equal(t, false, result)

	sumRespPath = "/secrets/kubernetes.io/serviceaccount/..2023_03_28_12_23_09.412453730/token"
	result = matchesSATokenPath(saTokenPathh, sumRespPath)
	assert.Equal(t, false, result)

	sumRespPath = "var/run/secrets/kubernetes.io/serviceaccount/token"
	result = matchesSATokenPath(saTokenPathh, sumRespPath)
	assert.Equal(t, false, result)

	sumRespPath = "/kubernetes.io/serviceaccount/token"
	result = matchesSATokenPath(saTokenPathh, sumRespPath)
	assert.Equal(t, false, result)
}

func Test_serviceAccountTokenUsed(t *testing.T) {
	// Case - 1
	// Both containers have summary with service account token being used
	containersSATokenMountPath := []containerMountPathServiceAccountToken{
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-1",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-2",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
	sumResponses := []*opb.Response{
		{
			PodName:       "pod-1",
			ClusterName:   "default",
			Namespace:     "default",
			Label:         "app=nginx",
			ContainerName: "container-1",
			FileData: []*opb.SysProcFileSummaryData{
				// only Destination is used in the logic
				{
					Destination: "/foo/bar",
				},
				{
					Destination: "/run/secrets/kubernetes.io/serviceaccount/..2023_03_28_12_23_09.412453730/token",
				},
			},
		},
		{
			PodName:       "pod-1",
			ClusterName:   "default",
			Namespace:     "default",
			Label:         "app=nginx",
			ContainerName: "container-2",
			FileData: []*opb.SysProcFileSummaryData{
				// only Destination is used in the logic
				{
					Destination: "/foo/bar/path",
				},
				{
					Destination: "/run/secrets/kubernetes.io/serviceaccount/..2023_03_28_12_23_09.412453730/token",
				},
			},
		},
	}

	result := serviceAccountTokenUsed(containersSATokenMountPath, sumResponses)
	assert.Equal(t, true, result)

	// Case - 2
	// One container has summary with service account token being used
	containersSATokenMountPath = []containerMountPathServiceAccountToken{
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-1",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-2",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
	sumResponses = []*opb.Response{
		{
			PodName:       "pod-1",
			ClusterName:   "default",
			Namespace:     "default",
			Label:         "app=nginx",
			ContainerName: "container-1",
			FileData: []*opb.SysProcFileSummaryData{
				// only Destination is used in the logic
				{
					Destination: "/foo/bar",
				},
				{
					Destination: "/var/run/secrets/kubernetes.io/serviceaccount/token",
				},
			},
		},
	}

	result = serviceAccountTokenUsed(containersSATokenMountPath, sumResponses)
	assert.Equal(t, true, result)

	// Case - 3
	// No container has summary with service account token being used
	containersSATokenMountPath = []containerMountPathServiceAccountToken{
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-1",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-2",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
	sumResponses = []*opb.Response{
		{
			PodName:       "pod-1",
			ClusterName:   "default",
			Namespace:     "default",
			Label:         "app=nginx",
			ContainerName: "container-1",
			FileData: []*opb.SysProcFileSummaryData{
				// only Destination is used in the logic
				{
					Destination: "/foo/bar",
				},
				{
					Destination: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
				},
			},
		},
	}

	result = serviceAccountTokenUsed(containersSATokenMountPath, sumResponses)
	assert.Equal(t, false, result)

	// Case - 4
	// Both containers have summary but only one container has service account token mount path being used
	containersSATokenMountPath = []containerMountPathServiceAccountToken{
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-1",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			podName:          "pod-1",
			podNamespace:     "default",
			containerName:    "container-2",
			saTokenMountPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
	sumResponses = []*opb.Response{
		{
			PodName:       "pod-1",
			ClusterName:   "default",
			Namespace:     "default",
			Label:         "app=nginx",
			ContainerName: "container-1",
			FileData: []*opb.SysProcFileSummaryData{
				// only Destination is used in the logic
				{
					Destination: "/foo/bar",
				},
				{
					Destination: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
				},
			},
		},
		{
			PodName:       "pod-1",
			ClusterName:   "default",
			Namespace:     "default",
			Label:         "app=nginx",
			ContainerName: "container-2",
			FileData: []*opb.SysProcFileSummaryData{
				// only Destination is used in the logic
				{
					Destination: "/foo/bar/path",
				},
				{
					Destination: "/run/secrets/kubernetes.io/serviceaccount/..2023_03_28_12_23_09.412453730/token",
				},
			},
		},
	}

	result = serviceAccountTokenUsed(containersSATokenMountPath, sumResponses)
	assert.Equal(t, true, result)
}
