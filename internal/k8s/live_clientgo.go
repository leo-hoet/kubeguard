package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const revisionAnnotation = "deployment.kubernetes.io/revision"

// LiveClientGoCluster implements ClusterBackend against a real Kubernetes API server
// using official k8s.io/client-go (via KUBECONFIG or in-cluster service account).
type LiveClientGoCluster struct {
	clientset kubernetes.Interface
}

// NewLiveClientGoCluster initializes a Kubernetes clientset from kubeconfigPath or InClusterConfig.
func NewLiveClientGoCluster(kubeconfigPath string) (*LiveClientGoCluster, error) {
	var (
		restCfg *rest.Config
		err     error
	)
	if strings.TrimSpace(kubeconfigPath) != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		restCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("building kubernetes client config: %w", err)
	}
	restCfg.Timeout = 15 * time.Second

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes clientset: %w", err)
	}
	return &LiveClientGoCluster{clientset: cs}, nil
}

// ListNamespaces lists active namespaces in the live cluster.
func (c *LiveClientGoCluster) ListNamespaces(ctx context.Context) ([]string, error) {
	nsList, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	out := make([]string, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		out = append(out, ns.Name)
	}
	slices.Sort(out)
	return out, nil
}

// ListUnhealthyWorkloads inspects deployments with unavailable pods or container restarts.
func (c *LiveClientGoCluster) ListUnhealthyWorkloads(ctx context.Context, namespace string) ([]WorkloadHealth, error) {
	if namespace != "" {
		if err := ValidateIdentifier(namespace); err != nil {
			return nil, err
		}
	}
	deps, err := c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing deployments: %w", err)
	}

	var out []WorkloadHealth
	for _, d := range deps.Items {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if d.Status.ReadyReplicas >= desired {
			continue
		}
		rev, _ := strconv.ParseInt(d.Annotations[revisionAnnotation], 10, 64)
		var img, memLimit string
		if len(d.Spec.Template.Spec.Containers) > 0 {
			ctr := d.Spec.Template.Spec.Containers[0]
			img = ctr.Image
			if lim, ok := ctr.Resources.Limits[corev1.ResourceMemory]; ok {
				memLimit = lim.String()
			}
		}
		out = append(out, WorkloadHealth{
			Namespace:       d.Namespace,
			Deployment:      d.Name,
			DesiredReplicas: desired,
			ReadyReplicas:   d.Status.ReadyReplicas,
			CurrentRevision: rev,
			Image:           img,
			PodStatus:       "Degraded",
			MemoryLimit:     memLimit,
		})
	}
	return out, nil
}

// FetchPodLogs reads recent container logs and warning events for the deployment's pods.
func (c *LiveClientGoCluster) FetchPodLogs(ctx context.Context, namespace, deployment string, tailLines int32) (*PodLogSnapshot, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}

	dep, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeploymentNotFound, err)
	}
	selector := metav1.FormatLabelSelector(dep.Spec.Selector)
	pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil || len(pods.Items) == 0 {
		return nil, fmt.Errorf("listing pods for %s/%s: %w", namespace, deployment, err)
	}

	pod := pods.Items[0]
	var termReason string
	var exitCode, restarts int32
	if len(pod.Status.ContainerStatuses) > 0 {
		cs := pod.Status.ContainerStatuses[0]
		restarts = cs.RestartCount
		if cs.LastTerminationState.Terminated != nil {
			termReason = cs.LastTerminationState.Terminated.Reason
			exitCode = cs.LastTerminationState.Terminated.ExitCode
		} else if cs.State.Waiting != nil {
			termReason = cs.State.Waiting.Reason
		}
	}

	if tailLines <= 0 || tailLines > 200 {
		tailLines = 50
	}
	tail64 := int64(tailLines)
	req := c.clientset.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		TailLines: &tail64,
		Previous:  restarts > 0,
	})
	stream, logErr := req.Stream(ctx)
	var lines []string
	if logErr == nil {
		defer func() { _ = stream.Close() }()
		var buf bytes.Buffer
		_, _ = io.CopyN(&buf, stream, 64*1024)
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line != "" {
				lines = append(lines, line)
			}
		}
	}

	containerName := ""
	if len(pod.Spec.Containers) > 0 {
		containerName = pod.Spec.Containers[0].Name
	}

	return &PodLogSnapshot{
		Namespace:         namespace,
		Deployment:        deployment,
		PodName:           pod.Name,
		ContainerName:     containerName,
		TerminationReason: termReason,
		ExitCode:          exitCode,
		RestartCount:      restarts,
		ScrubbedLogLines:  lines,
		CapturedAt:        time.Now().UTC(),
	}, nil
}

// InspectRolloutHistory inspects ReplicaSets owned by deployment sorted by revision.
func (c *LiveClientGoCluster) InspectRolloutHistory(ctx context.Context, namespace, deployment string) ([]RevisionEntry, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}

	dep, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeploymentNotFound, err)
	}
	rsList, err := c.clientset.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: metav1.FormatLabelSelector(dep.Spec.Selector),
	})
	if err != nil {
		return nil, fmt.Errorf("listing replicasets: %w", err)
	}

	var entries []RevisionEntry
	for _, rs := range rsList.Items {
		if !isOwnedBy(&rs, dep) {
			continue
		}
		rev, _ := strconv.ParseInt(rs.Annotations[revisionAnnotation], 10, 64)
		var img, mem string
		if len(rs.Spec.Template.Spec.Containers) > 0 {
			ctr := rs.Spec.Template.Spec.Containers[0]
			img = ctr.Image
			if lim, ok := ctr.Resources.Limits[corev1.ResourceMemory]; ok {
				mem = lim.String()
			}
		}
		entries = append(entries, RevisionEntry{
			Revision:      rev,
			Image:         img,
			MemoryLimit:   mem,
			ChangeSummary: fmt.Sprintf("ReplicaSet %s", rs.Name),
			Healthy:       rs.Status.ReadyReplicas >= rs.Status.Replicas,
			DeployedAt:    rs.CreationTimestamp.Time,
		})
	}
	slices.SortFunc(entries, func(a, b RevisionEntry) int {
		if a.Revision < b.Revision {
			return -1
		}
		if a.Revision > b.Revision {
			return 1
		}
		return 0
	})
	return entries, nil
}

// RollbackDeployment restores deployment's PodTemplateSpec from the ReplicaSet matching targetRevision.
func (c *LiveClientGoCluster) RollbackDeployment(ctx context.Context, namespace, deployment string, targetRevision int64, _ string) (*RemediationOutcome, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}
	if IsProtectedNamespace(namespace) {
		return nil, fmt.Errorf("%w: %q", ErrProtectedNamespace, namespace)
	}

	dep, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeploymentNotFound, err)
	}
	rsList, err := c.clientset.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: metav1.FormatLabelSelector(dep.Spec.Selector),
	})
	if err != nil {
		return nil, fmt.Errorf("listing replicasets: %w", err)
	}

	var targetRS *appsv1.ReplicaSet
	for i := range rsList.Items {
		rs := &rsList.Items[i]
		if !isOwnedBy(rs, dep) {
			continue
		}
		if rev, _ := strconv.ParseInt(rs.Annotations[revisionAnnotation], 10, 64); rev == targetRevision {
			targetRS = rs
			break
		}
	}
	if targetRS == nil {
		return nil, fmt.Errorf("%w: revision %d", ErrRevisionNotFound, targetRevision)
	}

	prevRev, _ := strconv.ParseInt(dep.Annotations[revisionAnnotation], 10, 64)
	dep.Spec.Template = targetRS.Spec.Template
	updated, err := c.clientset.AppsV1().Deployments(namespace).Update(ctx, dep, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("updating deployment template: %w", err)
	}

	replicas := int32(1)
	if updated.Spec.Replicas != nil {
		replicas = *updated.Spec.Replicas
	}
	appliedImg := ""
	if len(updated.Spec.Template.Spec.Containers) > 0 {
		appliedImg = updated.Spec.Template.Spec.Containers[0].Image
	}

	return &RemediationOutcome{
		Action:           "deployment_rollback",
		Namespace:        namespace,
		Deployment:       deployment,
		PreviousRevision: prevRev,
		AppliedRevision:  targetRevision,
		PreviousReplicas: replicas,
		AppliedReplicas:  replicas,
		AppliedImage:     appliedImg,
		CurrentPodStatus: "RollingUpdateInProgress",
		AppliedAt:        time.Now().UTC(),
	}, nil
}

// ScaleDeployment updates the Scale subresource of deployment within [1..50].
func (c *LiveClientGoCluster) ScaleDeployment(ctx context.Context, namespace, deployment string, replicas int32, _ string) (*RemediationOutcome, error) {
	if err := ValidateIdentifier(namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier(deployment); err != nil {
		return nil, err
	}
	if IsProtectedNamespace(namespace) {
		return nil, fmt.Errorf("%w: %q", ErrProtectedNamespace, namespace)
	}
	if replicas < 1 || replicas > 50 {
		return nil, fmt.Errorf("replica count %d violates cluster safety bounds [1..50]", replicas)
	}

	scaleObj, err := c.clientset.AppsV1().Deployments(namespace).GetScale(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeploymentNotFound, err)
	}
	prev := scaleObj.Spec.Replicas
	scaleObj.Spec.Replicas = replicas
	if _, err := c.clientset.AppsV1().Deployments(namespace).UpdateScale(ctx, deployment, scaleObj, metav1.UpdateOptions{}); err != nil {
		return nil, fmt.Errorf("updating deployment scale: %w", err)
	}

	return &RemediationOutcome{
		Action:           "scale_deployment",
		Namespace:        namespace,
		Deployment:       deployment,
		PreviousReplicas: prev,
		AppliedReplicas:  replicas,
		CurrentPodStatus: "Scaling",
		AppliedAt:        time.Now().UTC(),
	}, nil
}

func isOwnedBy(rs *appsv1.ReplicaSet, dep *appsv1.Deployment) bool {
	for _, ref := range rs.OwnerReferences {
		if ref.UID == dep.UID {
			return true
		}
	}
	return false
}
