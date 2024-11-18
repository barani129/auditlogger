package util

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/barani129/auditlogger/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type RemResponse struct {
	ID                  int    `json:"id"`
	ServiceType         string `json:"ServiceType"`
	Summary             string `json:"Summary"`
	Acknowledged        int    `json:"Acknowledged"`
	Type                int    `json:"Type"`
	Location            string `json:"Location"`
	Node                string `json:"Node"`
	Note                string `json:"Note"`
	Severity            int    `json:"Severity"`
	Agent               string `json:"Agent"`
	AlertGroup          string `json:"AlertGroup"`
	NodeAlias           string `json:"NodeAlias"`
	Manager             string `json:"Manager"`
	EquipRole           string `json:"EquipRole"`
	Tally               int    `json:"Tally"`
	X733SpecificProb    string `json:"X733SpecificProb"`
	Oseventid           string `json:"OSEVENTID"`
	EquipType           string `json:"EquipType"`
	LastOccurrence      string `json:"LastOccurrence"`
	AlertKey            string `json:"AlertKey"`
	SourceServerName    string `json:"SourceServerName"`
	SuppressEscl        int    `json:"SuppressEscl"`
	CorrelationID       string `json:"CorrelationID"`
	Serial              string `json:"Serial"`
	Identifier          string `json:"Identifier"`
	Class               int    `json:"Class"`
	StateChange         string `json:"StateChange"`
	FirstOccurrence     string `json:"FirstOccurrence"`
	Grade               int    `json:"Grade"`
	Flash               int    `json:"Flash"`
	EventID             string `json:"EventId"`
	ExpireTime          int    `json:"ExpireTime"`
	Customer            string `json:"Customer"`
	NmosDomainName      string `json:"NmosDomainName"`
	X733EventType       int    `json:"X733EventType"`
	X733ProbableCause   string `json:"X733ProbableCause"`
	ServerName          string `json:"ServerName"`
	ServerSerial        int    `json:"ServerSerial"`
	ExtendedAttr        string `json:"ExtendedAttr"`
	OldRow              int    `json:"OldRow"`
	ProbeSubSecondID    int    `json:"ProbeSubSecondId"`
	CollectionFirst     any    `json:"CollectionFirst"`
	AggregationFirst    any    `json:"AggregationFirst"`
	DisplayFirst        any    `json:"DisplayFirst"`
	LocalObjRelate      int    `json:"LocalObjRelate"`
	RemoteTertObj       string `json:"RemoteTertObj"`
	RemoteObjRelate     int    `json:"RemoteObjRelate"`
	CorrScore           int    `json:"CorrScore"`
	CauseType           int    `json:"CauseType"`
	AdvCorrCauseType    int    `json:"AdvCorrCauseType"`
	AdvCorrServerName   string `json:"AdvCorrServerName"`
	AdvCorrServerSerial int    `json:"AdvCorrServerSerial"`
	TTNumber            string `json:"TTNumber"`
	TicketState         string `json:"TicketState"`
	JournalSent         int    `json:"JournalSent"`
	ProbeSerial         string `json:"ProbeSerial"`
	AdditionalText      string `json:"AdditionalText"`
	AlarmID             string `json:"AlarmID"`
	OriginalSeverity    int    `json:"OriginalSeverity"`
	SentToJDBC          int    `json:"SentToJDBC"`
	Service             string `json:"Service"`
	URL                 string `json:"url"`
	AutomationState     any    `json:"automationState"`
	Cleared             any    `json:"cleared"`
	DedupeColumns       any    `json:"dedupeColumns"`
	SuppressAggregation bool   `json:"suppressAggregation"`
	QueueMessageKey     any    `json:"queueMessageKey"`
	Aggregationaction   any    `json:"aggregationaction"`
	Correlationobject   any    `json:"correlationobject"`
	CorrelationNode     string `json:"correlationNode"`
	BaseNode            string `json:"baseNode"`
	Enrichment          any    `json:"Enrichment"`
}

type OcpAPIConfig struct {
	APIServerArguments struct {
		AuditLogFormat         []string `json:"audit-log-format"`
		AuditLogMaxbackup      []string `json:"audit-log-maxbackup"`
		AuditLogMaxsize        []string `json:"audit-log-maxsize"`
		AuditLogPath           []string `json:"audit-log-path"`
		AuditPolicyFile        []string `json:"audit-policy-file"`
		EtcdHealthcheckTimeout []string `json:"etcd-healthcheck-timeout"`
		EtcdReadycheckTimeout  []string `json:"etcd-readycheck-timeout"`
		FeatureGates           []string `json:"feature-gates"`
		ShutdownDelayDuration  []string `json:"shutdown-delay-duration"`
		ShutdownSendRetryAfter []string `json:"shutdown-send-retry-after"`
	} `json:"apiServerArguments"`
	APIServers struct {
		PerGroupOptions []any `json:"perGroupOptions"`
	} `json:"apiServers"`
	APIVersion    string `json:"apiVersion"`
	Kind          string `json:"kind"`
	ProjectConfig struct {
		ProjectRequestMessage string `json:"projectRequestMessage"`
	} `json:"projectConfig"`
	RoutingConfig struct {
		Subdomain string `json:"subdomain"`
	} `json:"routingConfig"`
	ServingInfo struct {
		BindNetwork   string   `json:"bindNetwork"`
		CipherSuites  []string `json:"cipherSuites"`
		MinTLSVersion string   `json:"minTLSVersion"`
	} `json:"servingInfo"`
	StorageConfig struct {
		Urls []string `json:"urls"`
	} `json:"storageConfig"`
}

func GetSpecAndStatus(auditlogger client.Object) (*v1alpha1.AuditLoggerSpec, *v1alpha1.AuditLoggerStatus, error) {
	switch t := auditlogger.(type) {
	case *v1alpha1.AuditLogger:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an auditlogger type: %t", t)
	}
}

func GetReadyCondition(status *v1alpha1.AuditLoggerStatus) *v1alpha1.Condition {
	for _, c := range status.Conditions {
		if c.Type == v1alpha1.ConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *v1alpha1.AuditLoggerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == v1alpha1.ConditionTrue
	}
	return false
}

func SetReadyCondition(status *v1alpha1.AuditLoggerStatus, conditionStatus v1alpha1.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &v1alpha1.Condition{
			Type: v1alpha1.ConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == v1alpha1.ConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func randomString(length int) string {
	b := make([]byte, length+2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[2 : length+2]
}

func HandleCNString(cn string) string {
	var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)
	return nonAlphanumericRegex.ReplaceAllString(cn, "")
}

func GetAPIName(clientset kubernetes.Clientset) (domain string, err error) {
	var apiconfig OcpAPIConfig
	cm, err := clientset.CoreV1().ConfigMaps("openshift-apiserver").Get(context.Background(), "config", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	data := cm.Data["config.yaml"]
	err = json.Unmarshal([]byte(data), &apiconfig)
	if err != nil {
		return "", err
	}
	return apiconfig.RoutingConfig.Subdomain, nil
}

func SendEmailAlert(nodeName string, filename string, spec *v1alpha1.AuditLoggerSpec, alert string) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		message := fmt.Sprintf(`/usr/bin/printf '%s\n' "Subject: Alert from %s" "" "Alert: %s" | /usr/sbin/sendmail -f %s -S %s %s`, "%s", nodeName, alert, spec.Email, spec.RelayHost, spec.Email)
		cmd3 := exec.Command("/bin/bash", "-c", message)
		err := cmd3.Run()
		if err != nil {
			fmt.Printf("Failed to send the alert: %s", err)
		}
		writeFile(filename, "sent")
	} else {
		data, _ := ReadFile(filename)
		if data != "sent" {
			message := fmt.Sprintf(`/usr/bin/printf '%s\n' "Subject: MetallbScan alert from %s" "" "Alert: %s" | /usr/sbin/sendmail -f %s -S %s %s`, "%s", nodeName, alert, spec.Email, spec.RelayHost, spec.Email)
			cmd3 := exec.Command("/bin/bash", "-c", message)
			err := cmd3.Run()
			if err != nil {
				fmt.Printf("Failed to send the alert: %s", err)
			}
			os.Truncate(filename, 0)
			writeFile(filename, "sent")
		}
	}
}

func SendEmailRecoveredAlert(nodeName string, filename string, spec *v1alpha1.AuditLoggerSpec, commandToRun string) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		//
	} else {
		data, err := ReadFile(filename)
		if err != nil {
			fmt.Printf("Failed to send the alert: %s", err)
		}
		if data == "sent" {
			message := fmt.Sprintf(`/usr/bin/printf '%s\n' "Subject: MetallbScan alert from %s" ""  "Resolved: %s" | /usr/sbin/sendmail -f %s -S %s %s`, "%s", nodeName, commandToRun, spec.Email, spec.RelayHost, spec.Email)
			cmd3 := exec.Command("/bin/bash", "-c", message)
			err := cmd3.Run()
			if err != nil {
				fmt.Printf("Failed to send the alert: %s", err)
			}
		}
	}
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func writeFile(filename string, data string) error {
	err := os.WriteFile(filename, []byte(data), 0666)
	if err != nil {
		return err
	}
	return nil
}

func ReadFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func SetIncidentID(spec *v1alpha1.AuditLoggerSpec, username string, password string, fingerprint string) (string, error) {
	url := spec.ExternalURL
	nurl := strings.SplitAfter(url, "co.nz")
	getUrl := nurl[0] + "/rem/api/event/v1/query"
	var client *http.Client
	if strings.Contains(getUrl, "https://") {
		tr := http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: &tr,
		}
	}
	client = &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", getUrl, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("Content-Type", "application/json")
	q := req.URL.Query()
	q.Add("alertKey", fingerprint)
	q.Add("maxalarms", "1")
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	dat, err := io.ReadAll(resp.Body)
	sdata := string(dat)
	s1 := strings.TrimPrefix(sdata, "[")
	s2 := strings.TrimSuffix(s1, "]")
	if err != nil {
		return "", err
	}
	var x RemResponse
	err = json.Unmarshal([]byte(s2), &x)
	if err != nil {
		return "", err
	}
	return x.TTNumber, nil
}

func SubNotifyExternalSystem(data map[string]string, status string, url string, username string, password string, filename string, alertName string) error {
	var fingerprint string
	var err error
	if status == "resolved" {
		fingerprint, err = ReadFile(filename)
		if err != nil || fingerprint == "" {
			return fmt.Errorf("unable to notify the system for the %s status due to missing fingerprint in the file %s", status, filename)
		}
	} else {
		fingerprint, _ = ReadFile(filename)
		if fingerprint != "" {
			return nil
		}
		fingerprint = randomString(10)
	}
	data["fingerprint"] = fingerprint
	data["status"] = status
	data["startsAt"] = time.Now().String()
	data["alertName"] = alertName
	data["message"] = alertName
	m, b := data, new(bytes.Buffer)
	json.NewEncoder(b).Encode(m)
	var client *http.Client
	if strings.Contains(url, "https://") {
		tr := http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: &tr,
		}
	}
	client = &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("POST", url, b)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("User-Agent", "Openshift")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return err
	}
	writeFile(filename, fingerprint)
	return nil
}

func NotifyExternalSystem(data map[string]string, status string, url string, username string, password string, filename string, alertName string) error {
	fig, _ := ReadFile(filename)
	if fig != "" {
		log.Println("External system has already been notified for target %s . Exiting")
		return nil
	}
	fingerprint := randomString(10)
	data["fingerprint"] = fingerprint
	data["status"] = status
	data["startsAt"] = time.Now().String()
	data["alertName"] = alertName
	data["message"] = alertName
	m, b := data, new(bytes.Buffer)
	json.NewEncoder(b).Encode(m)
	var client *http.Client
	if strings.Contains(url, "https://") {
		tr := http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: &tr,
		}
	}
	client = &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("POST", url, b)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("User-Agent", "Openshift")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return err
	}
	writeFile(filename, fingerprint)
	return nil
}

func RetrieveMasterNodes(clientset kubernetes.Clientset) ([]string, []string, error) {
	nodeList, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	var nodes []string
	var faultynodes []string
	for _, val := range nodeList.Items {
		for _, cond := range val.Status.Conditions {
			if cond.Type == "Ready" {
				if cond.Status == "True" {
					nodes = append(nodes, val.Name)
				} else {
					faultynodes = append(faultynodes, val.Name)
				}
			}
		}
	}
	return nodes, faultynodes, nil
}

func CheckExistingPod(clientset kubernetes.Clientset, nodeName string, namespace string) (exists bool, running bool, err error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.Background(), fmt.Sprintf("auditlogger-%s", HandleCNString(nodeName)), metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		return false, false, err
	} else if err != nil {
		return false, false, err
	}
	if pod.Status.Phase == "Running" {
		return true, true, nil
	} else {
		return true, false, nil
	}
}

func DeletePod(clientset kubernetes.Clientset, nodeName string, namespace string) error {
	exists, _, err := CheckExistingPod(clientset, nodeName, namespace)
	if err == nil && !exists {
		return nil
	} else if err != nil {
		return err
	}
	err = clientset.CoreV1().Pods(namespace).Delete(context.Background(), fmt.Sprintf("auditlogger-%s", HandleCNString(nodeName)), metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	time.Sleep(30 * time.Second)
	return nil
}

func CreatePod(clientset kubernetes.Clientset, nodeName string, image string, serviceAccount string, namespace string) (string, error) {
	exists, running, err := CheckExistingPod(clientset, nodeName, namespace)
	if err == nil && exists && running {
		return fmt.Sprintf("auditlogger-%s", HandleCNString(nodeName)), nil
	} else if err == nil && exists && !running {
		// delete the pod here
		err := DeletePod(clientset, nodeName, namespace)
		if err != nil {
			return "", err
		}
	}
	// proceeding further with pod creation
	zero := int64(0)
	isTrue := true
	hostPathType := v1.HostPathDirectory
	podSpec := v1.PodSpec{
		NodeName:    nodeName,
		HostNetwork: true,
		HostPID:     true,
		HostIPC:     true,
		Volumes: []v1.Volume{
			{
				Name: "host",
				VolumeSource: v1.VolumeSource{
					HostPath: &v1.HostPathVolumeSource{
						Path: "/",
						Type: &hostPathType,
					},
				},
			},
		},
		PriorityClassName: "openshift-user-critical",
		RestartPolicy:     v1.RestartPolicyNever,
		Containers: []v1.Container{
			{
				Name:    "debug",
				Image:   image,
				Command: []string{"/bin/sleep"},
				Args:    []string{"1800"},
				SecurityContext: &v1.SecurityContext{
					Privileged: &isTrue,
					RunAsUser:  &zero,
				},
				VolumeMounts: []v1.VolumeMount{
					{
						Name:      "host",
						MountPath: "/host",
						ReadOnly:  true,
					},
				},
				Env: []v1.EnvVar{
					{
						// Set the Shell variable to auto-logout after 15m idle timeout
						Name:  "TMOUT",
						Value: "900",
					},
					{
						//  to collect more sos report requires this env var is set
						Name:  "HOST",
						Value: "/host",
					},
				},
			},
		},
	}
	desiredPod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("auditlogger-%s", HandleCNString(nodeName)),
			Namespace: namespace,
		},
		Spec: podSpec,
	}
	created, err := clientset.CoreV1().Pods(namespace).Create(context.Background(), &desiredPod, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	podRead, err := clientset.CoreV1().Pods(namespace).Get(context.Background(), created.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(podRead.Spec, desiredPod.Spec) {
		return "", err
	}
	// allow the pod to be ready
	time.Sleep(30 * time.Second)
	podRead, err = clientset.CoreV1().Pods(namespace).Get(context.Background(), created.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	// allow the pod to be ready
	var readinessCounter int64
	for {
		if podRead.Status.Phase != "Running" {
			//sleep again for a minute
			time.Sleep(15 * time.Second)
			readinessCounter++
		} else if podRead.Status.Phase == "Running" {
			return podRead.Name, nil
		}
		if readinessCounter >= 4 {
			return "", fmt.Errorf("exhausted wait time for pod readiness")
		}
	}
}

func ListFiles(outFile *os.File) ([]string, error) {
	content, err := os.ReadFile(outFile.Name())
	if err != nil {
		return nil, err
	}
	var files []string
	contents := strings.Split(string(content), "\n")
	if contents == nil {
		return nil, fmt.Errorf("contents is empty")
	}
	for _, con := range contents {
		if con != "" && con != " " {
			files = append(files, con)
		}
	}
	return files, nil
}
