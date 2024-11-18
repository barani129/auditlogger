/*
Copyright 2024 baranitharan.chittharanjan@spark.co.nz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/remotecommand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	monitoringv1alpha1 "github.com/barani129/auditlogger/api/v1alpha1"
	"github.com/barani129/auditlogger/internal/auditlogger/util"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	corev1 "k8s.io/api/core/v1"
)

var (
	errGetNamespace     = errors.New("failed to get the target namespace in the cluster")
	errGetAuthSecret    = errors.New("failed to get Secret containing External alert system credentials")
	errGetAuthConfigMap = errors.New("failed to get ConfigMap containing the data to be sent to the external alert system")
)

// AuditLoggerReconciler reconciles a AuditLogger object
type AuditLoggerReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	RESTClient               rest.Interface
	RESTConfig               *rest.Config
	Kind                     string
	ClusterResourceNamespace string
	recorder                 record.EventRecorder
}

// configuration structure
type DBConfig struct {
	db struct {
		dsn          string
		maxOpenConns int64
		maxIdleConns int64
		maxIdleTime  time.Duration
	}
}

// Audit log data type
type auditlog struct {
	Kind       string `json:"kind,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
	Level      string `json:"level,omitempty"`
	AuditID    string `json:"auditID,omitempty"`
	Stage      string `json:"stage,omitempty"`
	RequestURI string `json:"requestURI,omitempty"`
	Verb       string `json:"verb,omitempty"`
	User       struct {
		Username string   `json:"username,omitempty"`
		Groups   []string `json:"groups,omitempty"`
		Extra    struct {
			AuthenticationKubernetesIoPodName []string `json:"authentication.kubernetes.io/pod-name"`
			AuthenticationKubernetesIoPodUID  []string `json:"authentication.kubernetes.io/pod-uid"`
		} `json:"extra,omitempty"`
	} `json:"user,omitempty"`
	SourceIPs []string `json:"sourceIPs,omitempty"`
	UserAgent string   `json:"userAgent,omitempty"`
	ObjectRef struct {
		Resource   string `json:"resource,omitempty"`
		Namespace  string `json:"namespace,omitempty"`
		Name       string `json:"name,omitempty"`
		APIGroup   string `json:"apiGroup,omitempty"`
		APIVersion string `json:"apiVersion,omitempty"`
	} `json:"objectRef,omitempty"`
	ResponseStatus struct {
		Metadata struct {
		} `json:"metadata,omitempty"`
		Code int `json:"code,omitempty"`
	} `json:"responseStatus,omitempty"`
	RequestReceivedTimestamp time.Time `json:"requestReceivedTimestamp,omitempty"`
	StageTimestamp           time.Time `json:"stageTimestamp,omitempty"`
	Annotations              struct {
		AuthorizationK8SIoDecision string `json:"authorization.k8s.io/decision"`
		AuthorizationK8SIoReason   string `json:"authorization.k8s.io/reason"`
	} `json:"annotations,omitempty"`
}

//+kubebuilder:rbac:groups=monitoring.spark.co.nz,resources=auditloggers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=monitoring.spark.co.nz,resources=auditloggers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=monitoring.spark.co.nz,resources=auditloggers/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;create;list;watch;delete
//+kubebuilder:rbac:groups="",resources=pods/status,verbs=get;create;list;watch
//+kubebuilder:rbac:groups="",resources=pods/exec,verbs=get;create;list;watch
//+kubebuilder:rbac:groups="",resources=pods/proxy,verbs=get;create;list;watch
//+kubebuilder:rbac:groups="",resources=pods/portforward,verbs=get;create;list;watch
//+kubebuilder:rbac:groups="",resources=pods/attach,verbs=get;create;list;watch
//+kubebuilder:rbac:groups="",resources=pods/log,verbs=get;create;list;watch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
//+kubebuilder:rbac:groups="machineconfiguration.openshift.io",resources=machineconfigpools,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch;get

func (r *AuditLoggerReconciler) getResource() (client.Object, error) {
	AuditLoggerKind := monitoringv1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(AuditLoggerKind)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AuditLogger object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.2/pkg/reconcile
func (r *AuditLoggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	_ = log.FromContext(ctx)

	auditLogger, err := r.getResource()
	if err != nil {
		log.Log.Error(err, "unrecognized auditlogger type")
		return ctrl.Result{}, err
	}
	if err = r.Get(ctx, req.NamespacedName, auditLogger); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Log.Info("auditlogger is not found")
		return ctrl.Result{}, nil
	}

	spec, status, err := util.GetSpecAndStatus(auditLogger)
	if err != nil {
		log.Log.Error(err, "unexpected error while trying to retrieve auditlogger spec and status, not retrying...")
		return ctrl.Result{}, err
	}

	var defaultHealthCheckInterval time.Duration

	if spec.SyncInterval != nil {
		defaultHealthCheckInterval = time.Minute * time.Duration(*spec.SyncInterval)
	} else {
		defaultHealthCheckInterval = time.Minute * 10
	}

	if spec.Suspend != nil && *spec.Suspend {
		log.Log.Info("Audit logger is suspended, skipping...")
		return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
	}

	secretName := types.NamespacedName{
		Name: spec.ExternalSecret,
	}

	configmapName := types.NamespacedName{
		Name: spec.ExternalData,
	}

	switch auditLogger.(type) {
	case *monitoringv1alpha1.AuditLogger:
		secretName.Namespace = r.ClusterResourceNamespace
		configmapName.Namespace = r.ClusterResourceNamespace
	default:
		log.Log.Error(fmt.Errorf("unexpected monitoring group cr type: %s", auditLogger), "not retrying")
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	var configmap corev1.ConfigMap
	var username []byte
	var password []byte
	var data map[string]string
	if spec.NotifyExternal != nil && *spec.NotifyExternal {
		if err := r.Get(ctx, secretName, &secret); err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
		}
		username = secret.Data["username"]
		password = secret.Data["password"]
	}

	if spec.NotifyExternal != nil && *spec.NotifyExternal {
		if err := r.Get(ctx, configmapName, &configmap); err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, configmap name: %s, reason: %v", errGetAuthConfigMap, configmapName, err)
		}
		data = configmap.Data
	}

	// report gives feedback by updating the Ready condition of the audit logger
	report := func(conditionStatus monitoringv1alpha1.ConditionStatus, message string, err error) {
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Log.Info(message)
		}
		r.recorder.Event(auditLogger, eventType, monitoringv1alpha1.EventReasonIssuerReconciler, message)
		util.SetReadyCondition(status, conditionStatus, monitoringv1alpha1.EventReasonIssuerReconciler, message)
	}

	defer func() {
		if err != nil {
			report(monitoringv1alpha1.ConditionFalse, "unable to sync audit logs", err)
		}
		if updateErr := r.Status().Update(ctx, auditLogger); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := util.GetReadyCondition(status); ready == nil {
		report(monitoringv1alpha1.ConditionUnknown, "First Seen", nil)
		return ctrl.Result{}, nil
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Log.Error(err, "unable to retrieve in cluster configuration")
		return ctrl.Result{}, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Log.Error(err, "failure using the retrieved kubeconfig with clientset")
		return ctrl.Result{}, err
	}

	//get config from openshift's openshift-apiserver
	var runningHost string
	domain, err := util.GetAPIName(*clientset)
	if err == nil && domain == "" {
		if spec.Cluster != nil {
			runningHost = *spec.Cluster
		}
	} else if err == nil && domain != "" {
		runningHost = domain
	} else {
		log.Log.Error(err, "unable to retrieve config configmap from openshift-apiserver project")
		runningHost = "local-cluster"
	}

	// Initialize DB configuration
	var cfg DBConfig
	var dsn string
	if spec.DbInfo.SecretName != nil && spec.DbInfo.DatabaseSvcName != nil {
		dbsecretName := types.NamespacedName{
			Name: *spec.DbInfo.SecretName,
		}

		switch auditLogger.(type) {
		case *monitoringv1alpha1.AuditLogger:
			secretName.Namespace = r.ClusterResourceNamespace
		default:
			log.Log.Error(fmt.Errorf("unexpected monitoring group cr type: %s", auditLogger), "not retrying")
			return ctrl.Result{}, nil
		}

		var secret corev1.Secret
		var dbusername []byte
		var dbpassword []byte
		var dbname []byte

		if err := r.Get(ctx, dbsecretName, &secret); err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
		}
		dbusername = secret.Data["POSTGRESQL_USER"]
		dbpassword = secret.Data["POSTGRESQL_PASSWORD"]
		dbname = secret.Data["POSTGRESQL_DATABASE"]

		dsn = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", string(dbusername), string(dbpassword), string(dbname), *spec.DbInfo.DatabaseSvcName)
	}
	flag.StringVar(&cfg.db.dsn, "db-dsn", dsn, "postgres DSN")
	if spec.DbInfo.MaxOpenConn != nil {
		flag.Int64Var(&cfg.db.maxOpenConns, "db-max-open-conns", *spec.DbInfo.MaxOpenConn, "postgres max open connections")
	} else {
		flag.Int64Var(&cfg.db.maxOpenConns, "db-max-open-conns", 25, "postgres max open connections")
	}
	if spec.DbInfo.MaxIdleConn != nil {
		flag.Int64Var(&cfg.db.maxIdleConns, "db-max-idle-conns", *spec.DbInfo.MaxIdleConn, "postgres max idle connections")
	} else {
		flag.Int64Var(&cfg.db.maxIdleConns, "db-max-idle-conns", 25, "postgres max idle connections")
	}
	if spec.DbInfo.MaxIdleTime != nil {
		flag.DurationVar(&cfg.db.maxIdleTime, "db-max-idel-time", time.Minute*time.Duration(*spec.DbInfo.MaxIdleTime), "postgres max idel time")
	} else {
		flag.DurationVar(&cfg.db.maxIdleTime, "db-max-idel-time", time.Minute*30, "postgres max idel time")
	}

	var image string
	var serviceAccount string
	if spec.PodInfo.Image != nil {
		image = *spec.PodInfo.Image
	} else {
		image = "tobeupdated"
	}
	if spec.PodInfo.ServiceAccount != nil {
		serviceAccount = *spec.PodInfo.ServiceAccount
	} else {
		serviceAccount = "default"
	}

	if status.LastRunTime == nil {
		// Check if master MCP is being updated
		updating, err := isMasterMcpUpdating(*clientset)
		if err != nil && k8serrors.IsNotFound(err) {
			log.Log.Info("machineconfigpools do not exist, proceeding further")
		} else if err != nil {
			log.Log.Info("unable to retrieve machineconfigpools, exiting and requeuing")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		} else if err == nil && updating {
			log.Log.Info("master machineconfigpool is being updated, exiting and requeing")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		}
		// Step1: Initiate DB Checks
		// initialize DB
		db, err := openDB(cfg)
		defer db.Close()
		if err != nil {
			log.Log.Error(err, "unable to establish connection to backend postgres database")
			if !slices.Contains(status.FailedChecks, "unable to establish postgres db connection") {
				if spec.SuspendEmailAlert != nil && !*spec.SuspendEmailAlert {
					util.SendEmailAlert(runningHost, fmt.Sprintf("/home/golanguser/.%s.txt", "database-conn"), spec, fmt.Sprintf("Unable to establish connection to backend postgres database in cluster %s", runningHost))
				}
				status.FailedChecks = append(status.FailedChecks, "unable to establish postgres db connection")
				if spec.NotifyExternal != nil && *spec.NotifyExternal {
					err := util.NotifyExternalSystem(data, "firing", spec.ExternalURL, string(username), string(password), fmt.Sprintf("/home/golanguser/.%s.txt", "alert-database-conn"), fmt.Sprintf("Unable to establish connection to backend postgres database in cluster %s", runningHost))
					if err != nil {
						log.Log.Error(err, "Failed to notify the external system")
					}
					fingerprint, err := util.ReadFile(fmt.Sprintf("/home/golanguser/.%s.txt", "alert-database-conn"))
					if err != nil {
						log.Log.Info("Failed to update the incident ID. Couldn't find the fingerprint in the file")
					}
					incident, err := util.SetIncidentID(spec, string(username), string(password), fingerprint)
					if err != nil || incident == "" {
						log.Log.Info("Failed to update the incident ID, either incident is getting created or other issues.")
					}
					if !slices.Contains(status.IncidentID, incident) && incident != "" && incident != "[Pending]" {
						status.IncidentID = append(status.IncidentID, incident)
					}
				}
			}
		}
		log.Log.Info("Database connection established")
		// Step2: Create the pod in all master nodes
		// 2a retrieve active nodes
		nodes, fnodes, err := util.RetrieveMasterNodes(*clientset)
		if err != nil {
			log.Log.Info("unable to retrieve master nodes, exiting and requeuing...")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		}
		if len(fnodes) > 0 {
			log.Log.Info(fmt.Sprintf("Found nodes with Ready status unknown or false %v", fnodes))
			// Add alert for failed nodes
		}

		// 2b create the pod in each active master node

		updating, err = isMasterMcpUpdating(*clientset)
		if err != nil && k8serrors.IsNotFound(err) {
			log.Log.Info("machineconfigpools do not exist, proceeding further")
		} else if err != nil {
			log.Log.Info("unable to retrieve machineconfigpools, exiting and requeuing")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		} else if err == nil && updating {
			log.Log.Info("master machineconfigpool is being updated, exiting and requeing")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		}

		var pods []string
		for _, node := range nodes {
			podName, err := util.CreatePod(*clientset, node, image, serviceAccount, r.ClusterResourceNamespace)
			if err != nil {
				log.Log.Info(fmt.Sprintf("unable to create the debug pod in node %s", node))
			}
			if podName != "" {
				pods = append(pods, podName)
			}
		}
		if len(pods) < 1 {
			log.Log.Error(err, "no active pod to collect audit logs, exiting and requeing")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		}

		// Step3: Copy the log files to local compute and execute the insert in DB

		updating, err = isMasterMcpUpdating(*clientset)
		if err != nil && k8serrors.IsNotFound(err) {
			log.Log.Info("machineconfigpools do not exist, proceeding further")
		} else if err != nil {
			log.Log.Info("unable to retrieve machineconfigpools, exiting and requeuing")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		} else if err == nil && updating {
			log.Log.Info("master machineconfigpool is being updated, exiting and requeing")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
		}

		// insert the files
		for _, podName := range pods {
			files, err := GetFileList(r, *clientset, podName, r.ClusterResourceNamespace)
			if err != nil {
				log.Log.Info(fmt.Sprintf("unable to retrieve audit log files list from pod %s", podName))
			}
			err = InsertAuditLogFiles(files, db, podName, cfg)
			if err != nil {
				log.Log.Info(fmt.Sprintf("unable to insert the auditlog file names into db for pod %s", podName))
			}
		}

		// Step3b: Delete the pods

		// Step4: Post successful insertion, mark the ready to true
		now := metav1.Now()
		status.LastRunTime = &now
		if len(status.FailedChecks) < 1 {
			now := metav1.Now()
			status.LastSuccessfulRunTime = &now
			log.Log.Info("Audit log sync from all master pods are successful)")
			report(monitoringv1alpha1.ConditionTrue, "Audit log sync has been completed successfully.", nil)
		} else {
			report(monitoringv1alpha1.ConditionFalse, "Some checks are failing, please check status.FailedChecks for list of failures.", nil)
		}
	} else {

		// Step1: Initiate DB Checks

		// Step2: Create the pod in all master nodes

		// Step3a: Copy the log files to local compute and execute the insert in DB

		// Step3b: Ignore previously copied completed files, focus only on audit.log

		// Step4: Post successful insertion, mark the ready to true

	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuditLoggerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(monitoringv1alpha1.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&monitoringv1alpha1.AuditLogger{}).
		Complete(r)
}

func openDB(cfg DBConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.db.dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func writeFile(r *AuditLoggerReconciler, commandToRun string, outFile *os.File, pod string, namespace string) error {
	req := r.RESTClient.Post().Resource("pods").Name(pod).Namespace(namespace).SubResource("exec").VersionedParams(
		&corev1.PodExecOptions{
			Container: "debug",
			Command:   []string{"chroot", "/host", fmt.Sprintf("%s", commandToRun)},
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, runtime.NewParameterCodec(r.Scheme))
	// ex, err := remotecommand.NewWebSocketExecutor(config, "GET", req.URL().String())
	ex, err := remotecommand.NewSPDYExecutor(r.RESTConfig, "POST", req.URL())
	if err != nil {
		return err
	}
	err = ex.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdin:  os.Stdin,
		Stdout: outFile,
		Stderr: os.Stderr,
		Tty:    false,
	})
	if err != nil {
		return err
	}
	return nil
}

func GetFileList(r *AuditLoggerReconciler, clientset kubernetes.Clientset, podName string, namespace string) ([]string, error) {
	fileList, err := os.OpenFile(fmt.Sprintf("/home/golanguser/.%s-auditfilelist.txt", podName), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	writeFile(r, "ls /var/log/openshift-apiserver", fileList, podName, namespace)
	files, err := util.ListFiles(fileList)
	if err != nil {
		return nil, err
	}
	return files, nil
}

func InsertAuditLogFiles(files []string, db *sql.DB, podName string, cfg DBConfig) error {
	var dbTimeout = time.Second * 10
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	stmt := `insert into auditlogfiles (pod, filename) values ($1, $2)`
	for _, filename := range files {
		_, err := db.ExecContext(ctx, stmt, podName, filename)
		if err != nil {
			return err
		}
	}
	return nil
}

func isMasterMcpUpdating(clientset kubernetes.Clientset) (bool, error) {
	mcpList := mcfgv1.MachineConfigPoolList{}
	err := clientset.RESTClient().Get().AbsPath("/apis/machineconfiguration.openshift.io/v1/machineconfigpools").Do(context.Background()).Into(&mcpList)
	if err != nil {
		return false, err
	}
	for _, mcp := range mcpList.Items {
		if strings.ToLower(mcp.Name) == "master" {
			for _, cond := range mcp.Status.Conditions {
				if cond.Type == "Updating" {
					if cond.Status == "True" {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}
