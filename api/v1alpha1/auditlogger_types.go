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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	EventSource                 = "AuditLogger"
	EventReasonIssuerReconciler = "AuditLoggerReconciler"
)

// AuditLoggerSpec defines the desired state of AuditLogger
type AuditLoggerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// cluster name where audit logger is to be deployed which is used for sending notifications
	// if not specified controller will retrieve the API name from config configmap of openshift-apiserver project
	// if not specified and relevant configmap doesn't exist, cluster will be set to local-cluster
	Cluster *string `json:"cluster,omitempty"`

	// Database info
	DbInfo DBInfo `json:"dbInfo"`

	// Image for the host pod, if not set openshift/tools:latest will be used by default
	// +optional
	PodInfo PodInfo `json:"podImage,omitempty"`

	// Set suspend to true to disable monitoring the custom resource
	// +optional
	Suspend *bool `json:"suspend,omitempty"`

	// Suspends email alerts if set to true, target users will not be notified
	// +optional
	SuspendEmailAlert *bool `json:"suspendEmailAlert,omitempty"`

	// Target user's email for cluster status notification
	// +optional
	Email string `json:"email,omitempty"`

	// Relay host for sending the email
	// +optional
	RelayHost string `json:"relayHost,omitempty"`

	// To notify the external alerting system
	// +optional
	NotifyExternal *bool `json:"notifyExternal,omitempty"`

	// URL of the external alert system. Example: http://notify.example.com/ (both http/https supported with basic authentication)
	// +optional
	ExternalURL string `json:"externalURL,omitempty"`

	// Data to be sent to the external system in the form of config map
	// +optional
	ExternalData string `json:"externalData,omitempty"`

	// Secret which has the username and password to post the alert notification to the external system using Authorization header
	// +optional
	ExternalSecret string `json:"externalSecret,omitempty"`

	// frequency of the audit log sync from the host to database. If not set, it defaults to 10 mins.
	// +optional
	SyncInterval *int64 `json:"syncInterval,omitempty"`
}

type PodInfo struct {
	// image for creating the pod
	Image *string `json:"image"`

	// ServiceAccount for the pod
	ServiceAccount *string `json:"serviceAccount"`
}

// Postgres Database information
type DBInfo struct {
	// postgres service host
	DatabaseSvcName *string `json:"databaseSvcName"`

	// Secret name that contains username and password of postgres backend
	// secret is expected to be existing in the same namespace where audit logger CR is deployed
	SecretName *string `json:"secretName"`

	// Max open connections
	// +optional
	MaxOpenConn *int64 `json:"maxOpenConn,omitempty"`

	// Max idle connections
	// +optional
	MaxIdleConn *int64 `json:"maxIdleConn,omitempty"`

	// Max idle time
	// +optional
	MaxIdleTime *int64 `json:"maxIdleTime,omitempty"`
}

// AuditLoggerStatus defines the observed state of AuditLogger
type AuditLoggerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// list of status conditions to indicate the status of managed cluster
	// known conditions are 'Ready'.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`

	// last timestamp of audit log sync attempt
	// +optional
	LastRunTime *metav1.Time `json:"lastRunTime,omitempty"`

	// Incident ID from the rem. Spark specific
	// +optional
	IncidentID []string `json:"incidentID,omitempty"`

	// list of failed checks
	// +optional
	FailedChecks []string `json:"failedChecks,omitempty"`

	// last successful timestamp of audit log sync
	// +optional
	LastSuccessfulRunTime *metav1.Time `json:"lastSuccessfulRunTime,omitempty"`
}

type Condition struct {
	// Type of the condition, known values are 'Ready'.
	Type ConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown')
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp of the last update to the status
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is the machine readable explanation for object's condition
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is the human readable explanation for object's condition
	Message string `json:"message"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// AuditLogger is the Schema for the auditloggers API
// +kubebuilder:printcolumn:name="CreatedAt",type="string",JSONPath=".metadata.creationTimestamp",description="object creation timestamp(in cluster's timezone)"
// +kubebuilder:printcolumn:name="LastRunTime",type="string",JSONPath=".status.lastRunTime",description="last healthcheck run timestamp(in cluster's timezone)"
// +kubebuilder:printcolumn:name="LastSuccessfulRunTime",type="string",JSONPath=".status.lastSuccessfulRunTime",description="last successful run timestamp(in cluster's timezone) when audit log sync was successful"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[].status",description="if set to true, audit log sync is successful"
type AuditLogger struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuditLoggerSpec   `json:"spec,omitempty"`
	Status AuditLoggerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AuditLoggerList contains a list of AuditLogger
type AuditLoggerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuditLogger `json:"items"`
}

// ConditionType represents a audit logger condition value.
type ConditionType string

const (
	// ConditionReady represents the fact that audit logs are synced from host to database
	// If the `status` of this condition is `False`, there is an issue with audit log sync
	ConditionReady ConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

func init() {
	SchemeBuilder.Register(&AuditLogger{}, &AuditLoggerList{})
}
