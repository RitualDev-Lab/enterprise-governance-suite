{{/*
Expand the name of the chart.
*/}}
{{- define "ritual-governance.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ritual-governance.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ritual-governance.labels" -}}
helm.sh/chart: {{ include "ritual-governance.name" . }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
enterprise.ritualdev.com/suite: "governance"
{{- end }}

{{- define "ritual-agent-governance.name" -}}
{{- include "ritual-governance.name" . }}
{{- end }}

{{- define "ritual-agent-governance.fullname" -}}
{{- include "ritual-governance.fullname" . }}
{{- end }}

{{- define "ritual-agent-governance.labels" -}}
{{- include "ritual-governance.labels" . }}
{{- end }}
