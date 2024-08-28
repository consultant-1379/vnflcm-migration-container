{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "eric-vm-vnfm-migration.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-vm-vnfm-migration.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-vm-vnfm-migration.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create release name used for cluster role.
*/}}
{{- define "eric-vm-vnfm-migration.release.name" -}}
{{- default .Release.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "eric-vm-vnfm-migration.registryUrl" -}}
{{- if .Values.imageCredentials.registry.url -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- else -}}
{{- print .Values.global.registry.url -}}
{{- end -}}
{{- end -}}


{{/*
Create image pull secrets
*/}}
{{- define "eric-vm-vnfm-migration.pullSecrets" -}}
{{- if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- else if .Values.global.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create Ericsson product app.kubernetes.io info
*/}}
{{- define "eric-vm-vnfm-migration.kubernetes-io-info" -}}
app.kubernetes.io/name: {{ .Chart.Name | quote }}
app.kubernetes.io/version: {{ .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}


Create Ericsson Product Info
*/}}
{{- define "eric-vm-vnfm-migration.helm-annotations" -}}
ericsson.com/product-name: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productName | quote }}
ericsson.com/product-number: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productNumber | quote }}
ericsson.com/product-revision: {{ regexReplaceAll "(.*)[+|-].*" .Chart.Version "${1}" | quote }}
{{- end }}


{{/*
Define the default storage class name.
*/}}
{{- define "eric-vm-vnfm-migration.defaultStorageClassName" -}}
{{- if .Values.persistentVolumeClaim.storageClassName }}
{{- if (eq "-" .Values.persistentVolumeClaim.storageClassName) }}
{{- "" -}}
{{- else }}
{{- print .Values.persistentVolumeClaim.storageClassName -}}
{{- end }}
{{- else }}
{{- "erikube-rbd" -}}
{{- end }}
{{- end -}}


{{- define "vnflcm-migration.mainImagePath" -}}
    {{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
    {{- $registryUrl := $productInfo.images.mainImage.registry -}}
    {{- $repoPath := $productInfo.images.mainImage.repoPath -}}
    {{- $name := $productInfo.images.mainImage.name -}}
    {{- $tag := $productInfo.images.mainImage.tag -}}
    {{- if .Values.global -}}
        {{- if .Values.global.registry -}}
            {{- if .Values.global.registry.url -}}
                {{- $registryUrl = .Values.global.registry.url -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if .Values.imageCredentials -}}
        {{- if .Values.imageCredentials.mainImage -}}
            {{- if .Values.imageCredentials.mainImage.registry -}}
                {{- if .Values.imageCredentials.mainImage.registry.url -}}
                    {{- $registryUrl = .Values.imageCredentials.mainImage.registry.url -}}
                {{- end -}}
            {{- end -}}
            {{- if .Values.imageCredentials.mainImage.repoPath -}}
                {{- $repoPath = .Values.imageCredentials.mainImage.repoPath -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if $repoPath -}}
        {{- $repoPath = printf "%s/" $repoPath -}}
    {{- end -}}
    {{- printf "%s/%s%s:%s" $registryUrl $repoPath $name $tag -}}
{{- end -}}

{{- define "eric-eo-evnfm-vm.imagePullPolicy" -}}
{{- if .Values.global.registry.imagePullPolicy -}}
{{- print .Values.global.registry.imagePullPolicy  -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.imagePullPolicy -}}
{{- end -}}
{{- end -}}

{{/*
The name of the cluster role used during openshift deployments.
This helper is provided to allow use of the new global.security.privilegedPolicyClusterRoleName if set, otherwise
use the previous naming convention of <release_name>-allowed-use-privileged-policy for backwards compatibility.
*/}}
{{- define "eric-vm-vnfm-migration.privileged.cluster.role.name" -}}
  {{- if hasKey (.Values.global.security) "privilegedPolicyClusterRoleName" -}}
    {{ .Values.global.security.privilegedPolicyClusterRoleName }}
  {{- else -}}
    {{ template "eric-vm-vnfm-migration.release.name" . }}-allowed-use-privileged-policy
  {{- end -}}
{{- end -}}
