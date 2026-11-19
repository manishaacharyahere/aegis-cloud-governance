{{- define "aegis.name" -}}{{ .Release.Name | trunc 40 | trimSuffix "-" }}{{- end -}}

{{- define "aegis.labels" -}}
app.kubernetes.io/part-of: aegis
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "aegis.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "aegis.image" -}}
{{ printf "%s/%s:%s" .root.Values.image.registry .name (default .root.Chart.AppVersion .root.Values.image.tag) }}
{{- end -}}

{{- define "aegis.secret" -}}{{ default (printf "%s-secrets" (include "aegis.name" .)) .Values.existingSecret }}{{- end -}}

{{- define "aegis.issuer" -}}
{{- if .Values.api.oidc.issuer -}}{{ .Values.api.oidc.issuer }}{{- else if .Values.dex.enabled -}}https://{{ .Values.host }}/dex{{- end -}}
{{- end -}}

{{/* Locked-down defaults for every container. */}}
{{- define "aegis.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities: { drop: ["ALL"] }
seccompProfile: { type: RuntimeDefault }
{{- end -}}

{{/* Settings shared by the API and its init step. */}}
{{- define "aegis.apiEnv" -}}
- { name: AEGIS_ENV, value: {{ .Values.environment | quote }} }
- { name: AEGIS_LOG_LEVEL, value: {{ .Values.api.logLevel | quote }} }
- { name: AEGIS_HTTP_ADDR, value: ":8080" }
- { name: AEGIS_METRICS_ADDR, value: ":9464" }
- { name: AEGIS_MIGRATE_ON_START, value: "false" }
- { name: AEGIS_FIXTURES_DIR, value: "/fixtures" }
- name: AEGIS_DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ include "aegis.secret" . }}, key: app-database-url } }
- { name: AEGIS_OPA_URL, value: "http://{{ include "aegis.name" . }}-opa:8181" }
- name: AEGIS_OPA_TOKEN
  valueFrom: { secretKeyRef: { name: {{ include "aegis.secret" . }}, key: opa-token } }
- { name: AEGIS_NATS_URL, value: "nats://{{ include "aegis.name" . }}-nats:4222" }
- { name: AEGIS_NATS_USER, value: aegis_api }
- name: AEGIS_NATS_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ include "aegis.secret" . }}, key: nats-password } }
- name: AEGIS_SIGNING_KEY
  valueFrom: { secretKeyRef: { name: {{ include "aegis.secret" . }}, key: signing-key } }
- { name: AEGIS_AUTH_MODE, value: {{ .Values.api.authMode | quote }} }
- { name: AEGIS_OIDC_ISSUER, value: {{ include "aegis.issuer" . | quote }} }
- { name: AEGIS_OIDC_CLIENT_ID, value: {{ .Values.api.oidc.clientId | quote }} }
- { name: AEGIS_BOOTSTRAP_TENANT, value: {{ .Values.api.bootstrapTenant | quote }} }
- { name: AEGIS_BOOTSTRAP_ADMINS, value: {{ join "," .Values.api.bootstrapAdmins | quote }} }
{{- if eq .Values.api.authMode "dev-headers" }}
# The web proxy reaches the API from a pod address.
- { name: AEGIS_DEV_TRUST_PRIVATE_NETWORK, value: "true" }
{{- end }}
{{- with .Values.api.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}
