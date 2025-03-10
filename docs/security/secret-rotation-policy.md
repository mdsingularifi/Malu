# Secret Rotation Policy for Secret-Storage-Service

## Overview
This document outlines the secret rotation policy for the Secret-Storage-Service in the Malu ecosystem. It defines the rotation schedule, procedures, and responsibilities to maintain a high level of security for sensitive credentials.

## Rotation Schedule

| Secret Type | Rotation Frequency | Rotation Method | Responsibility |
|-------------|-------------------|-----------------|----------------|
| API Tokens | 30 days | Automatic via Vault integration | Platform Team |
| Database Credentials | 90 days | Automatic via Vault integration | Platform Team |
| TLS Certificates | 90 days | Automatic via cert-manager | Security Team |
| Encryption Keys | 180 days | Automated with operator approval | Security Team |
| JWT Signing Keys | 90 days | Automatic with versioning | Security Team |

## Rotation Procedures

### Automatic Rotation (Vault Integration)
1. Secrets are stored in HashiCorp Vault with TTL (Time To Live) settings
2. The service authenticates to Vault using Kubernetes service account
3. New secrets are automatically generated before expiration
4. Secret changes are communicated via Kubernetes projected volumes
5. The service detects changes and reloads without downtime

### Certificate Rotation (cert-manager)
1. TLS certificates are managed by cert-manager with automatic renewal
2. Certificates are renewed 30 days before expiration
3. New certificates are mounted to pods via Kubernetes secrets
4. Istio handles certificate distribution to sidecars

### Encryption Key Rotation
1. Master encryption keys are rotated using envelope encryption
2. New keys are generated and encrypted by the previous key
3. All data is progressively re-encrypted with the new key
4. Old keys are preserved for decryption of legacy data

## Emergency Rotation
In case of a security incident or suspected compromise:
1. Trigger immediate rotation via Security Operations Dashboard
2. All affected secrets are regenerated with new values
3. Force pod replacement to pick up new credentials
4. Incident response team validates rotation success
5. Generate incident report including affected credentials

## Monitoring and Validation
1. Metrics for secret age are exposed via Prometheus
2. Alerts trigger when rotation fails or secrets approach expiration
3. Weekly automated validation checks verify rotation mechanism
4. Quarterly security review of rotation mechanisms

## Implementation Details
The Secret-Storage-Service implements secret rotation through:
1. Kubernetes projected volumes for automatic updates
2. Vault Agent for credential management
3. Environment variables to control rotation behavior:
   - `SECRETS_AUTO_ROTATION`: Toggle automatic rotation
   - `SECRETS_ROTATION_INTERVAL`: Default rotation interval
4. Service gracefully handles credential updates at runtime

## Compliance Requirements
This rotation policy ensures compliance with:
- SOC2 Type II requirements for secret management
- NIST 800-53 controls for access management
- PCI-DSS requirements for cryptographic key management

Last updated: March 8, 2025
