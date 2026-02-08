---
# src/pages/rules.md
title: Rules
---

# Rules

This document outlines the rules and best practices for Docker images submitted to the platform.  
These requirements ensure **fairness**, **performance**, and **operational stability** across all deployments.

---

## General Requirements

All submissions **must** be packaged as a Docker image and comply with the rules below.

> ⚠️ Images that violate these rules may be rejected, throttled, or disqualified at runtime.

---

## Image Size Constraints

To ensure fast distribution and predictable startup times, Docker image sizes are limited.

- **Maximum compressed image size**: 2 GB
- **Recommended image size**: ≤ 1 GB
- Images should use **minimal base images** where possible (e.g., `alpine`, `distroless`, or slim variants)
- Unused build artifacts, package caches, and temporary files **must be removed**

> Images exceeding the maximum size limit will not be accepted.

---

## Performance Requirements

Submitted containers must meet basic performance expectations under constrained resources.

### Startup Time

- Containers must start and become ready within **30 seconds**
- Long initialization steps should be avoided or deferred

### Runtime Behavior

- Containers should not perform unnecessary background computation
- Busy loops, excessive polling, and artificial delays are prohibited
- All computation should be **event-driven or request-driven**

---

## Resource Limits

Containers will be executed with fixed resource limits.

### CPU

- Maximum: **2 vCPUs**
- Sustained CPU usage above **80%** may result in throttling

### Memory

- Maximum: **4 GB RAM**
- Containers exceeding memory limits will be terminated

### Disk

- Containers should assume **read-only root filesystem**
- Persistent storage is **not guaranteed**

---

## Networking Rules

To ensure security and isolation:

- Outbound internet access may be **restricted or disabled**
- Containers must not assume access to external services
- All required resources must be included in the image itself

---

## Security Requirements

All Docker images must follow basic security hygiene.

- Containers must **not run as root** unless explicitly required
- No embedded credentials, API keys, or secrets
- Images must not attempt to escape the container environment
- Privileged containers are **not allowed**

---

## Logging and Output

- Logs should be written to **stdout/stderr**
- Excessive logging may impact performance
- Logs should be human-readable and relevant

---

## Validation and Enforcement

All submissions will be automatically validated for:

- Image size compliance
- Startup time
- Resource usage
- Runtime behavior

Submissions that fail validation may be:
- Rejected before execution
- Disqualified during evaluation
- Removed from the platform

---

## Final Notes

These rules are intended to ensure a **fair, performant, and secure execution environment** for all participants.

Rules may be updated as the platform evolves.  
For the latest version, refer to the official documentation.
