# Documentation

[← back to the overview](../README.md)

The write-ups follow the runtime path from detection through storage and
delivery, then cover the baseline and deployment layers.

| Topic | What it shows |
|---|---|
| [Detection pipeline](detection-pipeline.md) | Every implemented check, its predicate, state, severity and one firing sequence |
| [Splunk integration](splunk-integration.md) | Process boundaries, JSON format, file transport and current schema gaps |
| [Baselines and operation](baseline-and-operation.md) | Snapshot generation, monitor state, service paths and baseline mismatch |
| [Ansible deployment](ansible-deployment.md) | Inventory-to-role flow, service modes and unverified deployment references |
| [Bugs found](BUGS-FOUND.md) | Status of every reported bug, with fix commits and reproduction output |
| [Measurement](measurement.md) | The Linux container run behind every number |
| [Legacy installation guide](INSTALLATION.md) | Historical installation text, explicitly marked unverified |
| [Implementation plan](implementation-plan.md) | Historical design scope, separated from current behavior |
