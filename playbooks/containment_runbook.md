# SOC Containment Runbook
1. **Host Isolation**: Isolate host via EDR agent.
2. **Volatile Memory**: Acquire RAM dump prior to power transition.
3. **Process Termination**: Terminate parent-child process tree matched by T1059 telemetry.
