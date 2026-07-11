# TMaC Pipeline: AI-Driven Data Privacy Vulnerability Modelling for Singapore Public Healthcare

Supplementary code and artifacts for the MSc thesis:

**[Evaluating AI-Driven Data Privacy Vulnerabilities and System Breach Mitigations in Singapore's
Public Healthcare Systems]**
Adam Lloyd Abraham (Student ID: MCSLT00402)
Università degli Studi Guglielmo Marconi
Supervisor: Mr Suryanto

This repository contains the Threat-Modelling-as-Code (TMaC) pipeline referenced in
Appendix B of the thesis: two STRIDE/LINDDUN validation engines, a scenario runner
evaluating eight Singapore public healthcare AI asset scenarios, the resulting output
export, and an offline stakeholder visualisation dashboard.

## Contents

| Path | Thesis reference | Description |
|---|---|---|
| `scripts/stride_engine.py` | Appendix B.1 | STRIDE validation engine |
| `scripts/linddun_engine.py` | Appendix B.2 | LINDDUN validation engine |
| `scripts/run_scenarios.py` | Appendix B.5–B.6 | Runs both engines across the 8 evaluation scenarios; exports `tmac_output.json` |
| `dashboard/tmac_dashboard.html` | Appendix B.7 | Offline stakeholder visualisation dashboard (no external dependencies) |
| `dashboard/tmac_output.json` | Appendix B.6 | Engine output consumed by the dashboard |
| `manifests/infrastructure_manifest.json` | Appendix B.4 | Illustrative infrastructure manifest referenced in the pipeline integration discussion |

## Running the pipeline

```bash
cd scripts
python run_scenarios.py
```

This regenerates `tmac_output.json` in the working directory. To refresh the copy the
dashboard reads from, copy the output into `dashboard/`:

```bash
cp tmac_output.json ../dashboard/tmac_output.json
```

## Viewing the dashboard

Open `dashboard/tmac_dashboard.html` directly in any browser - no server, build step,
or external dependencies required.

- If served from a local web server (or viewed on GitHub Pages) from the same folder,
  it auto-loads `dashboard/tmac_output.json`.
- If opened directly as a local file and the browser blocks the fetch, use the
  drag-and-drop / file-select option built into the dashboard to load
  `tmac_output.json` manually.

## Scope note

No live Synapxe, NEHR, HEALIX, or Tandem infrastructure is accessed by any script or
the dashboard. All evaluation scenarios are hypothetical, constructed for illustrative
and academic purposes as described in Appendix B.5.

## Citation

Abraham, A.L. (2026). milloyd7581/mcslt00402_adam_lloyd_abraham_tmac-healthcare-thesis: 
v1.0.2 - VIVA Submission Snapshot (Version v1.0.2-viva-submission) [Computer software]. 
Zenodo. https://doi.org/10.5281/zenodo.21294221
