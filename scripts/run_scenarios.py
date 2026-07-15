# run_scenarios.py - B.5 Worked Evaluation Scenarios
# Runs all 8 hypothetical asset scenarios from Appendix B.5 and prints
# structured results for inclusion in the thesis appendix.

import sys, os, datetime, json
sys.path.insert(0, os.path.dirname(__file__))

from stride_engine import Asset, evaluate_stride, STRIDE_RULES, stride_root_cause
from linddun_engine import evaluate_linddun, LINDDUN_RULES, linddun_root_cause

# Regulatory resolution map.
# Complete Table 9 resolution set across all thirteen categories. Only categories
# that return OPEN are printed, so untriggered categories do not appear in the
# printed output.
STRIDE_REG = {
    'Spoofing': 'PDPA Protection Obligation; Cybersecurity Act 2024 CII s.8; CSA Guidelines §4.1 identity verification',
    'Tampering': 'HIA 2026 data integrity standard; ISO/IEC 42001:2023 B.7 data management; PDPA Protection Obligation',
    # Repudiation is included for STRIDE completeness; it is not separately enumerated in Table 9.
    'Repudiation': 'HIA 2026 audit trail requirement; PSGA IM8 audit logging; ISO/IEC 27001:2022 A.8.15',
    'Information_Disclosure': 'PDPA Protection Obligation; CSA Guidelines encryption control; ISO/IEC 27001:2022 A.8.24',
    'Denial_of_Service': 'Cybersecurity Act 2024 CII availability obligation; PDPA Protection Obligation; HIA 2026 service continuity',
    'Elevation_of_Privilege': 'CSA Guidelines lifecycle stage 3 access control; Cybersecurity Act 2024 CII s.8; HIA 2026 access standards',
}
LINDDUN_REG = {
    'Linkability': 'PSGA IM8 anti-re-identification; PDPA Protection Obligation; ISO/IEC 42001:2023 B.6 data management',
    'Identifiability': 'PDPA Protection Obligation; PSGA IM8 data classification; ISO/IEC 42001:2023 B.7',
    'Non_Repudiation': 'PSGA IM8; HIA 2026 storage standards; ISO/IEC 42001:2023 B.7 lifecycle control',
    'Detectability': 'PDPA Protection Obligation; CSA Guidelines output monitoring; ISO/IEC 42001:2023 B.9 robustness',
    'Disclosure_of_Information': 'PDPA Consent Obligation; PDPC 2024 AI Advisory Guidelines; AIHGle 2.0 transparency requirement',
    'Unawareness': 'PDPA Consent Obligation; PDPC 2024 AI Advisory Guidelines; AIHGle 2.0 explainability requirement',
    'Non_Compliance': 'PDPA Protection Obligation; PSGA IM8; Cybersecurity Act 2024; HIA 2026',
}

# Asset inventory (8 scenarios from B.5).
assets = [
    # Scenario 1 - HEALIX inference API (rate limiting absent)
    Asset('healix_inference_api', 'Model APIs and Inference', {
        'mfa_enforced': True, 'integrity_signed': True, 'audit_logging': True,
        'encryption_in_transit': True, 'encryption_at_rest': True,
        'rate_limit_configured': False, 'redundancy_zone': True,
        'least_privilege_iam': True,
    }),
    # Scenario 2 - HEALIX training repository (membership-inference + noise defences absent)
    Asset('healix_training_repository', 'Training Data Repository', {
        'quasi_identifier_review': True, 'k_anonymity_threshold': 5,
        'pseudonymisation_applied': True, 'membership_inference_defence': False,
        'output_noise_calibrated': False, 'purpose_binding_enforced': True,
        'consent_capture_documented': True, 'pdpa_obligation_evidence': True,
        'psga_im8_evidence': True,
    }),
    # Scenario 3 - Tandem LLM interface (purpose binding absent)
    Asset('tandem_llm_interface', 'LLM and RAG User Interaction', {
        'quasi_identifier_review': True, 'k_anonymity_threshold': 5,
        'pseudonymisation_applied': True, 'membership_inference_defence': True,
        'output_noise_calibrated': True, 'purpose_binding_enforced': False,
        'consent_capture_documented': True, 'pdpa_obligation_evidence': True,
        'psga_im8_evidence': True,
    }),
    # Scenario 4 - NEHR (MFA absent on cross-cluster clinician authentication)
    Asset('nehr_cross_cluster', 'NEHR Record Consolidation', {
        'mfa_enforced': False, 'integrity_signed': True, 'audit_logging': True,
        'encryption_in_transit': True, 'encryption_at_rest': True,
        'rate_limit_configured': True, 'redundancy_zone': True,
        'least_privilege_iam': True,
    }),
    # Scenario 5 - aiTriage (model output integrity signing absent)
    Asset('aitriage_inference', 'AI Model Inference', {
        'mfa_enforced': True, 'integrity_signed': False, 'audit_logging': True,
        'encryption_in_transit': True, 'encryption_at_rest': True,
        'rate_limit_configured': True, 'redundancy_zone': True,
        'least_privilege_iam': True,
    }),
    # Scenario 6 - CareScribe (pseudonymisation absent in speech-to-text output)
    Asset('carescribe_speech_to_text', 'Speech Recognition AI', {
        'quasi_identifier_review': True, 'k_anonymity_threshold': 5,
        'pseudonymisation_applied': False, 'membership_inference_defence': True,
        'output_noise_calibrated': True, 'purpose_binding_enforced': True,
        'consent_capture_documented': True, 'pdpa_obligation_evidence': True,
        'psga_im8_evidence': True,
    }),
    # Scenario 7 - CARES 2 (membership inference defence absent)
    Asset('cares2_predictive_model', 'Clinical Predictive Model', {
        'quasi_identifier_review': True, 'k_anonymity_threshold': 5,
        'pseudonymisation_applied': True, 'membership_inference_defence': False,
        'output_noise_calibrated': True, 'purpose_binding_enforced': True,
        'consent_capture_documented': True, 'pdpa_obligation_evidence': True,
        'psga_im8_evidence': True,
    }),
    # Scenario 8 - AimSG (encryption at rest absent on imaging data store)
    Asset('aimsg_imaging_store', 'Medical Imaging Data Store', {
        'mfa_enforced': True, 'integrity_signed': True, 'audit_logging': True,
        'encryption_in_transit': True, 'encryption_at_rest': False,
        'rate_limit_configured': True, 'redundancy_zone': True,
        'least_privilege_iam': True,
    }),
]

# Engine routing: which engine runs on which asset.
ENGINE_MAP = {
    'healix_inference_api': 'STRIDE',
    'healix_training_repository': 'LINDDUN',
    'tandem_llm_interface': 'LINDDUN',
    'nehr_cross_cluster': 'STRIDE',
    'aitriage_inference': 'STRIDE',
    'carescribe_speech_to_text': 'LINDDUN',
    'cares2_predictive_model': 'LINDDUN',
    'aimsg_imaging_store': 'STRIDE',
}

REG_MAP = {'STRIDE': STRIDE_REG, 'LINDDUN': LINDDUN_REG}

# Run and print.
print('Threat-Modelling-as-Code: Worked Evaluation Scenarios (Appendix B.5)')
print('Generated:', datetime.datetime.now().strftime('%d %B %Y, %H:%M:%S'))
print('Engines: stride_engine.py v1.0 | linddun_engine.py v1.0')
print()

for i, asset in enumerate(assets, 1):
    engine = ENGINE_MAP[asset.name]
    results = evaluate_stride(asset) if engine == 'STRIDE' else evaluate_linddun(asset)
    reg_map = REG_MAP[engine]
    open_threats = [t for t, s in results.items() if s == 'OPEN']

    print(f'Scenario {i}: {asset.name}')
    print(f'  Asset type: {asset.asset_type}')
    print(f'  Engine: {engine}')
    if open_threats:
        print(f'  Status: {len(open_threats)} OPEN finding(s)')
        for threat in open_threats:
            print(f'    OPEN  {threat}: {reg_map[threat]}')
    else:
        print('  Status: ALL MITIGATED')
    print()

# Summary of open findings across all scenarios.
print('Summary: Open Findings Across All Scenarios')
for asset in assets:
    engine = ENGINE_MAP[asset.name]
    results = evaluate_stride(asset) if engine == 'STRIDE' else evaluate_linddun(asset)
    reg_map = REG_MAP[engine]
    open_threats = [t for t, s in results.items() if s == 'OPEN']
    if open_threats:
        primary = '; '.join(reg_map[t].split(';')[0] for t in open_threats)
        print(f'  {asset.name} [{engine}]: {", ".join(open_threats)} ({primary})')

print()
print('Note. All assets are hypothetical property sets as specified in Appendix B.5.')
print('No live Synapxe, NEHR, HEALIX, or Tandem infrastructure was accessed.')
print('Results demonstrate internal consistency of the rule sets with the taxonomy in Table 8.')
# Export structured results for the dashboard
export_data = []
for i, asset in enumerate(assets, 1):
    engine = ENGINE_MAP[asset.name]
    results = evaluate_stride(asset) if engine == 'STRIDE' else evaluate_linddun(asset)
    reg_map = REG_MAP[engine]
    open_threats = [t for t, s in results.items() if s == 'OPEN']
    mitigated_threats = [t for t, s in results.items() if s != 'OPEN']

    export_data.append({
        "scenario_id": i,
        "asset_name": asset.name,
        "asset_type": asset.asset_type,
        "engine": engine,
        "open_count": len(open_threats),
        "mitigated_count": len(mitigated_threats),
        "open_threats": [
            {
                "category": t,
                "regulation": reg_map[t],
                "root_cause": stride_root_cause(asset, t) if engine == 'STRIDE' else linddun_root_cause(asset, t),
            }
            for t in open_threats
        ],
        "mitigated_threats": mitigated_threats,
    })

with open('tmac_output.json', 'w') as f:
    json.dump({
        "generated": datetime.datetime.now().isoformat(),
        "scenarios": export_data
    }, f, indent=2)

print("Exported: tmac_output.json")
