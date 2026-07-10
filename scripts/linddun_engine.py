# linddun_engine.py - illustrative proof of concept
from typing import Dict
from stride_engine import Asset
LINDDUN_RULES = {
    'Linkability': lambda a: a.properties.get('quasi_identifier_review', False)
                              and a.properties.get('k_anonymity_threshold', 0) >= 5,
    'Identifiability': lambda a: a.properties.get('pseudonymisation_applied', False),
    'Non_Repudiation': lambda a: a.properties.get(
        'membership_inference_defence', False),
    'Detectability': lambda a: a.properties.get('output_noise_calibrated', False),
    'Disclosure_of_Information': lambda a: a.properties.get(
        'purpose_binding_enforced', False),
    'Unawareness': lambda a: a.properties.get('consent_capture_documented', False),
    'Non_Compliance': lambda a: a.properties.get('pdpa_obligation_evidence', False)
                              and a.properties.get('psga_im8_evidence', False),
}
def evaluate_linddun(asset: Asset) -> Dict[str, str]:
    return {threat: 'MITIGATED' if rule(asset) else 'OPEN'
            for threat, rule in LINDDUN_RULES.items()}

# Property dependencies per threat category, used only to report which
# specific property caused an OPEN finding. Does not affect evaluation.
LINDDUN_DEPENDENCIES = {
    'Linkability': ['quasi_identifier_review', 'k_anonymity_threshold'],
    'Identifiability': ['pseudonymisation_applied'],
    'Non_Repudiation': ['membership_inference_defence'],
    'Detectability': ['output_noise_calibrated'],
    'Disclosure_of_Information': ['purpose_binding_enforced'],
    'Unawareness': ['consent_capture_documented'],
    'Non_Compliance': ['pdpa_obligation_evidence', 'psga_im8_evidence'],
}

def linddun_root_cause(asset: Asset, threat: str) -> str:
    """Returns the property/properties responsible for an OPEN finding.
    Only meaningful when OPEN."""
    causes = []
    for p in LINDDUN_DEPENDENCIES[threat]:
        if p == 'k_anonymity_threshold':
            value = asset.properties.get('k_anonymity_threshold', 0)
            if value < 5:
                causes.append(f'k_anonymity_threshold={value} (below required 5)')
        elif not asset.properties.get(p, False):
            causes.append(f'{p}=False')
    return '; '.join(causes)
if __name__ == "__main__":
    # Example execution against the HEALIX training repository
    healix_repo = Asset(
        name='healix_training_repository',
        asset_type='DATA_STORE',
        properties={'quasi_identifier_review': True, 'k_anonymity_threshold': 5,
                    'pseudonymisation_applied': True,
                    'membership_inference_defence': False,
                    'output_noise_calibrated': False, 'purpose_binding_enforced': True,
                    'consent_capture_documented': True,
                    'pdpa_obligation_evidence': True,
                    'psga_im8_evidence': True})
    print(evaluate_linddun(healix_repo))
    # Expected: Non_Repudiation and Detectability: OPEN; all others MITIGATED
