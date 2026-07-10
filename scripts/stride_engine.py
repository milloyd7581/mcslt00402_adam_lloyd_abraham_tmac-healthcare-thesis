# stride_engine.py - illustrative proof of concept
from dataclasses import dataclass
from typing import Dict, Any
@dataclass
class Asset:
    name: str
    asset_type: str
    properties: Dict[str, Any]
STRIDE_RULES = {
    'Spoofing': lambda a: a.properties.get('mfa_enforced', False),
    'Tampering': lambda a: a.properties.get('integrity_signed', False),
    'Repudiation': lambda a: a.properties.get('audit_logging', False),
    'Information_Disclosure': lambda a: a.properties.get('encryption_in_transit', False)
                              and a.properties.get('encryption_at_rest', False),
    'Denial_of_Service': lambda a: a.properties.get('rate_limit_configured', False)
                              and a.properties.get('redundancy_zone', False),
    'Elevation_of_Privilege': lambda a: a.properties.get('least_privilege_iam', False),
}
def evaluate_stride(asset: Asset) -> Dict[str, str]:
    return {threat: 'MITIGATED' if rule(asset) else 'OPEN'
            for threat, rule in STRIDE_RULES.items()}

# Property dependencies per threat category, used only to report which
# specific property caused an OPEN finding. Does not affect evaluation.
STRIDE_DEPENDENCIES = {
    'Spoofing': ['mfa_enforced'],
    'Tampering': ['integrity_signed'],
    'Repudiation': ['audit_logging'],
    'Information_Disclosure': ['encryption_in_transit', 'encryption_at_rest'],
    'Denial_of_Service': ['rate_limit_configured', 'redundancy_zone'],
    'Elevation_of_Privilege': ['least_privilege_iam'],
}

def stride_root_cause(asset: Asset, threat: str) -> str:
    """Returns the property/properties responsible for an OPEN finding,
    e.g. 'rate_limit_configured=False'. Only meaningful when OPEN."""
    causes = [f'{p}=False' for p in STRIDE_DEPENDENCIES[threat]
              if not asset.properties.get(p, False)]
    return '; '.join(causes)
if __name__ == "__main__":
    # Example execution against a HEALIX inference endpoint
    healix_endpoint = Asset(
        name='healix_inference_api',
        asset_type='LLM_API',
        properties={'mfa_enforced': True, 'integrity_signed': True,
                    'audit_logging': True, 'encryption_in_transit': True,
                    'encryption_at_rest': True, 'rate_limit_configured': False,
                    'redundancy_zone': True, 'least_privilege_iam': True})
    print(evaluate_stride(healix_endpoint))
    # Expected: Denial_of_Service: OPEN (rate limit missing); all others MITIGATED
