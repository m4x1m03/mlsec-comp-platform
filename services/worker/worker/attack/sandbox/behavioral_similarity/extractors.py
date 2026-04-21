from typing import Any
from .normalizers import normalize_path, normalize_registry, normalize_string, normalize_url


def _tls_key(obj: dict) -> set[str]:
    if obj.get('sni'):
        return {normalize_string(obj['sni'])}
    if obj.get('thumbprint'):
        return {normalize_string(obj['thumbprint'])}
    if obj.get('subject'):
        return {normalize_string(str(obj['subject']))}
    return set()


OBJECT_EXTRACTORS: dict[str, Any] = {
    'processes_tree': lambda o: ({normalize_string(o['name'])} - {''}) if o.get('name') else set(),
    'files_dropped':  lambda o: ({normalize_path(o['path'])} - {''}) if o.get('path') else set(),
    'files_copied':   lambda o: {normalize_path(o.get('source', '')), normalize_path(o.get('destination', ''))} - {''},
    'registry_keys_set': lambda o: ({normalize_registry(o['key'])} - {''}) if o.get('key') else set(),
    'ip_traffic': lambda o: (
        {f"{o['destination_ip']}:{o['destination_port']}"}
        if o.get('destination_ip') and o.get('destination_port') is not None
        else set()
    ),
    'http_conversations': lambda o: (
        {f"{normalize_string(o.get('request_method', ''))} {normalize_url(o.get('url', ''))}".strip()} - {''}
    ),
    'tls': _tls_key,
    'mitre_attack_techniques': lambda o: (
        ({o['id'].upper()} - {''})
        if o.get('id') and o.get('severity', '').upper() not in ('IMPACT_SEVERITY_INFO', 'INFO')
        else set()
    ),
    'sigma_analysis_results':  lambda o: ({normalize_string(o['rule_id'])} - {''}) if o.get('rule_id') else set(),
    'ids_alerts':              lambda o: ({normalize_string(o['rule_id'])} - {''}) if o.get('rule_id') else set(),
    'signature_matches':       lambda o: ({normalize_string(o['name'])} - {''}) if o.get('name') else set(),
}


def _field_normalizer(field_name: str):
    if 'file' in field_name or field_name == 'modules_loaded':
        return normalize_path
    if 'registry' in field_name:
        return normalize_registry
    return normalize_string


def extract_field(field_name: str, values: list) -> set[str]:
    if not values:
        return set()
    if field_name in OBJECT_EXTRACTORS:
        result: set[str] = set()
        for obj in values:
            if isinstance(obj, dict):
                result.update(OBJECT_EXTRACTORS[field_name](obj))
        return result
    normalizer = _field_normalizer(field_name)
    result = set()
    for item in values:
        v = normalizer(item) if isinstance(item, str) else normalize_string(item)
        if v:
            result.add(v)
    return result
