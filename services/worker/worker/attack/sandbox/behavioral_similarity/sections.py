from typing import NamedTuple


class SectionSpec(NamedTuple):
    fields: list[str]


SECTIONS: dict[str, SectionSpec] = {
    'threat': SectionSpec(fields=[
        'mitre_attack_techniques',
        'sigma_analysis_results',
        'ids_alerts',
        'signature_matches',
    ]),
    'network': SectionSpec(fields=[
        'ip_traffic',
        'http_conversations',
        'ja3_digests',
        'tls',
    ]),
    'registry': SectionSpec(fields=[
        'registry_keys_opened',
        'registry_keys_set',
        'registry_keys_deleted',
    ]),
    'file': SectionSpec(fields=[
        'files_opened',
        'files_written',
        'files_deleted',
        'files_attribute_changed',
        'files_dropped',
        'files_copied',
    ]),
    'process': SectionSpec(fields=[
        'command_executions',
        'processes_created',
        'processes_terminated',
        'processes_killed',
        'processes_injected',
        'processes_tree',
    ]),
    'crypto': SectionSpec(fields=[
        'crypto_algorithms_observed',
        'crypto_keys',
        'encoding_algorithms_observed',
    ]),
    'system_api': SectionSpec(fields=[
        'calls_highlighted',
        'invokes',
        'windows_searched',
        'windows_hidden',
        'tags',
        'verdicts',
    ]),
    'modules': SectionSpec(fields=[
        'modules_loaded',
    ]),
    'sync': SectionSpec(fields=[
        'mutexes_opened',
        'mutexes_created',
        'services_opened',
        'services_created',
        'services_started',
        'services_stopped',
        'services_deleted',
        'services_bound',
    ]),
}

SECTION_WEIGHTS: dict[str, float] = {
    'threat':     0.25,
    'network':    0.18,
    'registry':   0.14,
    'file':       0.12,
    'process':    0.10,
    'crypto':     0.08,
    'system_api': 0.06,
    'modules':    0.04,
    'sync':       0.03,
}

assert abs(sum(SECTION_WEIGHTS.values()) - 1.0) < 1e-9, 'Weights must sum to 1.0'
assert set(SECTION_WEIGHTS) == set(SECTIONS), 'Every section must have a weight'
