from dataclasses import dataclass
from .sections import SECTIONS, SECTION_WEIGHTS, SectionSpec
from .extractors import extract_field

_OVERLAP_COEFFICIENT_SECTIONS = {'registry', 'file', 'process', 'modules', 'sync'}


@dataclass
class SectionResult:
    section: str
    score: float
    weight: float
    metric: str
    set_a_size: int
    set_b_size: int
    intersection_size: int


@dataclass
class SimilarityResult:
    final_score: float
    section_scores: list[SectionResult]

    def breakdown(self) -> dict[str, float]:
        return {r.section: round(r.score, 4) for r in self.section_scores}


class BehavioralSimilarity:
    """Compare two VirusTotal PE behavioral report attribute dicts.

    Usage:
        scorer = BehavioralSimilarity()
        result = scorer.compare(report_a, report_b)
        print(result.final_score)
        print(result.breakdown())
    """

    def compare(self, report_a: dict, report_b: dict) -> SimilarityResult:
        section_results = []

        for section_name, spec in SECTIONS.items():
            use_oc = section_name in _OVERLAP_COEFFICIENT_SECTIONS
            score, size_a, size_b, isect = self._compare_section(
                report_a, report_b, spec, use_overlap_coefficient=use_oc
            )
            weight = SECTION_WEIGHTS[section_name]
            section_results.append(SectionResult(
                section=section_name,
                score=score,
                weight=weight,
                metric='overlap' if use_oc else 'jaccard',
                set_a_size=size_a,
                set_b_size=size_b,
                intersection_size=isect,
            ))

        active = [r for r in section_results if r.set_a_size > 0 or r.set_b_size > 0]
        if not active:
            final_score = 1.0
        else:
            total_weight = sum(r.weight for r in active)
            final_score = sum(r.weight * r.score for r in active) / total_weight

        return SimilarityResult(
            final_score=round(final_score, 6),
            section_scores=section_results,
        )

    def _compare_section(
        self,
        report_a: dict,
        report_b: dict,
        spec: SectionSpec,
        use_overlap_coefficient: bool = False,
    ) -> tuple[float, int, int, int]:
        set_a = self._extract_section_set(report_a, spec)
        set_b = self._extract_section_set(report_b, spec)
        if use_overlap_coefficient:
            score = self._overlap_coefficient(set_a, set_b)
        else:
            score = self._jaccard(set_a, set_b)
        return score, len(set_a), len(set_b), len(set_a & set_b)

    @staticmethod
    def _extract_section_set(report: dict, spec: SectionSpec) -> set[str]:
        result: set[str] = set()
        for field_name in spec.fields:
            values = report.get(field_name) or []
            if not isinstance(values, list):
                continue
            result.update(extract_field(field_name, values))
        return result

    @staticmethod
    def _jaccard(set_a: set, set_b: set) -> float:
        if not set_a and not set_b:
            return 1.0
        if not set_a or not set_b:
            return 0.0
        return len(set_a & set_b) / len(set_a | set_b)

    @staticmethod
    def _overlap_coefficient(set_a: set, set_b: set) -> float:
        if not set_a and not set_b:
            return 1.0
        if not set_a or not set_b:
            return 0.0
        return len(set_a & set_b) / min(len(set_a), len(set_b))
