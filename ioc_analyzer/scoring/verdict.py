"""Расчёт итогового вердикта и risk score.

Философия скоринга — то, о чём стоит думать дольше всего:

* **Считаем детекты, а не доверяем одному движку.** Один сработавший
  антивирус из 70 — это почти всегда false positive (эвристика, PUA,
  «подозрительная упаковка»). Порог по умолчанию — 3 детекта.
* **Отсутствие данных ≠ чистота.** Если VT не ответил (сеть, лимит) —
  вердикт ``ERROR``. Если ответил «не знаю такого» — ``UNKNOWN``. Выдавать
  в этих случаях ``CLEAN`` означало бы скрыть от аналитика реальный риск.
* **Каждый вердикт объясним.** В ``reasons`` пишем, почему решение именно
  такое. Аналитик, который не понимает, откуда взялся вердикт, не будет
  доверять инструменту — и правильно сделает.
* **Пороги — конфигурация, а не константы в коде.** У разных команд разная
  толерантность к FP; меняется в .env без правки исходников.
"""

from __future__ import annotations

from ..config import Settings
from ..logging_setup import get_logger
from ..models import (
    IOC,
    AnalysisResult,
    EnrichmentResult,
    EnrichmentStatus,
    Verdict,
)

logger = get_logger("scoring.verdict")

# Веса risk score (0..100). Подобраны так, чтобы 3 детекта уже давали ~45,
# а 8+ детектов уверенно упирались в 90+.
_WEIGHT_MALICIOUS = 12
_WEIGHT_SUSPICIOUS = 4
_WEIGHT_BAD_REPUTATION = 15
_WEIGHT_RATIO = 40          # доля детектов от общего числа движков
_SCORE_UNKNOWN = 25         # «неизвестно» — это не ноль риска
_SCORE_ERROR = 20           # «не смогли проверить» — тоже не ноль

# Нижняя граница score для каждого вердикта. Нужна, чтобы score и вердикт
# не противоречили друг другу: индикатор с одним детектом набирает всего
# ~13 баллов по весам, но он уже SUSPICIOUS и обязан стоять в очереди
# триажа выше, чем «VirusTotal о нём не знает».
_SCORE_FLOOR: dict[str, int] = {
    Verdict.MALICIOUS.value: 60,
    Verdict.SUSPICIOUS.value: 30,
}


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return int(max(low, min(high, round(value))))


def calculate_risk_score(enrichment: EnrichmentResult, settings: Settings) -> int:
    """Числовая оценка риска 0..100 для сортировки и триажа.

    Вердикт отвечает на вопрос «что делать», а score — «в каком порядке
    разбирать». Две сущности намеренно разделены: 5/70 и 55/70 дают один
    вердикт MALICIOUS, но очень разный приоритет.
    """
    if enrichment.status is EnrichmentStatus.NOT_FOUND:
        return _SCORE_UNKNOWN
    if not enrichment.has_data:
        return _SCORE_ERROR

    score = 0.0
    score += enrichment.malicious * _WEIGHT_MALICIOUS
    score += enrichment.suspicious * _WEIGHT_SUSPICIOUS

    if enrichment.total_engines:
        ratio = enrichment.malicious / enrichment.total_engines
        score += ratio * _WEIGHT_RATIO

    if enrichment.reputation < settings.reputation_floor:
        score += _WEIGHT_BAD_REPUTATION
    elif enrichment.reputation > 0 and enrichment.malicious == 0:
        # Хорошая репутация у чистого индикатора немного снижает риск.
        score -= 5

    return _clamp(score)


def calculate_verdict(
    ioc: IOC,
    enrichment: EnrichmentResult | None,
    settings: Settings,
) -> AnalysisResult:
    """Собрать итог по индикатору: вердикт + score + человекочитаемые причины."""
    result = AnalysisResult(ioc=ioc, enrichment=enrichment)

    # --- обогащения не было вовсе (--offline) -------------------------------
    if enrichment is None:
        result.verdict = Verdict.SKIPPED
        result.risk_score = 0
        result.reasons.append("Обогащение не выполнялось (режим --offline)")
        return result

    # --- провайдер не умеет работать с таким типом --------------------------
    if enrichment.status is EnrichmentStatus.UNSUPPORTED:
        result.verdict = Verdict.SKIPPED
        result.risk_score = 0
        result.reasons.append(enrichment.error or "Тип IOC не поддерживается провайдером")
        return result

    # --- техническая ошибка: НЕ выдаём CLEAN --------------------------------
    if enrichment.status in {
        EnrichmentStatus.RATE_LIMITED,
        EnrichmentStatus.AUTH_ERROR,
        EnrichmentStatus.NETWORK_ERROR,
        EnrichmentStatus.API_ERROR,
        EnrichmentStatus.SKIPPED,
    }:
        result.verdict = Verdict.ERROR
        result.risk_score = _SCORE_ERROR
        result.reasons.append(
            f"Не удалось получить данные ({enrichment.status.value}): "
            f"{enrichment.error or 'причина неизвестна'}. "
            "Требуется ручная проверка."
        )
        return result

    # --- VT не знает такой индикатор ----------------------------------------
    if enrichment.status is EnrichmentStatus.NOT_FOUND:
        result.verdict = Verdict.UNKNOWN
        result.risk_score = _SCORE_UNKNOWN
        result.reasons.append(
            "Индикатор отсутствует в базе VirusTotal. Для свежесозданной "
            "инфраструктуры это ожидаемо и само по себе подозрительно."
        )
        return result

    # --- есть данные: считаем ------------------------------------------------
    result.risk_score = calculate_risk_score(enrichment, settings)
    malicious = enrichment.malicious
    suspicious = enrichment.suspicious

    if malicious >= settings.malicious_threshold:
        result.verdict = Verdict.MALICIOUS
        result.reasons.append(
            f"{malicious} антивирусных движка(ов) из {enrichment.total_engines} "
            f"классифицировали индикатор как вредоносный "
            f"(порог: {settings.malicious_threshold})"
        )
    elif malicious > 0 or suspicious >= settings.suspicious_threshold:
        result.verdict = Verdict.SUSPICIOUS
        if malicious:
            result.reasons.append(
                f"Детектов мало ({malicious} < порога {settings.malicious_threshold}), "
                "но они есть — возможен false positive, нужна проверка аналитиком"
            )
        if suspicious >= settings.suspicious_threshold:
            result.reasons.append(
                f"{suspicious} движка(ов) отметили индикатор как подозрительный"
            )
    elif enrichment.reputation < settings.reputation_floor:
        result.verdict = Verdict.SUSPICIOUS
        result.reasons.append(
            f"Детектов нет, но репутация сообщества VT крайне низкая "
            f"({enrichment.reputation} < {settings.reputation_floor})"
        )
    else:
        result.verdict = Verdict.CLEAN
        result.reasons.append(
            f"Детектов нет ({enrichment.detection_ratio}), "
            f"репутация {enrichment.reputation}"
        )

    # --- уточняющий контекст -------------------------------------------------
    if enrichment.detection_names:
        preview = ", ".join(enrichment.detection_names[:3])
        result.reasons.append(f"Названия детектов: {preview}")
    if enrichment.reputation < settings.reputation_floor and result.verdict is Verdict.MALICIOUS:
        result.reasons.append(f"Низкая репутация сообщества: {enrichment.reputation}")
    if ioc.occurrences > 1:
        result.reasons.append(
            f"Индикатор встречается во входных данных {ioc.occurrences} раз(а)"
        )
    if enrichment.from_cache:
        result.reasons.append("Данные получены из локального кеша")

    # Согласование: score не может быть ниже пола, заданного вердиктом.
    floor = _SCORE_FLOOR.get(result.verdict.value)
    if floor is not None and result.risk_score < floor:
        result.risk_score = floor

    logger.debug("Вердикт для %s: %s (score=%d)",
                 ioc.value, result.verdict.value, result.risk_score)
    return result
