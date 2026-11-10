from typing import Dict, Any

def score_severity(event: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Compute severity score (0-100) and classification based on event properties.
    Formula:
      severity = base_confidence * persistence_factor * actor_multiplier * criticality_weight * 50
    """
    base_confidence = float(event.get('confidence', 0.6))
    context = context or {}
    duration = context.get('duration_seconds', 1.0)
    num_actors = context.get('num_actors', 1)
    event_type = event.get('type', 'unknown')

    persistence_factor = min(1.0 + duration / 10.0, 2.0)
    actor_multiplier = 1.0 + 0.15 * max(0, num_actors - 1)

    criticality_weights = {
        'violence_detected': 2.0,
        'attack_detected': 2.0,
        'fight_detected': 2.0,
        'fall_detected': 1.8,
        'intrusion_detected': 1.7,
        'theft_detected': 1.6,
        'suspicious_proximity': 1.2,
        'line_crossing': 1.3,
        'unknown': 1.0
    }
    crit_weight = criticality_weights.get(event_type, 1.2)

    raw_score = base_confidence * persistence_factor * actor_multiplier * crit_weight
    severity_score = min(int(raw_score * 50), 100)

    if severity_score < 35:
        label = 'low'
    elif severity_score < 65:
        label = 'medium'
    elif severity_score < 85:
        label = 'high'
    else:
        label = 'critical'

    return {
        'score': severity_score,
        'label': label,
        'components': {
            'base_confidence': round(base_confidence, 2),
            'persistence_factor': round(persistence_factor, 2),
            'actor_multiplier': round(actor_multiplier, 2),
            'criticality_weight': crit_weight
        }
    }

