# ── Condition 1: 0.5 m line of sight ─────────────────────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 0.5m_los \
    --description "RPi on desk. Laptop 0.5 m away, direct line of sight, no obstacles between devices." \
    --trials 200

# ── Condition 2: 1 m line of sight ───────────────────────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 1m_los \
    --description "RPi on desk. Laptop 1 m away, direct line of sight, no obstacles between devices." \
    --trials 200

# ── Condition 3: 2 m line of sight ───────────────────────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 2m_los \
    --description "RPi on desk. Laptop 2 m away, direct line of sight, no obstacles between devices." \
    --trials 200

# ── Condition 4: 3 m line of sight ───────────────────────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 3m_los \
    --description "RPi on desk. Laptop 3 m away, direct line of sight, no obstacles between devices." \
    --trials 200

# ── Condition 5: 4 m line of sight ───────────────────────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 4m_los \
    --description "RPi on desk. Laptop 4 m away, direct line of sight, no obstacles between devices." \
    --trials 200

# ── Condition 6: 4 m with one wall ───────────────────────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 4m_wall \
    --description "RPi in one room. Laptop 4 m away in adjacent room, one standard interior wall between devices." \
    --trials 200


# ── Condition 7: 5–6 m with two walls ────────────────────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 6m_2wall \
    --description "RPi in one room. Laptop approx 6 m away, two standard interior walls between devices." \
    --trials 200

# ── Condition 8: 7 m with one wall (if reproducible) ─────────────────────────
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition 7m_wall \
    --description "RPi in one room. Laptop 7 m away in adjacent room, one standard interior wall between devices." \
    --trials 200


client/.venv/bin/python results/canonical/distance/run_J_steady.py \
    --address B8:27:EB:07:01:22 --condition 7m_wall \
    --description "RPi in one room. Laptop 7 m away in adjacent room, one standard interior wall between devices." \
    --trials 500