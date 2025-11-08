import json
import random
from itertools import combinations
from .models import Tournament, TournamentPlayer, Match, MatchResult, Round

# --- WotC recommended Swiss rounds (approx per player count) ---
def recommended_rounds(n_players: int) -> int:
    if n_players <= 8: return 3
    if n_players <= 16: return 4
    if n_players <= 32: return 5
    if n_players <= 64: return 6
    if n_players <= 128: return 7
    if n_players <= 226: return 8
    if n_players <= 409: return 9
    return 10  # fallback

def player_points(tp: TournamentPlayer, session) -> int:
    # Recompute points from matches
    points = 0
    t = tp.tournament
    if t.format.lower() == 'commander':
        cfg = [int(x) for x in t.commander_points.split(',')]
        for m in matches_for(tp, session):
            if not m.completed or not m.result:
                continue
            r = m.result
            if r.is_draw:
                pts = cfg[4] if len(cfg) > 4 else 1
                points += pts
                continue
            place = None
            if m.player1_id == tp.id:
                place = r.p1_place
            elif m.player2_id == tp.id:
                place = r.p2_place
            elif m.player3_id == tp.id:
                place = r.p3_place
            elif m.player4_id == tp.id:
                place = r.p4_place
            if place and 1 <= place <= 4:
                points += cfg[place-1]
        return points
    for m in matches_for(tp, session):
        if not m.completed or not m.result:
            continue
        p1 = (m.player1_id == tp.id)
        if m.player2_id is None:
            # Bye = win (3 points)
            points += 3
            continue
        r = m.result
        if r.player1_wins > r.player2_wins:
            if p1: points += 3
        elif r.player2_wins > r.player1_wins:
            if not p1: points += 3
        else:
            points += 1  # draws give 1 to each
    return points

def matches_for(tp: TournamentPlayer, session):
    return session.query(Match).join(Round).filter(Round.tournament_id==tp.tournament_id).filter(
        (Match.player1_id == tp.id) | (Match.player2_id == tp.id) |
        (Match.player3_id == tp.id) | (Match.player4_id == tp.id)
    ).all()

def have_played(a_id, b_id, session):
    if a_id == b_id:
        return True
    q = session.query(Match).filter(
        ((Match.player1_id==a_id) | (Match.player2_id==a_id) | (Match.player3_id==a_id) | (Match.player4_id==a_id)) &
        ((Match.player1_id==b_id) | (Match.player2_id==b_id) | (Match.player3_id==b_id) | (Match.player4_id==b_id))
    )
    return session.query(q.exists()).scalar()

def _group_conflicts(group, session):
    if len(group) < 2:
        return 0
    return sum(1 for a, b in combinations(group, 2) if have_played(a.id, b.id, session))


def _build_pods(players, group_size, session):
    def helper(remaining):
        if not remaining:
            return 0, []
        if len(remaining) <= group_size:
            group = remaining[:]
            return _group_conflicts(group, session), [group]

        first = remaining[0]
        rest = remaining[1:]
        pick = group_size - 1
        limit = len(rest)
        if group_size > 2:
            limit = min(limit, group_size * 3)
        idx_pool = list(range(limit))
        best = None
        for combo in combinations(idx_pool, pick):
            group = [first] + [rest[i] for i in combo]
            conflicts = _group_conflicts(group, session)
            selected = set(combo)
            new_remaining = [rest[i] for i in range(len(rest)) if i not in selected]
            result = helper(new_remaining)
            if result is None:
                continue
            total_conflicts = conflicts + result[0]
            grouping = [group] + result[1]
            if best is None or total_conflicts < best[0]:
                best = (total_conflicts, grouping)
                if total_conflicts == 0:
                    break
        return best

    total = helper(players)
    if total is None:
        return [players[i:i+group_size] for i in range(0, len(players), group_size)]
    return total[1]


def swiss_pair_round(t: Tournament, r: Round, session):
    players = session.query(TournamentPlayer).filter_by(tournament_id=t.id, dropped=False).all()
    group_size = 4 if t.format.lower() == 'commander' else 2
    if r.number == 1:
        random.shuffle(players)
        table = t.start_table_number or 1
        created = []
        i = 0
        while i < len(players):
            pod = players[i:i+group_size]
            m = Match(round_id=r.id, table_number=table,
                      player1_id=pod[0].id,
                      player2_id=pod[1].id if len(pod) > 1 else None,
                      player3_id=pod[2].id if len(pod) > 2 else None,
                      player4_id=pod[3].id if len(pod) > 3 else None)
            session.add(m)
            created.append(m)
            table += 1
            i += group_size
        session.commit()
        return created
    # Build ordering using match points and standard tie breakers
    standings = compute_standings(t, session)
    rank = {row['tp'].id: (
        row['points'], row['omw'], row['gw'], row['ogw'], row['player'].lower()
    ) for row in standings}
    players.sort(
        key=lambda tp: (
            -rank[tp.id][0], -rank[tp.id][1], -rank[tp.id][2], -rank[tp.id][3], rank[tp.id][4]
        )
    )
    pods = _build_pods(players, group_size, session)
    table = t.start_table_number or 1
    created = []
    for pod in pods:
        if not pod:
            continue
        m = Match(round_id=r.id, table_number=table,
                  player1_id=pod[0].id,
                  player2_id=pod[1].id if len(pod) > 1 else None,
                  player3_id=pod[2].id if len(pod) > 2 else None,
                  player4_id=pod[3].id if len(pod) > 3 else None)
        session.add(m)
        created.append(m)
        table += 1
    session.commit()
    return created


def _load_pairing_state(t: Tournament):
    try:
        return json.loads(t.pairing_options or '{}')
    except Exception:
        return {}


def _save_pairing_state(t: Tournament, state, session):
    t.pairing_options = json.dumps(state)
    session.add(t)


def _normalize_round_robin_order(order_ids, active_ids):
    present = [pid for pid in order_ids if pid in active_ids]
    missing = [pid for pid in active_ids if pid not in present]
    if missing:
        random.shuffle(missing)
        present.extend(missing)
    return present


def _round_robin_pairs(order_ids, round_index):
    players = list(order_ids)
    if not players:
        return []
    if len(players) % 2 == 1:
        players.append(None)
    total = len(players)
    working = players
    for _ in range(round_index % (total - 1 if total > 1 else 1)):
        working = [working[0]] + [working[-1]] + working[1:-1]
    pairs = []
    half = total // 2
    for i in range(half):
        a = working[i]
        b = working[-1 - i]
        pairs.append((a, b))
    return pairs


def round_robin_pair_round(t: Tournament, r: Round, session):
    players = session.query(TournamentPlayer).filter_by(tournament_id=t.id, dropped=False).all()
    if not players:
        return []
    if t.format and t.format.lower() == 'commander':
        # Commander pods use groups of four; reuse Swiss logic for now.
        return swiss_pair_round(t, r, session)
    state = _load_pairing_state(t)
    order_ids = state.get('round_robin_order') or []
    active_ids = [tp.id for tp in players]
    if not order_ids:
        order_ids = active_ids[:]
        random.shuffle(order_ids)
    else:
        order_ids = _normalize_round_robin_order(order_ids, active_ids)
    state['round_robin_order'] = order_ids
    _save_pairing_state(t, state, session)
    round_index = max(r.number - 1, 0)
    pair_ids = _round_robin_pairs(order_ids, round_index)
    table = t.start_table_number or 1
    created = []
    for pid1, pid2 in pair_ids:
        if pid1 is None and pid2 is None:
            continue
        if pid1 is None or pid2 is None:
            bye_player = pid1 or pid2
            m = Match(round_id=r.id, table_number=table, player1_id=bye_player, player2_id=None)
        else:
            if random.random() < 0.5:
                pid1, pid2 = pid2, pid1
            m = Match(round_id=r.id, table_number=table, player1_id=pid1, player2_id=pid2)
        session.add(m)
        created.append(m)
        table += 1
    session.commit()
    return created


def pair_round(t: Tournament, r: Round, session):
    pairing_type = (t.pairing_type or 'swiss').lower()
    if pairing_type == 'round_robin':
        return round_robin_pair_round(t, r, session)
    return swiss_pair_round(t, r, session)

# --- Tiebreakers per MTR (simplified) ---
# OMW%: average of each opponent's match-win %, floored at 33%
# GW%: player's game-win % (wins / (wins+losses+draws/2)), floored at 33%
# OGW%: average of opponents' game-win %, floored at 33%

def compute_standings(t: Tournament, session):
    if t.format.lower() == 'commander':
        return _compute_commander_standings(t, session)
    tps = session.query(TournamentPlayer).filter_by(tournament_id=t.id).all()

    # Build opponent lists and match/game counts
    opps = {tp.id: [] for tp in tps}
    match_points = {tp.id: 0 for tp in tps}
    game_wins = {tp.id: 0 for tp in tps}
    game_losses = {tp.id: 0 for tp in tps}
    game_draws = {tp.id: 0 for tp in tps}

    matches = session.query(Match).join(Round).filter(Round.tournament_id==t.id).all()
    for m in matches:
        if m.player2_id is None:  # bye -> counts as opponent with 33% for OMW/OGW via rules; we model as no opp
            # Assign 3 points and 2-0-0 games already stored if completed
            if m.completed and m.result:
                match_points[m.player1_id] += 3
                game_wins[m.player1_id] += m.result.player1_wins
                game_losses[m.player1_id] += m.result.player2_wins
                game_draws[m.player1_id] += m.result.draws
            continue
        # Record opponents
        opps[m.player1_id].append(m.player2_id)
        opps[m.player2_id].append(m.player1_id)
        if m.completed and m.result:
            r = m.result
            # Points
            if r.player1_wins > r.player2_wins:
                match_points[m.player1_id] += 3
            elif r.player2_wins > r.player1_wins:
                match_points[m.player2_id] += 3
            else:
                match_points[m.player1_id] += 1
                match_points[m.player2_id] += 1
            # Games
            game_wins[m.player1_id] += r.player1_wins
            game_losses[m.player1_id] += r.player2_wins
            game_draws[m.player1_id] += r.draws
            game_wins[m.player2_id] += r.player2_wins
            game_losses[m.player2_id] += r.player1_wins
            game_draws[m.player2_id] += r.draws

    def match_win_pct(tp_id):
        # Each match win = 3 points; denominator is 3 * matches played (excluding byes in OMW calc)
        # For player's own GW%/MW% we include all matches (including byes for match-win; WotC uses 3/3=1 for bye)
        total_matches = 0
        total_points = 0
        for m in matches:
            if m.player2_id is None:
                if m.player1_id == tp_id:
                    total_matches += 1
                    if m.completed:
                        total_points += 3
                continue
            if m.player1_id == tp_id or m.player2_id == tp_id:
                total_matches += 1
                if m.completed and m.result:
                    r = m.result
                    if r.player1_wins > r.player2_wins and m.player1_id == tp_id:
                        total_points += 3
                    elif r.player2_wins > r.player1_wins and m.player2_id == tp_id:
                        total_points += 3
                    elif r.player1_wins == r.player2_wins:
                        total_points += 1
        if total_matches == 0:
            return 0.0
        return total_points / (3.0 * total_matches)

    def game_win_pct(tp_id):
        gw = game_wins[tp_id]; gl = game_losses[tp_id]; gd = game_draws[tp_id]
        denom = gw + gl + gd * 0.5
        if denom <= 0: return 0.0
        return gw / denom

    # floor function to 33% minimum
    def floor33(x): return max(x, 0.33)

    mw_cache = {tp.id: match_win_pct(tp.id) for tp in tps}
    gw_cache = {tp.id: game_win_pct(tp.id) for tp in tps}

    omw = {}
    ogw = {}
    for tp in tps:
        opp_list = opps[tp.id]
        if not opp_list:
            omw[tp.id] = 0.33
            ogw[tp.id] = 0.33
        else:
            omw_vals = [floor33(mw_cache[o]) for o in opp_list]
            ogw_vals = [floor33(gw_cache[o]) for o in opp_list]
            omw[tp.id] = sum(omw_vals) / len(omw_vals)
            ogw[tp.id] = sum(ogw_vals) / len(ogw_vals)

    # Prepare rows
    rows = []
    for tp in tps:
        rows.append({
            'tp': tp,
            'player': tp.user.name,
            'points': match_points[tp.id],
            'mw': mw_cache[tp.id],
            'gw': gw_cache[tp.id],
            'omw': omw[tp.id],
            'ogw': ogw[tp.id],
        })
    # Sort: points desc, OMW desc, GW desc, OGW desc, name
    rows.sort(key=lambda r: (-r['points'], -r['omw'], -r['gw'], -r['ogw'], r['player'].lower()))
    return rows


def _compute_commander_standings(t: Tournament, session):
    tps = session.query(TournamentPlayer).filter_by(tournament_id=t.id).all()
    cfg = [int(x) for x in t.commander_points.split(',')]
    opps = {tp.id: [] for tp in tps}
    match_points = {tp.id: 0 for tp in tps}
    wins = {tp.id: 0 for tp in tps}
    draws = {tp.id: 0 for tp in tps}
    total = {tp.id: 0 for tp in tps}

    matches = session.query(Match).join(Round).filter(Round.tournament_id==t.id).all()
    for m in matches:
        players = [m.player1_id, m.player2_id, m.player3_id, m.player4_id]
        players = [pid for pid in players if pid]
        for pid in players:
            opps[pid].extend([o for o in players if o != pid])
            total[pid] += 1
        if not m.completed or not m.result:
            continue
        r = m.result
        if r.is_draw:
            pts = cfg[4] if len(cfg) > 4 else 1
            for pid in players:
                match_points[pid] += pts
                draws[pid] += 1
            continue
        placements = [
            (m.player1_id, r.p1_place),
            (m.player2_id, r.p2_place),
            (m.player3_id, r.p3_place),
            (m.player4_id, r.p4_place),
        ]
        for pid, place in placements:
            if pid and place and 1 <= place <= 4:
                match_points[pid] += cfg[place-1]
                if place == 1:
                    wins[pid] += 1

    def floor33(x):
        return max(x, 0.33)

    mw_cache = {}
    for pid in match_points.keys():
        if total[pid] == 0:
            mw_cache[pid] = 0.0
        else:
            mw_cache[pid] = (wins[pid] + draws[pid] * 0.5) / total[pid]
    gw_cache = mw_cache.copy()

    omw = {}
    ogw = {}
    for pid in match_points.keys():
        opp_list = opps[pid]
        if not opp_list:
            omw[pid] = 0.33
            ogw[pid] = 0.33
        else:
            omw_vals = [floor33(mw_cache[o]) for o in opp_list]
            ogw_vals = [floor33(gw_cache[o]) for o in opp_list]
            omw[pid] = sum(omw_vals) / len(omw_vals)
            ogw[pid] = sum(ogw_vals) / len(ogw_vals)

    rows = [{
        'tp': tp,
        'player': tp.user.name,
        'points': match_points[tp.id],
        'mw': mw_cache[tp.id],
        'gw': gw_cache[tp.id],
        'omw': omw[tp.id],
        'ogw': ogw[tp.id],
    } for tp in tps]
    rows.sort(key=lambda r: (-r['points'], -r['omw'], -r['gw'], -r['ogw'], r['player'].lower()))
    return rows
