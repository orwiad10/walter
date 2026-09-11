import json
import random
import secrets
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

def have_played(a_id, b_id, session, *, up_to_round_number=None):
    if a_id == b_id:
        return True
    q = session.query(Match).join(Round, Match.round_id == Round.id).filter(
        ((Match.player1_id==a_id) | (Match.player2_id==a_id) | (Match.player3_id==a_id) | (Match.player4_id==a_id)) &
        ((Match.player1_id==b_id) | (Match.player2_id==b_id) | (Match.player3_id==b_id) | (Match.player4_id==b_id))
    )
    if up_to_round_number is not None:
        q = q.filter(Round.number <= up_to_round_number)
    return session.query(q.exists()).scalar()


def _round_limit_for_tournament(t: Tournament, player_count: int) -> int:
    if t.rounds_override:
        return t.rounds_override
    return recommended_rounds(player_count)


def _is_post_cut_round(t: Tournament, r: Round, player_count: int) -> bool:
    if t.structure == 'single_elim' or not (t.cut or '').startswith('top'):
        return False
    return r.number > _round_limit_for_tournament(t, player_count)


def _player_has_bye(tp_id: int, tournament_id: int, session) -> bool:
    q = session.query(Match).join(Round).filter(
        Round.tournament_id == tournament_id,
        (
            ((Match.player1_id == tp_id) & (Match.player2_id.is_(None))) |
            ((Match.player2_id == tp_id) & (Match.player1_id.is_(None)))
        )
    )
    return session.query(q.exists()).scalar()


def _select_swiss_bye_player(players, tournament_id: int, session):
    if len(players) % 2 == 0:
        return None
    for idx in range(len(players) - 1, -1, -1):
        if not _player_has_bye(players[idx].id, tournament_id, session):
            return players.pop(idx)
    return players.pop()

def _group_conflicts(group, session, *, up_to_round_number=None):
    if len(group) < 2:
        return 0
    return sum(1 for a, b in combinations(group, 2) if have_played(a.id, b.id, session, up_to_round_number=up_to_round_number))


def _build_pods(players, group_size, session, *, up_to_round_number=None, allow_repeat_pairings=True):
    def helper(remaining):
        if not remaining:
            return 0, []
        if len(remaining) <= group_size:
            group = remaining[:]
            return _group_conflicts(group, session, up_to_round_number=up_to_round_number), [group]

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
            conflicts = _group_conflicts(group, session, up_to_round_number=up_to_round_number)
            selected = set(combo)
            new_remaining = [rest[i] for i in range(len(rest)) if i not in selected]
            result = helper(new_remaining)
            if result is None:
                continue
            if not allow_repeat_pairings and conflicts > 0:
                continue
            total_conflicts = conflicts + result[0]
            grouping = [group] + result[1]
            if best is None or total_conflicts < best[0]:
                best = (total_conflicts, grouping)
                if total_conflicts == 0:
                    break
        if best is None and not allow_repeat_pairings:
            return None
        return best

    total = helper(players)
    if total is None:
        if not allow_repeat_pairings:
            raise ValueError('Unable to create non-repeating pairings before cut.')
        return [players[i:i+group_size] for i in range(0, len(players), group_size)]
    return total[1]


def pairing_order_from_standings(standings):
    """Rank players while randomizing only exact tiebreak regions."""
    buckets = {}
    for row in standings:
        key = (row['points'], row['omw'], row['gw'], row['ogw'])
        buckets.setdefault(key, []).append(row['tp'])
    ordered = []
    for key in sorted(buckets, reverse=True):
        tied = buckets[key]
        random.shuffle(tied)
        ordered.extend(tied)
    return ordered


def seeded_cut_pairs(seeds):
    return [(seeds[i], seeds[len(seeds) - 1 - i]) for i in range(len(seeds) // 2)]


def seeded_cut_pods(seeds, group_size=4):
    """Distribute high and low seeds into counter-seeded multiplayer pods."""
    pod_count = max(1, (len(seeds) + group_size - 1) // group_size)
    pods = [[] for _ in range(pod_count)]
    counter_pairs = seeded_cut_pairs(seeds)
    for index, pair in enumerate(counter_pairs):
        pods[index % pod_count].extend(pair)
    if len(seeds) % 2:
        pods[-1].append(seeds[len(seeds) // 2])
    return pods


def _balanced_draft_pod_sizes(player_count, table_size=8):
    """Return optional, admin-requested pod sizes without a 1--3 player pod.

    Small drafts are balanced across all of their pods.  In a large draft, only
    the final full pod is disturbed so that already-full pods stay together.
    """
    if not player_count:
        return []
    pod_count = (player_count + table_size - 1) // table_size
    remainder = player_count % table_size
    if not remainder or remainder >= 4 or pod_count == 1:
        return [table_size] * (pod_count - bool(remainder)) + ([remainder] if remainder else [])

    balanced_count = pod_count if pod_count <= 3 else 2
    fixed_count = pod_count - balanced_count
    players_to_balance = player_count - (fixed_count * table_size)
    small_size, extra = divmod(players_to_balance, balanced_count)
    balanced_sizes = ([small_size] * (balanced_count - extra)
                      + [small_size + 1] * extra)
    # With two affected pods, put the larger pod first to match the natural
    # seating order (for example, 8 + 3 becomes 6 + 5).
    if balanced_count == 2:
        balanced_sizes.reverse()
    return [table_size] * fixed_count + balanced_sizes


def _draft_seating_tables(t: Tournament, players, session, table_size=8, *, rebalance=False):
    state = _load_pairing_state(t)
    saved_tables = state.get('draft_seating') or []
    active_ids = [tp.id for tp in players]
    active_set = set(active_ids)
    player_by_id = {tp.id: tp for tp in players}

    seated_ids = []
    for table in saved_tables:
        for player_id in table:
            if player_id in active_set and player_id not in seated_ids:
                seated_ids.append(player_id)

    missing_ids = [player_id for player_id in active_ids if player_id not in seated_ids]
    if missing_ids:
        random.shuffle(missing_ids)
        seated_ids.extend(missing_ids)

    if rebalance:
        pod_sizes = _balanced_draft_pod_sizes(len(seated_ids), table_size)
    else:
        pod_sizes = [table_size] * (len(seated_ids) // table_size)
        if len(seated_ids) % table_size:
            pod_sizes.append(len(seated_ids) % table_size)

    tables = []
    offset = 0
    for pod_size in pod_sizes:
        tables.append(seated_ids[offset:offset + pod_size])
        offset += pod_size
    if tables != saved_tables:
        state['draft_seating'] = tables
        _save_pairing_state(t, state, session)

    return [[player_by_id[player_id] for player_id in table if player_id in player_by_id] for table in tables]


def draft_seating_tables(t: Tournament, session, *, include_dropped=True, rebalance=False):
    query = session.query(TournamentPlayer).filter_by(tournament_id=t.id)
    if not include_dropped:
        query = query.filter_by(dropped=False)
    return _draft_seating_tables(t, query.all(), session, rebalance=rebalance)


def _big_x_little_x_pairs(pod):
    if len(pod) <= 1:
        return [(pod[0], None)] if pod else []

    half = len(pod) // 2
    pairs = [(pod[i], pod[i + half]) for i in range(half)]
    if len(pod) % 2:
        pairs.append((pod[-1], None))
    return pairs


def _cross_pod_pairs(pods):
    """Pair across draft pods until only internal-pod pairing is possible."""
    remaining = [pod[:] for pod in pods]
    for pod in remaining:
        random.shuffle(pod)

    pairs = []
    while sum(bool(pod) for pod in remaining) >= 2:
        pod_indexes = [index for index, pod in enumerate(remaining) if pod]
        random.shuffle(pod_indexes)
        pod_indexes.sort(key=lambda index: len(remaining[index]), reverse=True)
        first_pod, second_pod = pod_indexes[:2]
        pairs.append((remaining[first_pod].pop(), remaining[second_pod].pop()))
    for pod in remaining:
        pairs.extend(_big_x_little_x_pairs(pod))
    return pairs


def _draft_round_one_pairs(t: Tournament, players, session):
    pods = _draft_seating_tables(t, players, session)
    return _cross_pod_pairs(pods) if len(pods) > 1 else _big_x_little_x_pairs(pods[0])


def _complete_bye(match, session):
    """Automatically record the standard 2-0 result for a two-player bye."""
    match.completed = True
    match.result = MatchResult(player1_wins=2, player2_wins=0, draws=0)
    session.add(match)


def swiss_pair_round(t: Tournament, r: Round, session):
    players = session.query(TournamentPlayer).filter_by(tournament_id=t.id, dropped=False).all()
    group_size = 4 if t.format.lower() == 'commander' else 2
    if r.number == 1:
        table = t.start_table_number or 1
        created = []
        limited_format = (t.format or '').lower()
        if limited_format in ('draft', 'sealed') and group_size == 2:
            pairings = _draft_round_one_pairs(t, players, session)
            for p1, p2 in pairings:
                m = Match(round_id=r.id, table_number=table,
                          player1_id=p1.id,
                          player2_id=p2.id if p2 else None)
                session.add(m)
                if p2 is None:
                    _complete_bye(m, session)
                created.append(m)
                table += 1
            session.commit()
            return created

        random.shuffle(players)
        i = 0
        while i < len(players):
            pod = players[i:i+group_size]
            m = Match(round_id=r.id, table_number=table,
                      player1_id=pod[0].id,
                      player2_id=pod[1].id if len(pod) > 1 else None,
                      player3_id=pod[2].id if len(pod) > 2 else None,
                      player4_id=pod[3].id if len(pod) > 3 else None)
            session.add(m)
            if len(pod) == 1 and group_size == 2:
                _complete_bye(m, session)
            created.append(m)
            table += 1
            i += group_size
        session.commit()
        return created
    # Build ordering using match points and standard tie breakers
    standings = compute_standings(t, session)
    active_ids = {player.id for player in players}
    players = [player for player in pairing_order_from_standings(standings) if player.id in active_ids]
    is_post_cut = _is_post_cut_round(t, r, len(players))
    if group_size == 2:
        bye_player = _select_swiss_bye_player(players, t.id, session)
    else:
        bye_player = None
    pods = _build_pods(
        players,
        group_size,
        session,
        up_to_round_number=r.number - 1,
        allow_repeat_pairings=is_post_cut
    )
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
        if len(pod) == 1 and group_size == 2:
            _complete_bye(m, session)
        created.append(m)
        table += 1
    if bye_player is not None:
        m = Match(round_id=r.id, table_number=table, player1_id=bye_player.id, player2_id=None)
        session.add(m)
        _complete_bye(m, session)
        created.append(m)
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


def reroll_pairing_randomness(t: Tournament, r: Round, session):
    """Discard persisted random choices that affect a round being re-paired."""
    state = _load_pairing_state(t)
    changed = False
    if (t.pairing_type or 'swiss').lower() == 'round_robin':
        changed = state.pop('round_robin_order', None) is not None
    if r.number == 1 and (t.format or '').lower() in ('draft', 'sealed'):
        changed = state.pop('draft_seating', None) is not None or changed
    if changed:
        _save_pairing_state(t, state, session)
        session.flush()


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
        raise ValueError('Commander tournaments do not support round-robin pairing.')
    if t.format and t.format.lower() in ('draft', 'sealed'):
        if r.number == 1:
            pairings = _draft_round_one_pairs(t, players, session)
        else:
            random.shuffle(players)
            pairings = _build_pods(players, 2, session, up_to_round_number=r.number - 1,
                                   allow_repeat_pairings=False)
        table = t.start_table_number or 1
        created = []
        for p1, p2 in pairings:
            match = Match(round_id=r.id, table_number=table, player1_id=p1.id,
                          player2_id=p2.id if p2 else None)
            session.add(match)
            if p2 is None:
                _complete_bye(match, session)
            created.append(match)
            table += 1
        session.commit()
        return created
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
            _complete_bye(m, session)
        else:
            if secrets.randbelow(2) == 0:
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


def create_manual_pairings(t, r, groups, session):
    """Create a complete, non-repeating hand pairing for an impossible round."""
    players = session.query(TournamentPlayer).filter_by(tournament_id=t.id, dropped=False).all()
    expected = {player.id for player in players}
    flat = [player_id for group in groups for player_id in group]
    if len(flat) != len(set(flat)) or set(flat) != expected:
        raise ValueError('Every active player must be assigned exactly once.')
    group_size = 4 if (t.format or '').lower() == 'commander' else 2
    if any(not group or len(group) > group_size for group in groups):
        raise ValueError(f'Pairings must contain between one and {group_size} players.')
    if sum(len(group) < group_size for group in groups) > 1:
        raise ValueError('Only one incomplete pairing is allowed.')
    for group in groups:
        for a, b in combinations(group, 2):
            if have_played(a, b, session, up_to_round_number=r.number - 1):
                raise ValueError('A hand pairing cannot repeat a prior opponent.')
    table = t.start_table_number or 1
    created = []
    for group in groups:
        match = Match(round_id=r.id, table_number=table,
                      player1_id=group[0],
                      player2_id=group[1] if len(group) > 1 else None,
                      player3_id=group[2] if len(group) > 2 else None,
                      player4_id=group[3] if len(group) > 3 else None)
        session.add(match)
        if len(group) == 1 and group_size == 2:
            _complete_bye(match, session)
        created.append(match)
        table += 1
    session.commit()
    return created


def elimination_pairing_order(t, players, session):
    """Order survivors by game record and opponent game-win percentage."""
    active = {player.id for player in players}
    rows = [row for row in compute_standings(t, session) if row['tp'].id in active]
    game_record = {player_id: [0, 0] for player_id in active}
    matches = session.query(Match).join(Round).filter(Round.tournament_id == t.id).all()
    for match in matches:
        if not match.completed or not match.result or match.player2_id is None:
            continue
        if match.player1_id in active:
            game_record[match.player1_id][0] += match.result.player1_wins
            game_record[match.player1_id][1] += match.result.player2_wins
        if match.player2_id in active:
            game_record[match.player2_id][0] += match.result.player2_wins
            game_record[match.player2_id][1] += match.result.player1_wins
    buckets = {}
    for row in rows:
        wins, losses = game_record[row['tp'].id]
        if (t.format or '').lower() == 'commander':
            key = (row['gw'], row['ogw'])
        else:
            key = (wins, -losses, row['ogw'])
        buckets.setdefault(key, []).append(row['tp'])
    ordered = []
    for key in sorted(buckets, reverse=True):
        tied = buckets[key]
        random.shuffle(tied)
        ordered.extend(tied)
    return ordered

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
