from collections import defaultdict
from .models import Tournament, TournamentPlayer, Match, MatchResult, Round
from .app import db

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
        (Match.player1_id == tp.id) | (Match.player2_id == tp.id)
    ).all()

def have_played(a_id, b_id, session):
    if a_id == b_id: return True
    q = session.query(Match).filter(
        ((Match.player1_id==a_id) & (Match.player2_id==b_id)) |
        ((Match.player1_id==b_id) & (Match.player2_id==a_id))
    )
    return session.query(q.exists()).scalar()

def swiss_pair_round(t: Tournament, r: Round, session):
    # Build score groups
    players = session.query(TournamentPlayer).filter_by(tournament_id=t.id).all()
    scored = [(tp, player_points(tp, session)) for tp in players]
    scored.sort(key=lambda x: (-x[1], x[0].id))  # by points desc

    groups = defaultdict(list)
    for tp, pts in scored:
        groups[pts].append(tp)

    table = 1
    created = []
    for pts in sorted(groups.keys(), reverse=True):
        group = groups[pts][:]
        # If odd, float down lowest to next group
        if len(group) % 2 == 1:
            # Float lowest in group to the next lower points group or give bye if none
            floater = group.pop()
            lower_keys = [k for k in sorted(groups.keys()) if k < pts]
            placed = False
            for lk in reversed(lower_keys):
                groups[lk].append(floater)
                placed = True
                break
            if not placed:
                # Give BYE
                m = Match(round_id=r.id, player1_id=floater.id, player2_id=None, table_number=table, completed=True)
                m.result = MatchResult(player1_wins=2, player2_wins=0, draws=0)
                session.add(m)
                created.append(m)
                table += 1

        # Now pair within group avoiding rematches if possible
        used = set()
        for i, a in enumerate(group):
            if a.id in used: continue
            # find best opponent not yet used and not previously played
            opp = None
            for b in group[i+1:]:
                if b.id in used: continue
                if not have_played(a.id, b.id, session):
                    opp = b
                    break
            if opp is None:
                # fallback: first available
                for b in group[i+1:]:
                    if b.id in used: 
                        continue
                    opp = b
                    break
            if opp is None:
                # shouldn't happen due to even count after float, but guard
                continue
            used.add(a.id); used.add(opp.id)
            m = Match(round_id=r.id, player1_id=a.id, player2_id=opp.id, table_number=table)
            session.add(m)
            created.append(m)
            table += 1

    session.commit()
    return created

# --- Tiebreakers per MTR (simplified) ---
# OMW%: average of each opponent's match-win %, floored at 33%
# GW%: player's game-win % (wins / (wins+losses+draws/2)), floored at 33%
# OGW%: average of opponents' game-win %, floored at 33%

def compute_standings(t: Tournament, session):
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
