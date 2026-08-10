from types import SimpleNamespace

from app.league_scoring import colley_ratings, glicko_ratings, select_results


def result(points):
    return SimpleNamespace(points=points, wins=points // 3, losses=0)


def test_personal_and_field_best_scoring_limits():
    entries = [result(value) for value in (9, 6, 3, 0)]
    assert [item.points for item in select_results(entries, 'personal_best', 75)] == [9, 6, 3]
    assert [item.points for item in select_results(entries, 'field_best', 50, 6)] == [9, 6, 3]
    assert len(select_results(entries[:2], 'field_best', 75, 6)) == 2


def test_colley_rewards_wins_and_glicko_moves_both_players():
    games = [(1, 2, 1.0), (1, 3, 1.0), (2, 3, 0.5)]
    colley = colley_ratings([1, 2, 3], games)
    assert colley[1] > colley[2]
    assert colley[2] == colley[3]
    glicko = glicko_ratings([1, 2, 3], games)
    assert glicko[1][0] > 1500
    assert glicko[3][0] < 1500
    assert all(deviation < 350 for _rating, deviation in glicko.values())


def test_colley_scoring_keeps_all_event_results():
    entries = [result(value) for value in (0, 3, 6, 9)]
    assert len(select_results(entries, 'colley', 10)) == 4
