# Pairing algorithms

This document describes Walter's current tournament-pairing rules. Standings remain
deterministic for display, but a displayed name order is never used as a pairing
tiebreaker.

## Shared rules

- Standings use match points, opponent match-win percentage (OMW), game-win
  percentage (GW), and opponent game-win percentage (OGW), in that order.
- Players tied on all four values are shuffled within that exact tie region before
  pairings are built. This applies to two-player and Commander Swiss events.
- Before a cut, two players may not be paired again. For Commander, no pod may
  contain two players who shared an earlier pod.
- If no complete legal layout exists, Walter creates no matches and exposes the
  **Hand-pair Round** page to tournament administrators. The page requires every
  active player exactly once and rejects every repeated opponent. It is unavailable
  unless automatic pairing failed.
- A two-player bye is immediately reported as a 2–0 win. An administrator can use
  **Delete Report** on the round page to un-report it before re-pairing the round.
- Draft and Sealed use the same match-pairing rules.

## Swiss and cuts

Round one is random except for the limited-event rules below. Later Swiss rounds
pair down standings while avoiding repeats. Exact tiebreak ties are random rather
than alphabetical.

The first elimination round after a cut is counter-seeded. For example, Top 8 is
`1–8`, `2–7`, `3–6`, and `4–5`; the same first-versus-last rule applies to any
configured cut size. Commander distributes these counter-seeded pairs among
four-player pods. Later cut rounds advance the winners (or all players from a drawn
Commander pod).

## Draft and Sealed

Draft seating is generated before round-one matches. Players are shuffled into
eight-player pods. When the player count is not divisible by eight, remainder
players are distributed among the existing pods instead of being isolated in a
small final pod.

- With one pod, round one uses big-X/little-X: the first half plays the second half.
- With multiple pods, opponents are selected randomly from different pods until
  that is impossible. Any players left in one pod use big-X/little-X.
- Later Swiss rounds use the normal Swiss rules.
- Draft/Sealed round robin uses the limited round-one rule, then random legal
  opponents who have not played one another.

## Single elimination

- Constructed (including 60-card formats) starts randomly.
- Draft and Sealed use the limited round-one rules above.
- Commander starts with random pods of up to four.
- In later rounds, advancing players are ordered by game record (wins, then fewer
  losses) and then OGW, keeping records such as 2–0, 2–1, and 1–0 together. Exact
  ties are shuffled, and adjacent players (or groups of four for Commander) are paired.
- A Commander pod advances its first-place player. If the pod result is a draw, all
  players in that pod advance.

## Round robin

Two-player round robin uses a randomized rotation so every opponent is encountered
once. Draft and Sealed use their special first round and then random non-repeating
opponents. Commander round robin is not supported.
