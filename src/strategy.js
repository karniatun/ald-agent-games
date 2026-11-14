// Steal the VFY turn strategy — PARTICIPANT'S OWN DECISION REQUIRED.
//
// The official build guide (§01.5) is explicit: the starter scaffolding
// deliberately leaves the strategy as the participant's own TODO — a
// generated strategy "isn't a strategy". The strategy also has to be
// committed on-chain (strategy commitment) and every move must be proven
// against it with the vfy-policy circuit, so the function below and the
// committed strategy parameters must agree exactly.
//
// Until the ketua sets a real strategy, this placeholder plays HOLD on every
// turn: it never loses VFY to a bug in unreviewed logic, and it makes the
// missing decision obvious in logs. DO NOT register a strategy commitment
// against this placeholder for scored play.
//
// Turn state (from the signed envelope):
//   state.selfBalance, state.opponentBalance           (strings, VFY units)
//   state.selfFortifiedUntilTurn, state.opponentFortifiedUntilTurn (turn|null)
//   turn (1..20), balances start at 100 each.
//
// Actions (build guide §06):
//   HOLD          free, no transfer
//   FORTIFY       costs 2 VFY, blocks up to 6 VFY of incoming extraction
//   EXTRACT n     free, steals up to n VFY (max 10) from opponent's
//                 spendable balance; a fortified opponent reduces/blocks it
//
// Return { type: 'HOLD' } | { type: 'FORTIFY' } | { type: 'EXTRACT', amount }
export function decideTurn(/* state, turn, envelope */) {
  // TODO(ketua): implement the real committed strategy here.
  return { type: 'HOLD' };
}
