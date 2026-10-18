# T2 review and closure

## 対象と来歴

VM で測定した実装候補は `a61027578118ee93c90368fb2d9a4953afe2fa69` である。
レビュー対象の証拠 HEAD は `ade37ecb8041f39b8c635dfad34b4c16b6994ad9` であり、同 HEAD は測定候補のコードと acceptance 記録を含む。
この closure 文書と GOAL の更新は文書だけの変更とし、コードとテストは変更しない。

## 初回 review 指摘と修正

初回 review は、成功した exec の actor/time pairing と BTF/nsfs capture の骨格を確認した一方、wire ID 225 の再利用、管理 namespace と同一の namespace だけを測る acceptance、sys_exit の return read failure 時に pending map entry を残す経路を指摘した。

修正候補は `ExecEntryNetworkContext` に ID 228 を割り当て、225、226、227 を予約済みのまま保持する。
`ctx.read_at(16)` が失敗した場合は該当 task の pending entry を削除し、削除失敗は `exec_failure(4)`、exit capture failure は既存の診断経路で報告する。

producer acceptance は guest 内で `unshare --net` を使い、UID/AUID 1000 の leader と non-leader exec を新しい network namespace で実行する。
namespace FD の `fstat` と producer の identity を照合し、管理 namespace と device が一致し inode が異なること、actor/time の完全一致、失敗 exec に対応する context がないことを検証する。

## Review と検証

Gemini の最終 review は blocker なしとし、記録を `/tmp/network-impl.DDNwog/t2-close-review.txt` に保存した。
Main は修正 diff、reserved IDs、read failure cleanup、namespace acceptance を独立に確認し、focused と full VM の raw logs を確認した。
Main は workspace 216 tests、schema/process-identity pytest 6 tests、diff checks を再実行し、30 個の既存 untracked evidence file の archive hashes と最終 clean state も確認した。

専用 guest は Linux `6.8.0-49-generic` x86_64 である。
Focused acceptance は 3/3、full e2e regression は 81/81 であり、測定値と全 run provenance は [`t2-vm-acceptance.md`](t2-vm-acceptance.md) に、非 VM 検証結果は [`t2-nonvm-checks.md`](t2-nonvm-checks.md) に記録した。

## 既知の検査制約と範囲

`cargo fmt --all -- --check` は repository baseline の formatting drift で失敗し、`cargo clippy --workspace --all-targets -- -D warnings` は未変更の `bloodhound-tui/src/keybinds.rs:50` にある既存 `collapsible_match` lint で失敗する。
これらは pass と報告しない。変更した common/exec-handler 範囲の rustfmt、`bloodhound-common` strict Clippy、通常の workspace Clippy は pass した。

この承認は T2 の exec-entry network-context 実装と記載した acceptance に限る。
T3 または T7 の統合・acceptance を実施した、または承認したことを意味しない。

## 過去の証拠の保管

30 個の既存 untracked evidence file は、相対パスと内容を保持して `/tmp/network-impl.DDNwog/t2-historical-evidence-archive` に移した。
manifest は `/tmp/network-impl.DDNwog/t2-historical-evidence-archive/manifest.sha256` であり、その SHA-256 は `70c907bc8f6922e858363591995db50804e3c6406e8d955234bd902df93df5fb` である。
全 30 file の hash を archive と照合してから checkout 内の元ファイルだけを除去し、archive を再検証した。
これは一時的なローカル保存先であり、repository、build、runtime の依存ではなく、公開・統合していない。
