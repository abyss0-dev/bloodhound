# Repository agent contract

このリポジトリを変更するエージェントは、変更対象に必要なコマンドを非対話 shell から実行できる状態に保ってください。

## Working rules

- ユーザーの変更を保持してください。無関係なファイルを上書き・整形したり、既存の checkout を reset したりしてはいけません。
- 検査やテストを削除・弱体化・黙殺してはいけません。失敗は原因を調査してください。
- 完了を報告するときは、変更内容と実行した検証の結果を対応づけてください。実施していないテストを成功として報告してはいけません。

## Design philosophy

設計や実装の判断をする前に、`docs/philosophy/README.md` を読んで従ってください。

## Pull requests

PR を作成するときは、`.agents/skills/create-pr/SKILL.md` に従ってください。
変更が設計思想に沿っているかのレビューは、`.agents/skills/review-pr-against-philosophy/SKILL.md` に従ってください。
レビューは、変更を作成したセッションとは別のまっさらな文脈で行います。

## GitHub Actions

`.github/workflows/` 配下を作成または変更する前に、`.github/workflows/AGENTS.md` を読んで従ってください。

外部 Action と reusable workflow の参照は、mise で管理する pinact を使って40文字の commit SHAに固定します。
tag、branch、短縮SHAをチェックインしてはいけません。

## Repository settings

GitHub 上の設定の適用は、ユーザーの明示的な許可がある場合に限ります。適用するときは、リポジトリのルートで次を実行します。

```sh
./setup-repository.sh
```

設定ドリフトだけを確認する場合は、次を実行します。

```sh
./setup-repository.sh --check
```

スクリプトが拒否した owner、visibility、default branch を推測で変更してはいけません。

## Project commands

ビルドと E2E は Linux を前提とします。
eBPF の読み込みに必要なカーネル機能（`CONFIG_AUDIT`、BTF）と KVM が macOS にはないためです。
CI が実行するコマンドの正は `.github/workflows/` です。この節と食い違う場合は workflow に合わせて更新してください。

Setup は次の通りです。

```sh
mise install
```

Build は Docker 上で静的 musl バイナリを作ります。

```sh
make build-docker
```

Test はビルド用イメージ内で workspace のテストを実行します。

```sh
docker build --target build -t bloodhound-workspace-test -f Dockerfile.build .
docker run --rm bloodhound-workspace-test cargo test --workspace --locked --target x86_64-unknown-linux-musl
```

E2E は QEMU/KVM 上の VM を使います。手順は `e2e/README.md` に従ってください。

Check は次の通りです。

```sh
mise run actions:check
```
