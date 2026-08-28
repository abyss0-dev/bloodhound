#!/bin/sh

set -eu

mode=apply

usage() {
  printf '%s\n' "Usage: ./setup-repository.sh [--check]"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

case "${1-}" in
  "")
    ;;
  --check)
    mode=check
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

require_command gh
require_command jq
require_command mise

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
cd "$script_dir"

gh auth status -h github.com >/dev/null 2>&1 || fail "gh is not authenticated to github.com"

repository=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
case "$repository" in
  abyss0-dev/*)
    ;;
  *)
    fail "repository must belong to abyss0-dev: $repository"
    ;;
esac

metadata=$(gh api "repos/$repository")
visibility=$(printf '%s' "$metadata" | jq -r .visibility)
default_branch=$(printf '%s' "$metadata" | jq -r .default_branch)

case "$visibility" in
  private|public)
    ;;
  *)
    fail "unsupported repository visibility: $visibility"
    ;;
esac

[ "$default_branch" = main ] || fail "default branch must be main: $default_branch"

settings_file=.github/repository-settings.json
ruleset_file=.github/rulesets/public-default-branch.json

[ -f "$settings_file" ] || fail "missing settings file: $settings_file"
[ -f "$ruleset_file" ] || fail "missing ruleset file: $ruleset_file"

normalize_settings_file() {
  jq -S -c . "$settings_file"
}

read_repository_settings() {
  gh api "repos/$repository" | jq -S -c '{
    has_issues,
    has_projects,
    has_wiki,
    allow_squash_merge,
    allow_merge_commit,
    allow_rebase_merge,
    allow_auto_merge,
    delete_branch_on_merge,
    allow_update_branch,
    squash_merge_commit_title,
    squash_merge_commit_message
  }'
}

verify_repository_settings() {
  expected=$(normalize_settings_file)
  actual=$(read_repository_settings)
  [ "$actual" = "$expected" ] || {
    printf '%s\n' "repository settings differ" >&2
    printf '%s\n' "expected:" >&2
    printf '%s\n' "$expected" | jq . >&2
    printf '%s\n' "actual:" >&2
    printf '%s\n' "$actual" | jq . >&2
    return 1
  }
}

normalize_ruleset_file() {
  jq -S -c '.rules |= sort_by(.type)' "$ruleset_file"
}

read_ruleset() {
  ruleset_id=$1
  gh api "repos/$repository/rulesets/$ruleset_id" | jq -S -c '{
    name,
    target,
    enforcement,
    bypass_actors: (.bypass_actors // []),
    conditions,
    rules
  } | .rules |= sort_by(.type)'
}

find_ruleset_id() {
  gh api "repos/$repository/rulesets" \
    --jq '.[] | select(.name == "default-branch") | .id'
}

verify_public_ruleset() {
  ids=$(find_ruleset_id)
  count=$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')
  [ "$count" -eq 1 ] || fail "expected one default-branch ruleset, found $count"

  expected=$(normalize_ruleset_file)
  actual=$(read_ruleset "$ids")
  [ "$actual" = "$expected" ] || {
    printf '%s\n' "public ruleset differs" >&2
    printf '%s\n' "expected:" >&2
    printf '%s\n' "$expected" | jq . >&2
    printf '%s\n' "actual:" >&2
    printf '%s\n' "$actual" | jq . >&2
    return 1
  }
}

if [ "$mode" = apply ]; then
  note "Applying repository settings to $repository"
  gh api --method PATCH "repos/$repository" --input "$settings_file" >/dev/null
fi

verify_repository_settings || fail "repository settings verification failed"

if [ "$visibility" = public ]; then
  if [ "$mode" = apply ]; then
    ids=$(find_ruleset_id)
    count=$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')
    case "$count" in
      0)
        note "Creating public default-branch ruleset"
        gh api --method POST "repos/$repository/rulesets" --input "$ruleset_file" >/dev/null
        ;;
      1)
        note "Updating public default-branch ruleset"
        gh api --method PUT "repos/$repository/rulesets/$ids" --input "$ruleset_file" >/dev/null
        ;;
      *)
        fail "refusing to update duplicate default-branch rulesets: $count"
        ;;
    esac
  fi
  verify_public_ruleset || fail "public ruleset verification failed"
else
  note "Private repository on GitHub Free: repository ruleset and Merge Queue are not applied"
fi

if [ "$mode" = apply ]; then
  mise install pinact
fi

github_token=$(gh auth token)
GITHUB_TOKEN=$github_token mise run actions:check
unset github_token

note "Repository setup verified: $repository ($visibility)"
