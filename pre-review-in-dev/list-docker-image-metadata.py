#!/usr/bin/env python3
"""
List local Docker image references with their manifest digests and a simple
IOC match for the known `/wrapper.sh` entrypoint pattern.

IOC means "indicator of compromise". In this incident-response workflow, if any
IOC signal is active for an image, we treat that image as malicious and we must
not run it.

This script only reads local Docker metadata via `docker image ls --digests`
plus `docker image inspect` and `docker image history` for IOC metadata. It
does not create containers, start containers, or run any of the inspected
images.

The `--90-day-github-runs` CSV is treated as the expected set of legitimate
image-name-plus-digest pairs produced by the GitHub build workflow. For that
cross-reference we compare `repository@digest`, not `repository:tag@digest`,
because we care about the image name and digest while ignoring version tags.
In this incident model, the GitHub build workflow is not the compromised
component; the registry is. That means an IOC-positive image whose
`repository@digest` also appears in the GitHub-runs CSV is especially unusual.
We also treat IOC-positive images created before 2026-02-15 as unexpectedly
old relative to the currently understood incident timeline.

The CSV comes from automated log extraction, so we treat any digest hit in that
CSV as meaningful. We still keep a small warning path for the special case
where a digest only appears in attestation rows, because that may indicate the
CSV extraction needs a closer look.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path


HEADER = [
    "image_id",
    "name",
    "digest",
    "created",
    "wrapper_ep",
    "layer_wrapper",
    "layer_checkappend",
    "layer_dockerd",
    "layer_known_dockerd_hash_match",
    "github_runs_90d_match",
    "ioc_before_2026_02_15",
]

# We use this as a coarse sanity check on the GitHub-runs CSV. This is only a
# "does this look like the right file at all?" guard, so we count all validated
# CSV data rows here, including attestation rows.
MIN_GITHUB_RUNS_90D_CSV_ENTRIES = 100
# Under the current incident timeline, IOC-positive images created before
# 2026-02-15 would be older than we currently expect for the known malicious
# Harbor activity for potentially affected images (not odd dev ones)
IOC_UNEXPECTED_OLD_CUTOFF = date(2026, 2, 15)
RECENT_UNEXPLAINED_IMAGE_CUTOFF = date(2026, 1, 26)
HARBOR2_REPOSITORY_PREFIX = "harbor2.vantage6.ai/"


@dataclass(frozen=True)
class GitHubRuns90dIndex:
    """
    Image-name-plus-digest index built from the GitHub-runs CSV.

    We compare `repository@digest`, not full `repository:tag@digest`, because
    local Docker images often lose their original tag and show up as
    `...:<none>`. That still lets us distinguish, for example, `node@digest`
    from `server@digest` without caring about the release tag itself.
    """

    all_image_names_with_digests: set[str]
    non_attestation_image_names_with_digests: set[str]
    csv_entry_count: int

    def has_image_name_with_digest(self, image_name_with_digest: str) -> bool:
        """
        Return whether this `repository@digest` appears anywhere in the
        GitHub-runs CSV.
        """
        return image_name_with_digest in self.all_image_names_with_digests

    def has_only_attestation_match(self, image_name_with_digest: str) -> bool:
        """
        Return whether this `repository@digest` appears in the CSV, but only in
        attestation rows.
        """
        return (
            image_name_with_digest in self.all_image_names_with_digests
            and image_name_with_digest
            not in self.non_attestation_image_names_with_digests
        )


@dataclass(frozen=True)
class ImageReportRow:
    """
    One output row in the final TSV and summary report.

    We keep the row as a dataclass instead of a long tuple so the field names
    stay visible in the code where we build, sort, and summarize rows.
    """

    image_id: str
    name: str
    digest: str
    created: str
    wrapper_ep: str
    layer_wrapper: str
    layer_checkappend: str
    layer_dockerd: str
    layer_known_dockerd_hash_match: str
    github_runs_90d_match: str
    image_found_as_attestation_digest_warning: str
    ioc_before_2026_02_15: str

    def to_tsv_row(self) -> list[str]:
        """
        Return this row in the same column order as `HEADER`.
        """
        return [
            self.image_id,
            self.name,
            self.digest,
            self.created,
            self.wrapper_ep,
            self.layer_wrapper,
            self.layer_checkappend,
            self.layer_dockerd,
            self.layer_known_dockerd_hash_match,
            self.github_runs_90d_match,
            self.ioc_before_2026_02_15,
        ]

    def sort_key(
        self,
    ) -> tuple[str, str, str, str, str, str, str, str, str, str, str]:
        """
        Return the stable sort key for this row.
        """
        return (
            self.created,
            self.name,
            self.image_id,
            self.digest,
            self.wrapper_ep,
            self.layer_wrapper,
            self.layer_checkappend,
            self.layer_dockerd,
            self.layer_known_dockerd_hash_match,
            self.github_runs_90d_match,
            self.ioc_before_2026_02_15,
        )

    def ioc_signals(self) -> list[str]:
        """
        Return the positive IOC signals for this row.
        """
        signals: list[str] = []
        if self.wrapper_ep == "yes":
            signals.append("wrapper_ep")
        if self.layer_wrapper == "yes":
            signals.append("layer_wrapper")
        if self.layer_checkappend == "yes":
            signals.append("layer_checkappend")
        if self.layer_dockerd == "yes":
            signals.append("layer_dockerd")
        if self.layer_known_dockerd_hash_match == "yes":
            signals.append("layer_known_dockerd_hash_match")
        return signals

    def has_iocs(self) -> bool:
        """
        Return whether this row has any IOC signal.

        In this workflow, any positive signal means we treat the image as
        malicious.
        """
        return bool(self.ioc_signals())

    def image_with_digest(self) -> str:
        """
        Return this row as `name@digest` when a digest is available.

        We use this in the summary report because `name@digest` is the most
        useful human-readable identifier for cross-checking a flagged image.
        """
        if self.digest and self.digest != "<none>":
            return f"{self.name}@{self.digest}"
        return self.name

    def summary_identity_fields(self) -> str:
        """
        Return the human-readable identity fields for summary stderr output.

        We already show the digest in `name@digest`, so we only add
        `image_id=...` when it differs from the digest and therefore adds new
        information.
        """
        if self.image_id and self.image_id != self.digest:
            return f"{self.image_with_digest()}\timage_id={self.image_id}"
        return self.image_with_digest()

    def is_ioc_in_expected_github_build(self) -> bool:
        """
        Return whether this row has IOC signals and its `repository@digest`
        does match the GitHub-runs CSV.

        This is especially unusual in the current incident model because the
        GitHub workflow is treated as the source of legitimate builds, while
        the registry is the compromised component.
        """
        return self.has_iocs() and self.github_runs_90d_match == "yes"

    def is_unexpectedly_old_ioc(self) -> bool:
        """
        Return whether this row has IOC signals and was created before
        2026-02-15.

        We use this as a timeline check. Under the current incident model, IOC
        signals before 2026-02-15 would be earlier than we currently expect for
        the known Harbor compromise window.
        """
        return self.ioc_before_2026_02_15 == "yes"


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for this script.

    Input:
      command-line arguments from `sys.argv`

    Output:
      argparse namespace with required input files
    """
    parser = argparse.ArgumentParser(
        description=(
            "List local Docker images with IOC (indicator of compromise) checks "
            "and a required CSV-based cross-reference against recent GitHub "
            "runs output. This script only inspects metadata and must not run "
            "the images it reports."
        )
    )
    parser.add_argument(
        "--90-day-github-runs",
        dest="github_runs_90d",
        type=Path,
        required=True,
        help=(
            "CSV with columns like "
            "run_name,source,image_tag,digest,manifest_type"
        ),
    )
    parser.add_argument(
        "--harbor2",
        action="store_true",
        help=(
            "Only report local image rows whose repository starts with "
            f"`{HARBOR2_REPOSITORY_PREFIX}`"
        ),
    )
    return parser.parse_args()


# needlessly robust, but whatever
def image_name_from_image_tag(image_tag: str) -> str:
    """
    Return the image-name part of a Docker image reference.

    Input:
      image_tag: Docker reference like
        `harbor2.vantage6.ai/infrastructure/node:4.13.6rc1`

    Output:
      image name without the tag, for example
        `harbor2.vantage6.ai/infrastructure/node`

    We remove the tag only when the last `:` appears after the last `/`, so
    registry ports like `registry:5000/...` stay intact.
    """
    reference = image_tag.strip()
    if "@" in reference:
        reference = reference.split("@", 1)[0]

    last_slash = reference.rfind("/")
    last_colon = reference.rfind(":")
    # We only strip the suffix after `:` when that `:` is part of the tag
    # position, e.g. `repo/image:4.13.7`. A registry port like
    # `registry:5000/repo/image` appears before the last `/` and must stay.
    if last_colon > last_slash:
        return reference[:last_colon]
    # If there is no tag suffix after the last `/`, the reference already is
    # just the image name.
    return reference


def image_name_with_digest(image_name: str, digest: str) -> str:
    """
    Return the cross-reference key format `repository@digest`.
    """
    return f"{image_name}@{digest}"


def run_docker(*args: str) -> str:
    """
    Run one Docker CLI command and return stdout as text.

    Input:
      docker CLI arguments, e.g. ("image", "ls", ...)

    Output:
      stdout from Docker

    Exits the script with Docker's error text if the command fails.
    """
    # Keep Docker invocation in one helper so the main logic stays focused on
    # transforming Docker's output into the TSV we want.
    try:
        completed = subprocess.run(
            ["docker", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit("docker is not installed or not in PATH") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        raise SystemExit(stderr or stdout or "docker command failed") from exc

    return completed.stdout


def load_github_runs_90d_index(csv_path: Path) -> GitHubRuns90dIndex:
    """
    Load an image-name-plus-digest index from the GitHub-runs CSV.

    Input:
      csv_path: path from `--90-day-github-runs`

    Output:
      `repository@digest` index from the GitHub-runs CSV

    We treat this CSV as the expected set of legitimate GitHub-built images.
    We match by `repository@digest`, not by full `repository:tag@digest`,
    because local Docker images may be untagged by the time we inspect them
    and because we do not want version tags to control the cross-reference.

    This parser is intentionally strict: malformed rows should fail the script
    with a clear error instead of being normalized away.

    Expected CSV shape:
      run_name,source,image_tag,digest,manifest_type

    Example row:
      2026-01-26_Build_&_Release_21354617254_failure,buildx,harbor2.vantage6.ai/infrastructure/node:4.13.6rc1,sha256:4fc28...,manifest
    """
    if not csv_path.is_file():
        raise SystemExit(f"CSV file not found: {csv_path}")

    all_image_names_with_digests: set[str] = set()
    non_attestation_image_names_with_digests: set[str] = set()
    csv_entry_count = 0
    # We use `utf-8-sig` instead of plain `utf-8` so a UTF-8 BOM at the start
    # of the CSV does not turn the first header into `\ufeffimage_tag` or
    # similar. That BOM is an invisible prefix some tools add when exporting
    # CSV files.
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SystemExit(f"CSV file has no header: {csv_path}")

        # Expected columns in the GitHub-runs CSV:
        #   run_name, source, image_tag, digest, manifest_type
        # We use `image_tag` only to derive the image name part, so the
        # cross-reference key becomes `repository@digest`.
        # We keep `manifest_type` because we want one narrow warning case:
        # a digest that only shows up in attestation rows. We do not use that
        # to suppress the match, because this CSV came from automated log
        # extraction and we do not want to throw away a potentially real hit.
        required_columns = {"image_tag", "digest", "manifest_type"}
        fieldnames = {
            field.strip() for field in reader.fieldnames if field is not None
        }
        missing = sorted(required_columns - fieldnames)
        if missing:
            raise SystemExit(
                f"CSV file is missing required columns: {', '.join(missing)} "
                f"({csv_path})"
            )

        for row_number, raw_row in enumerate(reader, start=2):
            if None in raw_row:
                raise SystemExit(
                    f"CSV row {row_number} has extra unnamed columns ({csv_path})"
                )

            row = {key.strip(): value for key, value in raw_row.items() if key is not None}

            image_tag = row.get("image_tag")
            digest = row.get("digest")
            manifest_type = row.get("manifest_type")

            if image_tag is None:
                raise SystemExit(
                    f"CSV row {row_number} is missing image_tag ({csv_path})"
                )
            if digest is None:
                raise SystemExit(
                    f"CSV row {row_number} is missing digest ({csv_path})"
                )
            if manifest_type is None:
                raise SystemExit(
                    f"CSV row {row_number} is missing manifest_type ({csv_path})"
                )

            # image_tag is not ":4.13", but the whole image name.. "harbor2..../infrastructure/node:4.13"
            image_tag = image_tag.strip()
            digest = digest.strip()
            manifest_type = manifest_type.strip()

            if not image_tag:
                raise SystemExit(
                    f"CSV row {row_number} has blank image_tag ({csv_path})"
                )
            if not digest:
                raise SystemExit(
                    f"CSV row {row_number} has blank digest ({csv_path})"
                )
            if not manifest_type:
                raise SystemExit(
                    f"CSV row {row_number} has blank manifest_type ({csv_path})"
                )

            if manifest_type not in {"manifest", "manifest_list", "attestation"}:
                raise SystemExit(
                    f"CSV row {row_number} has unexpected manifest_type "
                    f"{manifest_type!r} ({csv_path})"
                )

            image_name = image_name_from_image_tag(image_tag)
            github_image_name_with_digest = image_name_with_digest(image_name, digest)
            # Any `repository@digest` hit from the GitHub-runs CSV is useful to
            # keep, even if this particular row is marked as `attestation`.
            # That lets the main cross-reference stay simple: if the pair shows
            # up anywhere in the CSV, `github_runs_90d_match=yes`.
            all_image_names_with_digests.add(github_image_name_with_digest)
            # This count is only a sanity check on the CSV input itself, so we
            # count every validated data row here, including attestation rows.
            csv_entry_count += 1

            if manifest_type == "attestation":
                # We stop here for attestation rows because they should not
                # count toward the narrower non-attestation set. We still kept
                # the pair above so we can emit the attestation-only warning
                # later if this is the only kind of GitHub match.
                continue

            non_attestation_image_names_with_digests.add(github_image_name_with_digest)

    return GitHubRuns90dIndex(
        all_image_names_with_digests=all_image_names_with_digests,
        non_attestation_image_names_with_digests=non_attestation_image_names_with_digests,
        csv_entry_count=csv_entry_count,
    )


def parse_created_at_date(created: str) -> date:
    """
    Parse Docker's `CreatedAt` text into a UTC calendar date.

    Input:
      created: `CreatedAt` string from `docker image ls`, for example
        `2026-04-07 23:32:21 +0000 UTC`

    Output:
      calendar date portion, for example `date(2026, 4, 7)`

    We only need the date, not the time, for the fixed incident-window check.
    """
    created_date_text = created.strip().split(" ", 1)[0]
    if not created_date_text:
        raise SystemExit("Docker image listing returned a blank CreatedAt field")

    try:
        return date.fromisoformat(created_date_text)
    except ValueError as exc:
        raise SystemExit(
            f"Could not parse Docker CreatedAt date: {created!r}"
        ) from exc


def has_wrapper_sh_entrypoint(
    image_id: str, wrapper_ep_by_image_id: dict[str, str]
) -> str:
    """
    Return whether this image's configured entrypoint is exactly `/wrapper.sh`.

    Input:
      image_id: Docker image ID from `docker image ls`
      wrapper_ep_by_image_id: memoized yes/no results keyed by image ID

    Output:
      "yes" if `.Config.Entrypoint` is `/wrapper.sh`, otherwise "no"
    """
    # `docker image ls` does not expose entrypoint metadata, so inspect the
    # image ID once per unique image. This keeps dangling/untagged images in
    # scope, which matters for IOC hunting.
    if image_id not in wrapper_ep_by_image_id:
        output = run_docker(
            "image",
            "inspect",
            "--format",
            "{{json .Config.Entrypoint}}",
            image_id,
        ).strip()

        entrypoint = json.loads(output or "null")
        # `yes` means the image matches the known `/wrapper.sh` IOC entrypoint
        # pattern we are looking for.
        wrapper_ep_by_image_id[image_id] = (
            "yes"
            if entrypoint == "/wrapper.sh" or entrypoint == ["/wrapper.sh"]
            else "no"
        )

    return wrapper_ep_by_image_id[image_id]


def get_created_by_history_rows(
    image_id: str, created_by_history_by_image_id: dict[str, list[str]]
) -> list[str]:
    """
    Return lower-cased `CreatedBy` history rows for one image.

    Input:
      image_id: Docker image ID from `docker image ls`
      created_by_history_by_image_id: memoized history rows keyed by image ID

    Output:
      list of lower-cased `CreatedBy` strings from `docker image history`
    """
    if image_id not in created_by_history_by_image_id:
        output = run_docker(
            "image",
            "history",
            "--no-trunc",
            "--format",
            "{{json .}}",
            image_id,
        )
        # `docker image history --format {{json .}}` emits one JSON object per
        # layer/history row. Example:
        # {"CreatedBy":"/bin/sh -c #(nop)  ENTRYPOINT [\"/wrapper.sh\"]","ID":"<missing>","Size":"0B"}
        # {"CreatedBy":"/bin/sh -c #(nop) COPY file:54a2... in /usr/bin/dockerd","ID":"<missing>","Size":"430kB"}
        # {"CreatedBy":"CMD [\"/bin/sh\"]","ID":"sha256:c190...","Size":"0B"}
        # We only keep the `CreatedBy` text because the IOC checks below are
        # based entirely on those history commands.

        created_by_rows: list[str] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            item = json.loads(line)
            created_by = str(item.get("CreatedBy") or "")
            created_by_rows.append(created_by.lower())

        created_by_history_by_image_id[image_id] = created_by_rows

    return created_by_history_by_image_id[image_id]


def has_wrapper_sh_history_pattern(created_by_lower: str) -> bool:
    """
    Return whether one history row copies or adds `wrapper.sh`.

    Input:
      created_by_lower: one lower-cased `CreatedBy` history string

    Output:
      True if the row looks like COPY/ADD of `wrapper.sh`, else False
    """
    return (
        ("copy " in created_by_lower or "add " in created_by_lower)
        and "wrapper.sh" in created_by_lower
    )


def has_checkappend_history_pattern(created_by_lower: str) -> bool:
    """
    Return whether one history row copies or adds `checkAppend`.

    Input:
      created_by_lower: one lower-cased `CreatedBy` history string

    Output:
      True if the row looks like COPY/ADD of `checkAppend`, else False
    """
    return (
        ("copy " in created_by_lower or "add " in created_by_lower)
        and "checkappend" in created_by_lower
    )


def has_dockerd_history_pattern(created_by_lower: str) -> bool:
    """
    Return whether one history row copies or adds `dockerd`.

    Input:
      created_by_lower: one lower-cased `CreatedBy` history string

    Output:
      True if the row looks like COPY/ADD of `dockerd`, else False
    """
    return (
        ("copy " in created_by_lower or "add " in created_by_lower)
        and "dockerd" in created_by_lower
    )


def has_known_dockerd_file_hash_pattern(created_by_lower: str) -> bool:
    """
    Return whether one history row contains the specific `file:54a2...` marker.

    Input:
      created_by_lower: one lower-cased `CreatedBy` history string

    Output:
      True if the row contains the specific marker, else False

    This is probably not a stable IOC across builders or rebuilds. We keep it
    as a weaker hint than the basename/path checks.
    """
    return (
        "file:54a2c646c30aea31bba9525c07ec8260fc5ff10de9e4008b7a265c269dce665d"
        in created_by_lower
    )


def has_wrapper_sh_layer(created_by_rows: list[str]) -> str:
    """
    Return whether any history row matches the `wrapper.sh` IOC layer
    pattern.

    Input:
      created_by_rows: lower-cased `CreatedBy` strings for one image

    Output:
      "yes" if any history row copies/adds `wrapper.sh`, otherwise "no"
    """
    for created_by_lower in created_by_rows:
        if has_wrapper_sh_history_pattern(created_by_lower):
            return "yes"
    return "no"


def has_checkappend_layer(created_by_rows: list[str]) -> str:
    """
    Return whether any history row matches the `checkAppend` IOC layer
    pattern.

    Input:
      created_by_rows: lower-cased `CreatedBy` strings for one image

    Output:
      "yes" if any history row copies/adds `checkAppend`, otherwise "no"
    """
    for created_by_lower in created_by_rows:
        if has_checkappend_history_pattern(created_by_lower):
            return "yes"
    return "no"


def has_dockerd_layer(created_by_rows: list[str]) -> str:
    """
    Return whether any history row matches the `dockerd` IOC layer
    pattern.

    Input:
      created_by_rows: lower-cased `CreatedBy` strings for one image

    Output:
      "yes" if any history row copies/adds `dockerd`, otherwise "no"
    """
    for created_by_lower in created_by_rows:
        if has_dockerd_history_pattern(created_by_lower):
            return "yes"
    return "no"


def has_dockerd_hash_layer(created_by_rows: list[str]) -> str:
    """
    Return whether any history row contains the specific `file:54a2...` marker.

    Input:
      created_by_rows: lower-cased `CreatedBy` strings for one image

    Output:
      "yes" if any history row contains the specific marker, otherwise "no"
    """
    for created_by_lower in created_by_rows:
        if has_known_dockerd_file_hash_pattern(created_by_lower):
            return "yes"
    return "no"


def check_layer_iocs(
    image_id: str,
    layer_checks_by_image_id: dict[str, tuple[str, str, str, str]],
    created_by_history_by_image_id: dict[str, list[str]],
) -> tuple[str, str, str, str]:
    """
    Return the four per-layer IOC checks for one image.

    Here, IOC means "indicator of compromise": a history line that suggests the
    image may contain the malicious wrapper/checkAppend/dockerd pattern we are
    looking for.

    Input:
      image_id: Docker image ID from `docker image ls`
      layer_checks_by_image_id: memoized per-check results keyed by image ID
      created_by_history_by_image_id: memoized history rows keyed by image ID

    Output:
      tuple of:
      (
        layer_wrapper,
        layer_checkappend,
        layer_dockerd,
        layer_known_dockerd_hash_match,
      )
    """
    if image_id not in layer_checks_by_image_id:
        created_by_rows = get_created_by_history_rows(
            image_id, created_by_history_by_image_id
        )
        layer_checks_by_image_id[image_id] = (
            has_wrapper_sh_layer(created_by_rows),
            has_checkappend_layer(created_by_rows),
            has_dockerd_layer(created_by_rows),
            has_dockerd_hash_layer(created_by_rows),
        )

    return layer_checks_by_image_id[image_id]


def build_rows(
    github_runs_90d_index: GitHubRuns90dIndex,
    harbor2_only: bool = False,
) -> list[ImageReportRow]:
    """
    Build the TSV rows that will be printed by the script.

    Input:
      github_runs_90d_index: digest index loaded from the required CSV file
      harbor2_only: only include rows whose repository starts with the Harbor2
        registry prefix

    Output:
      one dataclass row per listed local image reference
    """
    # We expect a real 90-day export here, not an empty or obviously incomplete
    # file. This sanity check keeps the cross-reference from quietly running on
    # a tiny or broken input set.
    if github_runs_90d_index.csv_entry_count < MIN_GITHUB_RUNS_90D_CSV_ENTRIES:
        raise SystemExit(
            "Expected at least "
            f"{MIN_GITHUB_RUNS_90D_CSV_ENTRIES} CSV data rows from "
            f"--90-day-github-runs, got {github_runs_90d_index.csv_entry_count}"
        )

    output = run_docker(
        "image",
        "ls",
        "--all",
        "--digests",
        "--no-trunc",
        "--format",
        "{{json .}}",
    )
    # `--format {{json .}}` gives one machine-readable JSON object per line,
    # which is easier to parse than scraping the table output.
    # Each line is one JSON object from `docker image ls`. Example:
    # {"CreatedAt":"2026-04-07 23:32:21 +0000 UTC","Digest":"sha256:b202...","ID":"sha256:b202...","Repository":"localhost/infrastructure/node","Tag":"v123",...}
    # We turn that into a simpler TSV row:
    # sha256:b202...    localhost/infrastructure/node:v123    sha256:b202...    2026-04-07 23:32:21 +0000 UTC    yes|no    yes|no    yes|no    yes|no    yes|no    yes|no    yes|no

    rows: list[ImageReportRow] = []
    seen: set[ImageReportRow] = set()
    wrapper_ep_by_image_id: dict[str, str] = {}
    layer_checks_by_image_id: dict[str, tuple[str, str, str, str]] = {}
    # We fill this lazily while scanning `docker image ls` rows because the
    # same local image ID can appear multiple times under different names/tags.
    # That lets us reuse one `docker image history` lookup per unique image ID.
    created_by_history_by_image_id: dict[str, list[str]] = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        item = json.loads(line)
        image_id = item.get("ID", "")
        repository = item.get("Repository", "")
        if harbor2_only and not repository.startswith(HARBOR2_REPOSITORY_PREFIX):
            continue
        tag = item.get("Tag", "")
        digest = item.get("Digest", "")
        created = item.get("CreatedAt", "")
        created_date = parse_created_at_date(created)

        # We keep dangling and untagged images in the report. An image does not
        # stop mattering for IOC review just because it lost its tag.
        # It'd be weird if it didn' have a repo.. maybe locally built image?
        name = f"{repository or '<none>'}:{tag or '<none>'}"

        # For the GitHub cross-reference we compare `repository@digest`, not
        # `repository:tag@digest`. We want the same image name and digest while
        # ignoring local tag loss or tag differences.
        local_image_name_with_digest = (
            image_name_with_digest(repository, digest)
            if repository and repository != "<none>" and digest and digest != "<none>"
            else ""
        )

        wrapper_ep = has_wrapper_sh_entrypoint(image_id, wrapper_ep_by_image_id)
        # `check_layer_iocs()` lazily fills `created_by_history_by_image_id`
        # through `get_created_by_history_rows()` on the first lookup for this
        # image ID, then reuses that cached history for later rows.
        # unpack returned tuple
        (
            layer_wrapper,
            layer_checkappend,
            layer_dockerd,
            layer_known_dockerd_hash_match,
        ) = check_layer_iocs(
            image_id, layer_checks_by_image_id, created_by_history_by_image_id
        )
        github_runs_90d_match = (
            "yes"
            if local_image_name_with_digest
            and github_runs_90d_index.has_image_name_with_digest(
                local_image_name_with_digest
            )
            else "no"
        )
        image_found_as_attestation_digest_warning = (
            "found only in attestation rows in the GitHub-runs CSV; this may indicate the CSV extraction needs review"
            if local_image_name_with_digest
            and github_runs_90d_index.has_only_attestation_match(
                local_image_name_with_digest
            )
            else ""
        )
        # In this incident-response workflow, any positive signal means we
        # treat the image as malicious.
        has_any_ioc = any(
            value == "yes"
            for value in (
                wrapper_ep,
                layer_wrapper,
                layer_checkappend,
                layer_dockerd,
                layer_known_dockerd_hash_match,
            )
        )
        ioc_before_2026_02_15 = (
            "yes"
            if has_any_ioc and created_date < IOC_UNEXPECTED_OLD_CUTOFF
            else "no"
        )
        row = ImageReportRow(
            image_id=image_id,
            name=name,
            digest=digest,
            created=created,
            wrapper_ep=wrapper_ep,
            layer_wrapper=layer_wrapper,
            layer_checkappend=layer_checkappend,
            layer_dockerd=layer_dockerd,
            layer_known_dockerd_hash_match=layer_known_dockerd_hash_match,
            github_runs_90d_match=github_runs_90d_match,
            image_found_as_attestation_digest_warning=image_found_as_attestation_digest_warning,
            ioc_before_2026_02_15=ioc_before_2026_02_15,
        )

        # This dedupe is defensive. We do not currently rely on a specific
        # Docker case that emits identical rows here, but we keep the TSV
        # stable if Docker output or this script ever produces repeats.
        if row not in seen:
            rows.append(row)
            seen.add(row)

    # Sort by creation time first so review follows image age, then use the
    # other fields as stable tiebreakers.
    rows.sort(key=lambda row: row.sort_key())
    return rows


def write_summary_report(rows: list[ImageReportRow]) -> None:
    """
    Write a short human-readable summary report to stderr.

    We keep the full TSV on stdout and the review-oriented summary on stderr so
    redirecting the TSV to a file does not mix formats.
    """
    # `rows` counts listed repository/tag references, while the image-ID sets
    # count unique local images. One local image ID can appear under multiple
    # names/tags, so these counts are related but not always identical.
    unique_image_ids = {row.image_id for row in rows}
    ioc_rows = [row for row in rows if row.has_iocs()]
    ioc_image_ids = {row.image_id for row in ioc_rows}
    ioc_in_expected_github_rows = [
        row for row in rows if row.is_ioc_in_expected_github_build()
    ]
    ioc_in_expected_github_image_ids = {
        row.image_id for row in ioc_in_expected_github_rows
    }
    unexpectedly_old_ioc_rows = [
        row for row in rows if row.is_unexpectedly_old_ioc()
    ]
    unexpectedly_old_ioc_image_ids = {
        row.image_id for row in unexpectedly_old_ioc_rows
    }
    recent_non_ioc_non_github_rows = [
        row
        for row in rows
        if not row.has_iocs()
        and row.github_runs_90d_match == "no"
        and parse_created_at_date(row.created) >= RECENT_UNEXPLAINED_IMAGE_CUTOFF
    ]
    recent_non_ioc_non_github_image_ids = {
        row.image_id for row in recent_non_ioc_non_github_rows
    }

    print("=== Summary ===", file=sys.stderr)
    print(f"Listed images: {len(rows)}", file=sys.stderr)
    print(f"Unique image IDs: {len(unique_image_ids)}", file=sys.stderr)
    print(f"Listed images with IOC signals: {len(ioc_rows)}", file=sys.stderr)
    print(f"Image IDs with IOC signals: {len(ioc_image_ids)}", file=sys.stderr)
    print(
        "Listed images with IOC signals and github_runs_90d_match=yes: "
        f"{len(ioc_in_expected_github_rows)}",
        file=sys.stderr,
    )
    print(
        "Image IDs with IOC signals and github_runs_90d_match=yes: "
        f"{len(ioc_in_expected_github_image_ids)}",
        file=sys.stderr,
    )
    print(
        "Listed images with IOC signals and created before 2026-02-15: "
        f"{len(unexpectedly_old_ioc_rows)}",
        file=sys.stderr,
    )
    print(
        "Image IDs with IOC signals and created before 2026-02-15: "
        f"{len(unexpectedly_old_ioc_image_ids)}",
        file=sys.stderr,
    )
    print(
        "Listed images created on or after 2026-01-26 with no IOC signals "
        "and github_runs_90d_match=no: "
        f"{len(recent_non_ioc_non_github_rows)}",
        file=sys.stderr,
    )
    print(
        "Image IDs created on or after 2026-01-26 with no IOC signals and "
        f"github_runs_90d_match=no: {len(recent_non_ioc_non_github_image_ids)}",
        file=sys.stderr,
    )
    print(
        f"wrapper_ep=yes: {sum(row.wrapper_ep == 'yes' for row in rows)}",
        file=sys.stderr,
    )
    print(
        f"layer_wrapper=yes: {sum(row.layer_wrapper == 'yes' for row in rows)}",
        file=sys.stderr,
    )
    print(
        "layer_checkappend=yes: "
        f"{sum(row.layer_checkappend == 'yes' for row in rows)}",
        file=sys.stderr,
    )
    print(
        f"layer_dockerd=yes: {sum(row.layer_dockerd == 'yes' for row in rows)}",
        file=sys.stderr,
    )
    print(
        "layer_known_dockerd_hash_match=yes: "
        f"{sum(row.layer_known_dockerd_hash_match == 'yes' for row in rows)}",
        file=sys.stderr,
    )
    print(
        "github_runs_90d_match=yes: "
        f"{sum(row.github_runs_90d_match == 'yes' for row in rows)}",
        file=sys.stderr,
    )

    print(file=sys.stderr)
    print("=== Images That Look Malicious ===", file=sys.stderr)
    if not ioc_rows:
        print("none", file=sys.stderr)
    else:
        print(
            "Any image listed here has at least one active IOC signal and "
            "should be treated as malicious. Do not run it.",
            file=sys.stderr,
        )
        for row in ioc_rows:
            warning_suffix = (
                f"\twarning={row.image_found_as_attestation_digest_warning}"
                if row.image_found_as_attestation_digest_warning
                else ""
            )
            print(
                f"{row.summary_identity_fields()}"
                f"\tcreated={row.created}"
                f"\tsignals={','.join(row.ioc_signals())}"
                f"\tgithub_runs_90d_match={row.github_runs_90d_match}"
                f"{warning_suffix}",
                file=sys.stderr,
            )

    if ioc_in_expected_github_rows:
        print(file=sys.stderr)
        print("=== Highly Unusual Findings ===", file=sys.stderr)
        print(
            "IOC-positive images whose digests also match the GitHub-runs CSV:",
            file=sys.stderr,
        )
        for row in ioc_in_expected_github_rows:
            warning_suffix = (
                f"\twarning={row.image_found_as_attestation_digest_warning}"
                if row.image_found_as_attestation_digest_warning
                else ""
            )
            print(
                f"{row.summary_identity_fields()}"
                f"\tcreated={row.created}"
                f"\tsignals={','.join(row.ioc_signals())}"
                f"\tgithub_runs_90d_match={row.github_runs_90d_match}"
                f"{warning_suffix}",
                file=sys.stderr,
            )

    if unexpectedly_old_ioc_rows:
        print(file=sys.stderr)
        print("=== Unexpectedly Old IOC Findings ===", file=sys.stderr)
        print(
            "IOC-positive images created before 2026-02-15:",
            file=sys.stderr,
        )
        for row in unexpectedly_old_ioc_rows:
            warning_suffix = (
                f"\twarning={row.image_found_as_attestation_digest_warning}"
                if row.image_found_as_attestation_digest_warning
                else ""
            )
            print(
                f"{row.summary_identity_fields()}"
                f"\tcreated={row.created}"
                f"\tsignals={','.join(row.ioc_signals())}"
                f"\tgithub_runs_90d_match={row.github_runs_90d_match}"
                f"{warning_suffix}",
                file=sys.stderr,
            )

    if recent_non_ioc_non_github_rows:
        print(file=sys.stderr)
        print("=== Recent Non-IOC Images Not In GitHub Runs ===", file=sys.stderr)
        print(
            "Images created on or after 2026-01-26 with no IOC signals and "
            "github_runs_90d_match=no:",
            file=sys.stderr,
        )
        for row in recent_non_ioc_non_github_rows:
            print(
                f"{row.image_with_digest()}\tcreated={row.created}",
                file=sys.stderr,
            )


def main() -> int:
    """
    Print the final TSV report to stdout.

    Input:
      none

    Output:
      TSV on stdout with the columns listed in `HEADER`
    """
    args = parse_args()
    github_runs_90d_index = load_github_runs_90d_index(args.github_runs_90d)
    rows = build_rows(
        github_runs_90d_index=github_runs_90d_index,
        harbor2_only=args.harbor2,
    )

    # We emit TSV so the output stays readable in a terminal and easy to
    # redirect to a file for later comparison.
    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(HEADER)
    writer.writerows(row.to_tsv_row() for row in rows)
    write_summary_report(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
